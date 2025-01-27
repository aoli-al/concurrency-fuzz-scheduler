package me.bechberger.fuzz.scheduler;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import me.bechberger.ebpf.runtime.BpfDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.fuzz.util.DurationConverter;

import static me.bechberger.ebpf.bpf.BPFJ._continue;
import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;
import static me.bechberger.ebpf.bpf.Scheduler.PerProcessFlags.PF_KTHREAD;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL_ON;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_enq_flags.SCX_ENQ_PREEMPT;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_ktime_get_ns;

/**
 * FIFO round-robin scheduler
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "fifo_fuzz_scheduler")
public abstract class FIFOScheduler extends BPFProgram implements Scheduler {

    @Type
    public record DurationRange(@Unsigned long minNs, @Unsigned long maxNs) {

        public DurationRange {
            if (minNs > maxNs) {
                throw new IllegalArgumentException("minNs must be less than or equal to maxNs");
            }
        }

        @Override
        public String toString() {
            return DurationConverter.nanoSecondsToString(minNs, 3) + " - " + DurationConverter.nanoSecondsToString(maxNs, 3);
        }
    }

    @Type
    public enum CPUMode implements Enum<CPUMode> {
        SHARED, EXCLUSIVE,
        /** Don't schedule on the HT siblings of the cores */
        HT_EXCLUSIVE
    }

    @Type
    public record SchedulerSetting(int scriptPID, int cores, DurationRange sleepRange, DurationRange runRange, int systemSliceNs, int sliceNs, int seed, CPUMode cpuMode, boolean scaleSlice, boolean log) {
    }

    @Type
    enum TaskState implements Enum<TaskState> {
        START, RUNNING, SLEEPING
    }

    @Type
    static class TaskContext {

        TaskState state;

        @Unsigned long timeAllowedInState;

        /** Time the task last has been started on the CPU */
        @Unsigned long lastStartNs;
        /** Total runtime of the task since it last slept */
        @Unsigned long runtimeSinceLastSleepNs;
        /** Time the task last has been moved off a CPU */
        @Unsigned long lastStopNs;
    }

    private static final int SHARED_DSQ_ID = 0;

    final GlobalVariable<SchedulerSetting> schedulerSetting = new GlobalVariable<>(new SchedulerSetting(1,1, new DurationRange(0, 0), new DurationRange(0, 0), 1000000, 1000000, 0, CPUMode.SHARED, true, false));

    @BPFMapDefinition(maxEntries = 10000)
    BPFLRUHashMap<@Unsigned Integer, TaskContext> taskContexts;

    /** Is the task related to the fuzzed script? */
    @BPFMapDefinition(maxEntries = 100000)
    BPFLRUHashMap<@Unsigned Integer, Boolean> isScriptRelated;

    final GlobalVariable<@Unsigned Integer> randomState = new GlobalVariable<>(0);

    @BPFFunction
    @AlwaysInline
    boolean isTaskScriptRelated(Ptr<TaskDefinitions.task_struct> task) {
        var ret = isScriptRelated.bpf_get(task.val().pid);
        return task.val().pid == schedulerSetting.get().scriptPID || (ret != null && ret.val());
    }

    /**
     * Generate a random number using a Park-Miller linear congruential generator
     * (h<a href="ttps://en.wikipedia.org/wiki/Lehmer_random_number_generator)">wikipedia</a>
     */
    @BPFFunction
    @AlwaysInline
    @Unsigned long random() {
        randomState.set(randomState.get() * 48271 % 0x7fffffff);
        return randomState.get();
    }

    /**
     * Generate a random number in the range [min, max)
     */
    @BPFFunction
    @AlwaysInline
    @Unsigned long randomInRange(@Unsigned long min, @Unsigned long max) {
        return min + random() % (max - min);
    }

    @BPFFunction
    @AlwaysInline
    void getTaskContext(Ptr<TaskDefinitions.task_struct> task, Ptr<Ptr<TaskContext>> statPtr) {
        var id = task.val().tgid;
        var ret = taskContexts.bpf_get(id);
        if (ret == null) {
            var stat = new TaskContext();
            stat.lastStartNs = 0;
            stat.runtimeSinceLastSleepNs = 0;
            stat.lastStopNs = 0;
            taskContexts.put(id, stat);
        }
        var ret2 = taskContexts.bpf_get(id);
        statPtr.set(ret2);
    }

    @BPFFunction
    @AlwaysInline
    void initSleeping(Ptr<TaskContext> stat, Ptr<TaskDefinitions.task_struct> p) {
        stat.val().state = TaskState.SLEEPING;
        stat.val().lastStopNs = bpf_ktime_get_ns();
        stat.val().timeAllowedInState = randomInRange(schedulerSetting.get().sleepRange.minNs(), schedulerSetting.get().sleepRange.maxNs());
        if (schedulerSetting.get().log()) {
            bpf_trace_printk("Task %d (%s) is sleeping for %s\n", stat.val().timeAllowedInState, p.val().comm);
        }
    }

    @BPFFunction
    @AlwaysInline
    void initRunning(Ptr<TaskContext> stat, Ptr<TaskDefinitions.task_struct> p) {
        stat.val().state = TaskState.RUNNING;
        stat.val().lastStopNs = bpf_ktime_get_ns();
        stat.val().timeAllowedInState = randomInRange(schedulerSetting.get().runRange.minNs(), schedulerSetting.get().runRange.maxNs());
        if (schedulerSetting.get().log()) {
            bpf_trace_printk("Task %d (%s) is running for %s\n", stat.val().timeAllowedInState, p.val().comm);
        }
    }

    @BPFFunction
    @AlwaysInline
    boolean updateStateIfNeededAndReturnIfSchedulable(Ptr<TaskDefinitions.task_struct> p) {
        if (!isTaskScriptRelated(p)) { // don't schedule tasks that are not related to the script
            return true;
        }
        Ptr<TaskContext> stat = null;
        getTaskContext(p, Ptr.of(stat));
        if (stat == null) {
            return true;
        }

        if (stat.val().state == TaskState.START) { // initialize the task, randomly choose if it should sleep or run
            if (randomInRange(0, 2) == 0) {
                initSleeping(stat, p);
                return false;
            } else {
                initRunning(stat, p);
                return true;
            }
        }

        if (stat.val().state == TaskState.RUNNING) { // check if the task has to sleep
            if (stat.val().runtimeSinceLastSleepNs >= stat.val().timeAllowedInState) { // sleep if the task has run too long
                initSleeping(stat, p);
                return false;
            }
            return true;
        } else { // check if the task can be scheduled again
            if (bpf_ktime_get_ns() - stat.val().lastStopNs >= stat.val().timeAllowedInState) {
                initRunning(stat, p);
                return true;
            }
            return false;
        }
    }

    @Override
    public int init() {
        randomState.set(schedulerSetting.get().seed);
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public void enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags) {
        var isScriptRelated = isTaskScriptRelated(p);
        @Unsigned int sliceLength = isScriptRelated ? schedulerSetting.get().sliceNs() : schedulerSetting.get().systemSliceNs();
        if (schedulerSetting.get().scaleSlice()) {
            sliceLength = sliceLength / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        }
        scx_bpf_dispatch(p, SHARED_DSQ_ID, sliceLength, enq_flags);
    }

    @BPFFunction
    @AlwaysInline
    public boolean tryDispatching(Ptr<BpfDefinitions.bpf_iter_scx_dsq> iter, Ptr<TaskDefinitions.task_struct> p, int cpu) {
        // check if the CPU is usable by the task
        if (!bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)) {
            return false;
        }
        return scx_bpf_dispatch_from_dsq(iter, p, SCX_DSQ_LOCAL_ON.value() | cpu, SCX_ENQ_PREEMPT.value());
    }

    @BPFFunction
    public boolean hasConstraints(Ptr<TaskDefinitions.task_struct> p) {
        return ((p.val().flags & PF_KTHREAD) != 0) || (p.val().nr_cpus_allowed != scx_bpf_nr_cpu_ids());
    }

    @BPFFunction
    @AlwaysInline
    public boolean canScheduleOnCPU(Ptr<TaskDefinitions.task_struct> p, int cpu) {
        if (schedulerSetting.get().cpuMode() == CPUMode.SHARED) {
            return true;
        }
        if (schedulerSetting.get().cpuMode() == CPUMode.EXCLUSIVE) {
            return cpu < scx_bpf_nr_cpu_ids() - schedulerSetting.get().cores || isTaskScriptRelated(p);
        }
        if (schedulerSetting.get().cpuMode() == CPUMode.HT_EXCLUSIVE) {
            int cores = schedulerSetting.get().cores;
            @Unsigned int num = scx_bpf_nr_cpu_ids();
            if (cpu > num / 2 && cpu >= num - cores) { // avoid HT siblings
                return false;
            }
            return cpu < num - cores || isTaskScriptRelated(p);
        }
        return true;
    }

    @Override
    public void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) {
        Ptr<TaskDefinitions.task_struct> p = null;
        bpf_for_each_dsq(SHARED_DSQ_ID, p, iter -> {
            if (!updateStateIfNeededAndReturnIfSchedulable(p)) {
                _continue();
            }
            if ((hasConstraints(p) || canScheduleOnCPU(p, cpu)) && tryDispatching(iter, p, cpu)) {
                return; // has different semantics than continue, return will return from the dispatch function
            }
        });
    }

    @Override
    public void running(Ptr<TaskDefinitions.task_struct> p) {
        if (!isTaskScriptRelated(p)) {
            return;
        }
        Ptr<TaskContext> stat = null;
        getTaskContext(p, Ptr.of(stat));
        if (stat != null) {
            stat.val().lastStopNs = 0;
            stat.val().lastStartNs = bpf_ktime_get_ns();
        }
    }

    @Override
    public void stopping(Ptr<TaskDefinitions.task_struct> p, boolean runnable) {
        if (!isTaskScriptRelated(p)) {
            return;
        }
        Ptr<TaskContext> stat = null;
        getTaskContext(p, Ptr.of(stat));
        if (stat != null) {
            stat.val().runtimeSinceLastSleepNs = stat.val().runtimeSinceLastSleepNs + (bpf_ktime_get_ns() - stat.val().lastStartNs);
        }
    }

    @BPFFunction
    @AlwaysInline
    void setupIsTaskRelatedToScript(Ptr<TaskDefinitions.task_struct> task) {
        var curPid = task.val().tgid;
        var tgidRel = isScriptRelated.bpf_get(curPid);
        if (tgidRel == null) {
            var isRelated = curPid == schedulerSetting.get().scriptPID();
            if (!isRelated) {
                // check parent process
                var parentPid = task.val().real_parent.val().tgid;
                isRelated = parentPid == schedulerSetting.get().scriptPID();
            }
            isScriptRelated.put(task.val().pid, isRelated);
            isScriptRelated.put(curPid, isRelated);
        }
    }

    @Override
    public void enable(Ptr<TaskDefinitions.task_struct> p) {
        setupIsTaskRelatedToScript(p);
    }

    @Override
    public void disable(Ptr<TaskDefinitions.task_struct> p) {
        isScriptRelated.bpf_delete(p.val().tgid);
    }

    public void setSchedulerSetting(SchedulerSetting setting) {
        schedulerSetting.set(setting);
    }
}