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

import static me.bechberger.ebpf.bpf.BPFJ.*;
import static me.bechberger.ebpf.bpf.Scheduler.PerProcessFlags.PF_KTHREAD;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL_ON;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_enq_flags.SCX_ENQ_PREEMPT;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_current_task_btf;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_prandom_u32;

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
    public record SchedulerSetting(int scriptPID, DurationRange sleepRange, DurationRange runRange, long systemSliceNs, long sliceNs, boolean scaleSlice, boolean log, boolean focusOnJava) {
    }

    @Type
    enum TaskState implements Enum<TaskState> {
        START, RUNNING, SLEEPING
    }

    @Type
    static class TaskContext {
        TaskState state;
        @Unsigned long priority;
    }

    private static final int SHARED_DSQ_ID = 0;

    final GlobalVariable<@Unsigned Integer> this_program_id =
            new GlobalVariable<>(0);

    final GlobalVariable<SchedulerSetting> schedulerSetting = new GlobalVariable<>(new SchedulerSetting(0, new DurationRange(0, 0), new DurationRange(0, 0), 1000000, 1000000, true, false, false));

    @BPFMapDefinition(maxEntries = 10000)
    BPFLRUHashMap<@Unsigned Integer, TaskContext> taskContexts;

    /** Is the task related to the fuzzed script? */
    @BPFMapDefinition(maxEntries = 100000)
    BPFLRUHashMap<@Unsigned Integer, Boolean> isScriptRelated;

    @BPFFunction
    @AlwaysInline
    boolean isTaskScriptRelated(Ptr<TaskDefinitions.task_struct> task) {
        var curPid = task.val().pid;
        var pidRel = isScriptRelated.bpf_get(curPid);
        var scriptPid = schedulerSetting.get().scriptPID;
        if (scriptPid == 0) {
            return false;
        }
        if (pidRel == null) {
            var isRelated =
                    (task.val().comm[0] == 'r' && task.val().comm[1] == 'p' && task.val().comm[2] == 'c') ||
                            (task.val().comm[0] == 't' && task.val().comm[1] == 'a' && task.val().comm[2] == 's') ||
                            (task.val().comm[0] == 's' && task.val().comm[1] == 'h');
            isScriptRelated.put(curPid, isRelated);
            if (isRelated) {
                bpf_trace_printk("Control task %s with pid %d (parent pid %d)", task.val().comm, curPid,
                        task.val().real_parent.val().pid);
            }
//            else {
//                bpf_trace_printk("Task %s with pid %d is NOT related. parent pid %d", task.val().comm, curPid,
//                        task.val().real_parent.val().pid);
//            }
//            if (isRelated) {
//                bpf_trace_printk("Task %s with pid %d is related to script with pid %d", task.val().comm, curPid, 0);
//            }
            return isRelated;
        }
        return pidRel.val();
    }

    /**
     * Generate a random number in the range [min, max)
     */
    @BPFFunction
    @Unsigned long randomInRange(@Unsigned long min, @Unsigned long max) {
        if (min == max) {
            return min;
        }
        return min + (bpf_get_prandom_u32() * 31L) % (max - min);
    }

    @BPFFunction
    @AlwaysInline
    void getTaskContext(Ptr<TaskDefinitions.task_struct> task, Ptr<Ptr<TaskContext>> contextPtr) {
        var id = task.val().tgid;
        var ret = taskContexts.bpf_get(id);
        if (ret == null) {
            var context = new TaskContext();
            context.state = TaskState.START;
            context.priority = randomInRange(0, 1000);
            taskContexts.put(id, context);
        }
        var ret2 = taskContexts.bpf_get(id);
        contextPtr.set(ret2);
    }

    @Override
    public int init() {
        var current_task = bpf_get_current_task_btf();
        bpf_trace_printk("Current task: %d ", current_task.val().pid);
        this_program_id.set(current_task.val().pid);
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public void enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags) {
        var isScriptRelated = isTaskScriptRelated(p);
        @Unsigned long sliceLength = isScriptRelated ? schedulerSetting.get().sliceNs() : schedulerSetting.get().systemSliceNs();
        if (schedulerSetting.get().scaleSlice()) {
            sliceLength = sliceLength / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        }
//        if (isTaskScriptRelated(p)) {
//            bpf_trace_printk("Enqueuing task %s with pid %d", p.val().comm, p.val().pid);
//        }
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
    @AlwaysInline
    public boolean hasConstraints(Ptr<TaskDefinitions.task_struct> p) {
        return ((p.val().flags & PF_KTHREAD) != 0) || (p.val().nr_cpus_allowed != scx_bpf_nr_cpu_ids());
    }

    @BPFFunction
    @AlwaysInline
    public boolean canScheduleOnCPU(Ptr<TaskDefinitions.task_struct> p, int cpu) {
        return true;
    }

    @Override
    public void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) {
        Ptr<TaskDefinitions.task_struct> p = null;
        bpf_for_each_dsq(SHARED_DSQ_ID, p, iter -> {
            if (isTaskScriptRelated(p)) {
                // We only want to dispatch tasks to CPU 23
                if (cpu != 8) {
                    _continue();
                }
                long priority = randomInRange(0, 5);
                if (priority == 0L) {
//                    bpf_trace_printk("Dispatching task %s with pid %d to CPU %d", p.val().comm, p.val().pid, cpu);
                    tryDispatching(iter, p, cpu);
                    return;
                }
            } else {
                if ((hasConstraints(p) || canScheduleOnCPU(p, cpu)) && tryDispatching(iter, p, cpu)) {
                    return; // has different semantics than continue, return will return from the dispatch function
                }
            }
        });
        bpf_for_each_dsq(SHARED_DSQ_ID, p, iter -> {
            if (isTaskScriptRelated(p)) {
                // We only want to dispatch tasks to CPU 23
                if (cpu != 8) {
                    _continue();
                }
//                bpf_trace_printk("backup: Dispatching task %s with pid %d to CPU %d", p.val().comm, p.val().pid, cpu);
                tryDispatching(iter, p, cpu);
                return;
            } else {
                if ((hasConstraints(p) || canScheduleOnCPU(p, cpu)) && tryDispatching(iter, p, cpu)) {
                    return; // has different semantics than continue, return will return from the dispatch function
                }
            }
        });
    }

    @BPFFunction
    @AlwaysInline
    void setupIsTaskRelatedToScript(Ptr<TaskDefinitions.task_struct> task) {
        var curPid = task.val().pid;
        var pidRel = isScriptRelated.bpf_get(curPid);
        var scriptPid = schedulerSetting.get().scriptPID;
        if (scriptPid == 0) {
            return;
        }
        if (pidRel == null) {
            var isRelated =
                    task.val().comm[0] == 'r' && task.val().comm[1] == 'p' && task.val().comm[2] == 'c';
            isScriptRelated.put(curPid, isRelated);
            if (isRelated) {
                bpf_trace_printk("Task %s with pid %d is related to script with pid %d", task.val().comm, curPid, 0);
            } else {
                bpf_trace_printk("Task %s with pid %d is NOT related. parent pid %d", task.val().comm, curPid,
                        task.val().real_parent.val().pid);
            }
        }
    }

    @Override
    public void enable(Ptr<TaskDefinitions.task_struct> p) {
//        bpf_trace_printk("Hello, World2!");
//        setupIsTaskRelatedToScript(p);
    }

    @Override
    public void disable(Ptr<TaskDefinitions.task_struct> p) {
        isScriptRelated.bpf_delete(p.val().pid);
    }

    public void setSchedulerSetting(SchedulerSetting setting) {
        schedulerSetting.set(setting);
    }
}