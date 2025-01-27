package me.bechberger.fuzz;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.fuzz.scheduler.FIFOScheduler;
import me.bechberger.fuzz.util.DurationConverter;
import me.bechberger.fuzz.util.DurationRangeConverter;
import picocli.CommandLine;

import java.io.IOException;

import static picocli.CommandLine.Option;
import static picocli.CommandLine.Parameters;

@CommandLine.Command(name = "scheduler.sh", mixinStandardHelpOptions = true,
        description = "Linux scheduler that produces random scheduling edge case to fuzz concurrent applications, runs till error")
public class Main implements Runnable{

    @Parameters(arity = "1..*", paramLabel = "script", description = "Script or command to execute")
    String script;

    @Option(names = {"-c", "--cpus"}, defaultValue = "-1",
            description = "Number of cores to use, -1 for all cores")
    int cpus;

    @Option(names = {"-s", "--sleep"}, defaultValue = "10ms,20s",
            description = "Range of sleep lengths", converter = DurationRangeConverter.class)
    FIFOScheduler.DurationRange sleepRange;

    @Option(names = {"-r", "--run"}, defaultValue = "10ms,20s",
            description = "Range of running time lengths", converter = DurationRangeConverter.class)
    FIFOScheduler.DurationRange runRange;

    @Option(names = {"--system-slice"}, defaultValue = "5ms",
            description = "Time slice duration for all non-script tasks", converter = DurationConverter.class)
    int systemSliceNs;

    @Option(names = {"--slice"}, defaultValue = "5ms",
            description = "Time slice duration for the script", converter = DurationConverter.class)
    int sliceNs;

    @Option(names = {"-e", "--error-command"}, defaultValue = "",
            description = "Command to execute on error, default checks for error code != 0")
    String errorCommand;

    @Option(names = {"-i", "--iteration-time"}, defaultValue = "10s",
            description = "Time to run the script for at a time, restart the whole process afterward with same seed", converter = DurationConverter.class)
    int iterationTimeNs;

    @Option(names = {"-x", "--cpu-mode"}, defaultValue = "HT_EXCLUSIVE",
            description = "Keep the cpu exclusive to the script, one of: ${COMPLETION-CANDIDATES}")
    FIFOScheduler.CPUMode cpuMode;

    @Option(names = {"-d", "--dont-scale-slice"}, defaultValue = "false",
            description = "Don't scale the slice time with the number of waiting tasks")
    boolean dontScaleSlice;

    @Option(names = {"-z", "--seed"}, defaultValue = "31",
            description = "Initial seed for the random number generator")
    int seed;

    @Option(names = {"-m", "--max-iterations"}, defaultValue = "-1",
            description = "Maximum number of iterations")
    int maxIterations;

    @Option(names = "--error-check-interval", defaultValue = "10s",
            description = "Time between two checks via the error script", converter = DurationConverter.class)
    int errorCheckIntervalNs;

    @Option(names = "--log", defaultValue = "false",
            description = "Log the state changes")
    boolean log;

    boolean doesErrorScriptSucceed() {
        if (errorCommand.isEmpty()) {
            return false;
        }
        try {
            return new ProcessBuilder("/bin/sh", "-c", errorCommand).start().waitFor() == 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private int randomState;
    private int curRandomState;

    private int random() {
        curRandomState = randomState;
        randomState = randomState * 48271 % 0x7fffffff;
        return curRandomState;
    }

    /**
     * @return boolean should continue
     */
    boolean iteration() throws InterruptedException, IOException {
        boolean didProgramFail = false;
        Process process;
        long startTime = System.nanoTime();
        try (var scheduler = BPFProgram.load(FIFOScheduler.class)) {
            System.out.println("loaded");
            // we have a circular dependency here between getting the pid and setting the scheduler setting
            // sleeping for two seconds should prevent any issues
            process = new ProcessBuilder("/bin/sh", "-c", "sleep 2; " + script).inheritIO().start();
            scheduler.setSchedulerSetting(new FIFOScheduler.SchedulerSetting((int)process.pid(), cpus, sleepRange, runRange, systemSliceNs, sliceNs, random(), cpuMode, !dontScaleSlice, log));
            scheduler.attachScheduler();
            System.out.println("attached");
            long lastErrorCheckTime = System.nanoTime();
            while (scheduler.isSchedulerAttachedProperly()) {
                Thread.sleep(100);
                if (!process.isAlive() && process.exitValue() != 0) {
                    didProgramFail = true;
                    break;
                }
                if (System.nanoTime() > lastErrorCheckTime + errorCheckIntervalNs) {
                    if (doesErrorScriptSucceed()) {
                        didProgramFail = true;
                        break;
                    }
                }
                if (startTime + iterationTimeNs < System.nanoTime()) {
                    break;
                }
            }
        }
        while (process.isAlive()) {
            process.destroy();
            System.out.println("Killing process");
            Thread.sleep(100);
        }
        return didProgramFail;
    }

    @Override
    public void run() {
        if (log) {
            var logPrintThread = new Thread(() -> {
                TraceLog.getInstance().printLoop(true);
            });
            logPrintThread.setDaemon(true);
            logPrintThread.start();
        }
        for (int i = 0; maxIterations < 0 || i < maxIterations; i++) {
            try {
                if (iteration()) {
                    System.out.println("Program failed with seed " + curRandomState);
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                break;
            }
        }

    }


    public static void main(String[] args) throws InterruptedException {
        var cli = new CommandLine(new Main());
        cli.setUnmatchedArgumentsAllowed(false)
                .registerConverter(FIFOScheduler.CPUMode.class, name -> FIFOScheduler.CPUMode.valueOf(name.toUpperCase()))
                .execute(args);
    }

}