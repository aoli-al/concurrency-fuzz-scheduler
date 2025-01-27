package me.bechberger.fuzz;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.fuzz.scheduler.FIFOScheduler;
import me.bechberger.fuzz.util.DurationConverter;
import me.bechberger.fuzz.util.DurationRangeConverter;
import picocli.CommandLine;

import java.io.*;

import static picocli.CommandLine.Option;
import static picocli.CommandLine.Parameters;

@CommandLine.Command(name = "scheduler.sh", mixinStandardHelpOptions = true,
        description = "Linux scheduler that produces random scheduling edge case to fuzz concurrent applications, runs till error")
public class Main implements Runnable{

    @Parameters(arity = "1", paramLabel = "script", description = "Script or command to execute")
    String script;

    @Option(names = {"-s", "--sleep"}, defaultValue = "10ms,500ms",
            description = "Range of sleep lengths", converter = DurationRangeConverter.class)
    FIFOScheduler.DurationRange sleepRange;

    @Option(names = {"-r", "--run"}, defaultValue = "10ms,500ms",
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

    private void startPrintThread(InputStream source, OutputStream dest) {
        var thread = new Thread(() -> {
            try {
                while (true) {
                    var read = source.read();
                    if (read == -1) {
                        break;
                    }
                    dest.write(source.read());
                }
            } catch (Exception ex) {}
        });
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * @return boolean should continue
     */
    boolean iteration() throws InterruptedException, IOException {
        boolean didProgramFail = false;
        Process process;
        try (var scheduler = BPFProgram.load(FIFOScheduler.class)) {
            System.out.println("loaded");
            // we have a circular dependency here between getting the pid and setting the scheduler setting
            // sleeping for two seconds should prevent any issues

            scheduler.setSchedulerSetting(new FIFOScheduler.SchedulerSetting(0, sleepRange, runRange, systemSliceNs, sliceNs, random(), !dontScaleSlice, log));

            scheduler.attachScheduler();

            process = new ProcessBuilder(script).start();

            scheduler.setSchedulerSetting(new FIFOScheduler.SchedulerSetting((int)process.pid(), sleepRange, runRange, systemSliceNs, sliceNs, random(), !dontScaleSlice, log));

            // print err and out using threads
            startPrintThread(process.getErrorStream(), System.err);
            startPrintThread(process.getInputStream(), System.out);

            long startTime = System.currentTimeMillis();
            long lastErrorCheckTime = System.currentTimeMillis();
            while (scheduler.isSchedulerAttachedProperly()) {
                Thread.sleep(100);
                if (!process.isAlive() && process.exitValue() != 0) {
                    didProgramFail = true;
                    break;
                }
                if (System.currentTimeMillis() > lastErrorCheckTime + errorCheckIntervalNs / 1_000_000) {
                    if (doesErrorScriptSucceed()) {
                        System.out.println("Break because process isn't alive");

                        didProgramFail = true;
                        break;
                    }
                }
                if (startTime + iterationTimeNs / 1_000_000 < System.currentTimeMillis()) {
                    System.out.println("Break because process isn't alive222 " + iterationTimeNs / 1_000_000);

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
        this.randomState = seed;
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
                .execute(args);
    }

}