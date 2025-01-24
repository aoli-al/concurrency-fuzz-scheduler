package me.bechberger.sos.util;

import me.bechberger.sos.scheduler.FIFOScheduler;
import picocli.CommandLine;

import static me.bechberger.sos.util.DurationConverter.parseToNanoSeconds;

public class DurationRangeConverter implements CommandLine.ITypeConverter<FIFOScheduler.DurationRange> {

    @Override
    public FIFOScheduler.DurationRange convert(String s) throws Exception {
        String[] parts = s.split(",");
        if (parts.length == 1) {
            return new FIFOScheduler.DurationRange(parseToNanoSeconds(parts[0]), parseToNanoSeconds(parts[0]));
        }
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid duration range: " + s);
        }
        return new FIFOScheduler.DurationRange(parseToNanoSeconds(parts[0]), parseToNanoSeconds(parts[1]));
    }
}
