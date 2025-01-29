package me.bechberger.fuzz.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Helps to create a simple schedule diagram */
public class DiagramHelper {

    /**
     * [5.778] java is running for 2ms
     * [5.782] java is sleeping for 2143ms
     * [7.930] java is running for 9ms
     * [7.940] java is sleeping for 2199ms
     * [10.141] java is running for 14ms
     * [10.171] Producer is sleeping for 1858ms
     * [12.030] Consumer is running for 2ms
     * [12.041] Consumer is sleeping for 2172ms
     * [14.213] Consumer is running for 2ms
     * [14.217] Consumer is sleeping for 964ms
     */

    public enum EventType {
        RUNNING, SLEEPING
    }

    private record Event(double time, String task, EventType type, double duration) {}

    private List<Event> events = new ArrayList<>();

    public void recordEvent(double timeSeconds, String task, EventType type, double durationSeconds) {
        events.add(new Event(timeSeconds, task, type, durationSeconds));
    }

    public String createDataJSON() {
        // Grouping events by task
        Map<String, List<Event>> eventsByTask = events.stream()
                .collect(Collectors.groupingBy(Event::task));

        StringBuilder json = new StringBuilder("[");
        boolean firstTask = true;

        // Looping through each task
        for (Map.Entry<String, List<Event>> entry : eventsByTask.entrySet()) {
            if (!firstTask) {
                json.append(",");
            }
            json.append("{ \"task\": \"").append(entry.getKey()).append("\", \"events\": [");

            boolean firstEvent = true;

            // Looping through events of each task
            for (Event event : entry.getValue()) {
                if (!firstEvent) {
                    json.append(",");
                }
                json.append(createSingleEventJSON(event));
                firstEvent = false;
            }
            json.append("] }");

            firstTask = false;
        }
        json.append("]");

        return json.toString();
    }

    private String createSingleEventJSON(Event event) {
        // Returning event as JSON format
        return String.format("{ \"action\": \"%s\", \"start\": %f, \"duration\": %f }",
                event.type.toString().toLowerCase(), event.time, event.duration);
    }
}
