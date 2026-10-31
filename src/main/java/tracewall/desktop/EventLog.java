package tracewall.desktop;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Bounded in-memory feed for the dashboard and for tests. The DNS path never
 * blocks on it: the deque is synchronised and every operation is O(1).
 */
public final class EventLog {

    /** One decision, ready to render. */
    public record Event(long timeMillis, String action, String host, String reason,
                        String category, Double confidence, String client) { }

    private final int capacity;
    private final Deque<Event> events = new ArrayDeque<>();

    public EventLog(int capacity) {
        this.capacity = Math.max(1, capacity);
    }

    public synchronized void add(Event event) {
        if (events.size() == capacity) events.removeFirst();
        events.addLast(event);
    }

    /** Oldest first. */
    public synchronized List<Event> recent(int limit) {
        int n = Math.min(Math.max(limit, 0), events.size());
        List<Event> out = new ArrayList<>(n);
        int skip = events.size() - n;
        int i = 0;
        for (Event e : events) {
            if (i++ >= skip) out.add(e);
        }
        return out;
    }

    public synchronized int size() {
        return events.size();
    }
}
