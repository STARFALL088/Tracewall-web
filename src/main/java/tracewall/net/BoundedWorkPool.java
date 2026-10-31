/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.net;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Bounded pending work with explicit rejection; never runs DNS work on the submitting TUN thread. */
public final class BoundedWorkPool {
    private BoundedWorkPool() {}

    public static ThreadPoolExecutor create(String prefix, int threads, int capacity) {
        if (prefix == null || prefix.isEmpty() || threads < 1 || capacity < 1)
            throw new IllegalArgumentException("Invalid worker pool bounds");
        AtomicInteger sequence = new AtomicInteger();
        return new ThreadPoolExecutor(threads, threads, 0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(capacity), task -> {
                Thread thread = new Thread(task, prefix + "-" + sequence.incrementAndGet());
                thread.setDaemon(true);
                return thread;
            }, new ThreadPoolExecutor.AbortPolicy());
    }
}
