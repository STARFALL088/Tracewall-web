/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.net;

import java.util.Objects;

/** Bounded single-flight state: one active request plus only the latest pending desired state. */
public final class LatestWork<T> {
    private T running, latest;

    /** Start the returned request outside the monitor; null means an existing request owns the work. */
    public synchronized T offer(T request) {
        latest = Objects.requireNonNull(request);
        if (running != null) return null;
        running = request;
        return request;
    }

    /** Call once after asynchronous work finishes, not when it is merely submitted. */
    public synchronized T finish(T request, boolean repeatIfNoNewerRequest) {
        if (running == null || request != running) throw new IllegalStateException("Request is not active");
        running = latest != request ? latest : repeatIfNoNewerRequest ? request : null;
        latest = running;
        return running;
    }
}
