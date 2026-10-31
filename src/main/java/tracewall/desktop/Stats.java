package tracewall.desktop;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Process-wide counters. Everything is an {@link AtomicLong} so the receive
 * loop, worker threads and the dashboard can all read and write without locks.
 */
public final class Stats {
    public final AtomicLong total = new AtomicLong();
    public final AtomicLong blockedCategory = new AtomicLong();
    public final AtomicLong blockedCustom = new AtomicLong();
    public final AtomicLong blockedAi = new AtomicLong();
    public final AtomicLong allowed = new AtomicLong();
    public final AtomicLong servfail = new AtomicLong();
    public final AtomicLong dropped = new AtomicLong();
    public final AtomicLong malformed = new AtomicLong();
    public final AtomicLong aiCalls = new AtomicLong();
    public final AtomicLong aiCacheHits = new AtomicLong();

    public long blocked() {
        return blockedCategory.get() + blockedCustom.get() + blockedAi.get();
    }

    /** One line, fixed field order, easy to grep and to chart. */
    public String oneLine() {
        return "stats total=" + total.get()
                + " blocked=" + blocked()
                + " (category=" + blockedCategory.get()
                + " custom=" + blockedCustom.get()
                + " ai=" + blockedAi.get() + ")"
                + " allowed=" + allowed.get()
                + " servfail=" + servfail.get()
                + " dropped=" + dropped.get()
                + " malformed=" + malformed.get()
                + " ai_calls=" + aiCalls.get()
                + " ai_cache_hits=" + aiCacheHits.get();
    }
}
