/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.blocklist;

/** An absolute UTC expiry; importing or restarting never renews an exception. */
public final class TimedAllow {
    // Last millisecond of year 9999. Avoid overflow/unbounded timestamps in backups.
    public static final long MAX_EXPIRES_AT_MILLIS = 253402300799999L;
    public static final int MAX_DURATION_MINUTES = 7 * 24 * 60;
    public final DomainPattern pattern;
    public final long expiresAtMillis;

    public TimedAllow(DomainPattern pattern, long expiresAtMillis) {
        if (pattern == null || expiresAtMillis <= 0 || expiresAtMillis > MAX_EXPIRES_AT_MILLIS)
            throw new IllegalArgumentException("Invalid temporary allow");
        this.pattern = pattern;
        this.expiresAtMillis = expiresAtMillis;
    }

    public boolean matches(String host, long nowMillis) {
        return nowMillis < expiresAtMillis && pattern.matches(host);
    }

    public static long expiresAfterMinutes(long nowMillis, int minutes) {
        if (nowMillis < 0 || minutes < 1 || minutes > MAX_DURATION_MINUTES)
            throw new IllegalArgumentException("Invalid temporary allow duration");
        long duration = minutes * 60_000L;
        if (nowMillis > MAX_EXPIRES_AT_MILLIS - duration)
            throw new IllegalArgumentException("Invalid temporary allow expiry");
        return nowMillis + duration;
    }
}
