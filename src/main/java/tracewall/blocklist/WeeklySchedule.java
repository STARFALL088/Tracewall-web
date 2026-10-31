/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.blocklist;

import java.util.Calendar;
import java.util.TimeZone;

/**
 * A recurring device-local wall-clock interval, start inclusive and end exclusive.
 * Bits 0..6 are Monday..Sunday and identify the day on which an interval STARTS.
 * An overnight Sunday interval therefore continues into Monday. Equal endpoints
 * are rejected rather than ambiguously meaning either zero or twenty-four hours.
 * Clock/time-zone changes (including DST) take effect at the next DNS decision;
 * this is not an alarm and makes no exact-time background-execution promise.
 */
public final class WeeklySchedule {
    public static final int ALL_DAYS = 0x7f;
    public final boolean enabled;
    public final int days;
    public final int startMinute;
    public final int endMinute;

    public WeeklySchedule(boolean enabled, int days, int startMinute, int endMinute) {
        if (days <= 0 || (days & ~ALL_DAYS) != 0
                || startMinute < 0 || startMinute >= 24 * 60
                || endMinute < 0 || endMinute >= 24 * 60 || startMinute == endMinute) {
            throw new IllegalArgumentException("Invalid weekly schedule");
        }
        this.enabled = enabled;
        this.days = days;
        this.startMinute = startMinute;
        this.endMinute = endMinute;
    }

    /** ISO day: Monday=1, Sunday=7. Pure boundary helper for deterministic tests. */
    public boolean isActive(int isoDay, int minuteOfDay) {
        if (isoDay < 1 || isoDay > 7 || minuteOfDay < 0 || minuteOfDay >= 24 * 60)
            throw new IllegalArgumentException("Invalid local day/time");
        if (!enabled) return false;
        if (startMinute < endMinute) {
            return selected(isoDay) && minuteOfDay >= startMinute && minuteOfDay < endMinute;
        }
        int previousDay = isoDay == 1 ? 7 : isoDay - 1;
        return (selected(isoDay) && minuteOfDay >= startMinute)
                || (selected(previousDay) && minuteOfDay < endMinute);
    }

    public boolean isActive(long nowMillis, TimeZone zone) {
        Calendar local = localTime(nowMillis, zone);
        return isActive(isoDay(local), minuteOfDay(local));
    }

    private boolean selected(int isoDay) { return (days & (1 << (isoDay - 1))) != 0; }

    static Calendar localTime(long nowMillis, TimeZone zone) {
        if (zone == null) throw new IllegalArgumentException("Time zone required");
        Calendar local = Calendar.getInstance(zone);
        local.setTimeInMillis(nowMillis);
        return local;
    }

    static int isoDay(Calendar local) { return (local.get(Calendar.DAY_OF_WEEK) + 5) % 7 + 1; }
    static int minuteOfDay(Calendar local) { return local.get(Calendar.HOUR_OF_DAY) * 60 + local.get(Calendar.MINUTE); }
}
