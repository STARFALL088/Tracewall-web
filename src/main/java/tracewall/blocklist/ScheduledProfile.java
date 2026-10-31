/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.blocklist;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/** Additive DNS rules only: a profile cannot disable a base or parent rule. */
public final class ScheduledProfile {
    public static final int MAX_NAME_LENGTH = 40;
    public static final int MAX_BLOCKED_UIDS = 1000;
    public static final Set<String> CATEGORIES = Collections.unmodifiableSet(
            new TreeSet<>(Arrays.asList("adult", "ads", "gambling", "malware")));

    public final String name;
    public final WeeklySchedule schedule;
    public final Set<String> categories;
    public final Set<Integer> blockedUids;

    public ScheduledProfile(String name, WeeklySchedule schedule,
                            Collection<String> categories, Collection<Integer> blockedUids) {
        if (name == null || name.trim().isEmpty() || name.length() > MAX_NAME_LENGTH || schedule == null
                || categories == null || categories.size() > CATEGORIES.size()
                || blockedUids == null || blockedUids.size() > MAX_BLOCKED_UIDS)
            throw new IllegalArgumentException("Invalid profile");
        for (int i = 0; i < name.length(); i++) {
            if (Character.isISOControl(name.charAt(i))) throw new IllegalArgumentException("Invalid profile name");
        }
        Set<String> checkedCategories = new TreeSet<>();
        for (String category : categories) {
            if (category == null || !CATEGORIES.contains(category)) throw new IllegalArgumentException("Unknown category");
            checkedCategories.add(category);
        }
        Set<Integer> checkedUids = new TreeSet<>();
        for (Integer uid : blockedUids) {
            if (uid == null || uid < 0) throw new IllegalArgumentException("Invalid UID");
            checkedUids.add(uid);
        }
        if (checkedCategories.isEmpty() && checkedUids.isEmpty()) throw new IllegalArgumentException("Empty profile");
        this.name = name.trim();
        this.schedule = schedule;
        this.categories = Collections.unmodifiableSet(checkedCategories);
        this.blockedUids = Collections.unmodifiableSet(checkedUids);
    }
}
