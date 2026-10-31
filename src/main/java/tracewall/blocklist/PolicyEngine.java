/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.blocklist;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;

/**
 * Immutable policy snapshot. Local precedence: explicit (permanent or unexpired)
 * allow > custom deny > app DNS block > category > default allow. Scheduled
 * profiles add app/category blocks, never replace or subtract existing rules.
 *
 * An optional managed policy is authoritative before local exceptions: parent
 * allows still win, and a local edit/backup cannot override a parent block.
 * The original three-argument constructor retains its original precedence.
 * No preferences, asset reads, alarms or scheduler jobs occur on the query path.
 */
public final class PolicyEngine {
    public enum Verdict {
        ALLOW_DEFAULT,
        ALLOW_LISTED,
        BLOCK_APP,
        BLOCK_CATEGORY,
        BLOCK_CUSTOM
    }

    /** The outcome for one query. Immutable, cheap, safe to log. */
    public static final class Decision {
        public final Verdict verdict;
        public final String reason;

        Decision(Verdict verdict, String reason) {
            this.verdict = verdict;
            this.reason = reason;
        }

        public boolean blocked() {
            return verdict == Verdict.BLOCK_APP || verdict == Verdict.BLOCK_CATEGORY
                    || verdict == Verdict.BLOCK_CUSTOM;
        }

        @Override public String toString() {
            return reason.isEmpty() ? verdict.name() : verdict.name() + ":" + reason;
        }
    }

    private static final Decision DEFAULT_ALLOW = new Decision(Verdict.ALLOW_DEFAULT, "");
    private static final Decision ALLOWLISTED = new Decision(Verdict.ALLOW_LISTED, "allowlist");
    private static final Decision TEMPORARILY_ALLOWED = new Decision(Verdict.ALLOW_LISTED, "temporary_allow");
    private static final Decision APP_BLOCKED = new Decision(Verdict.BLOCK_APP, "app");
    private static final Decision CUSTOM_BLOCKED = new Decision(Verdict.BLOCK_CUSTOM, "custom_deny");

    private final DomainSet allowList;
    private final DomainSet denyList;
    private final Map<String, DomainSet> categories;
    private final Map<String, DomainSet> scheduledCategories;
    private final Set<Integer> blockedApps;
    private final List<TimedAllow> temporaryAllows;
    private final List<ScheduledProfile> profiles;
    private final PolicyEngine managedPolicy;

    public PolicyEngine(DomainSet allowList, Map<String, DomainSet> categories, Set<Integer> blockedApps) {
        this(allowList, categories, blockedApps, null, null, null, null);
    }

    public PolicyEngine(DomainSet allowList, Map<String, DomainSet> categories, Set<Integer> blockedApps,
                        DomainSet denyList, Map<String, Long> temporaryAllows,
                        Map<String, DomainSet> scheduledCategories, Collection<ScheduledProfile> profiles) {
        this(allowList, categories, blockedApps, denyList, temporaryAllows, scheduledCategories, profiles, null);
    }

    public PolicyEngine(DomainSet allowList, Map<String, DomainSet> categories, Set<Integer> blockedApps,
                        DomainSet denyList, Map<String, Long> temporaryAllows,
                        Map<String, DomainSet> scheduledCategories, Collection<ScheduledProfile> profiles,
                        PolicyEngine managedPolicy) {
        this.allowList = allowList == null ? new DomainSet() : allowList;
        this.denyList = denyList == null ? new DomainSet() : denyList;
        this.categories = sorted(categories);
        this.scheduledCategories = sorted(scheduledCategories);
        this.blockedApps = blockedApps == null ? Collections.emptySet()
                : Collections.unmodifiableSet(new HashSet<>(blockedApps));
        List<TimedAllow> timed = new ArrayList<>();
        if (temporaryAllows != null) {
            for (Map.Entry<String, Long> entry : new TreeMap<>(temporaryAllows).entrySet()) {
                if (entry.getValue() == null) throw new IllegalArgumentException("Missing expiry");
                timed.add(new TimedAllow(DomainPattern.parse(entry.getKey()), entry.getValue()));
            }
        }
        this.temporaryAllows = Collections.unmodifiableList(timed);
        List<ScheduledProfile> ordered = profiles == null ? new ArrayList<>() : new ArrayList<>(profiles);
        ordered.sort(Comparator.comparing(profile -> profile.name));
        this.profiles = Collections.unmodifiableList(ordered);
        this.managedPolicy = managedPolicy;
    }

    private static Map<String, DomainSet> sorted(Map<String, DomainSet> input) {
        return input == null ? Collections.emptyMap() : Collections.unmodifiableMap(new TreeMap<>(input));
    }

    public Decision decide(String host, int uid) {
        return decide(host, uid, System.currentTimeMillis(), TimeZone.getDefault());
    }

    /** Inject the instant/zone in tests; production follows the device's current wall clock. */
    public Decision decide(String host, int uid, long nowMillis, TimeZone zone) {
        if (host == null) return DEFAULT_ALLOW;
        if (managedPolicy != null) {
            Decision managed = managedPolicy.decide(host, uid, nowMillis, zone);
            if (managed.verdict != Verdict.ALLOW_DEFAULT) return managed;
        }
        if (allowList.matches(host)) return ALLOWLISTED;
        for (TimedAllow allow : temporaryAllows) {
            if (allow.matches(host, nowMillis)) return TEMPORARILY_ALLOWED;
        }
        if (denyList.matches(host)) return CUSTOM_BLOCKED;
        if (blockedApps.contains(uid)) return APP_BLOCKED;
        List<ScheduledProfile> active = activeProfiles(nowMillis, zone);
        for (ScheduledProfile profile : active) {
            if (profile.blockedUids.contains(uid)) return new Decision(Verdict.BLOCK_APP, "profile:" + profile.name);
        }
        for (Map.Entry<String, DomainSet> category : categories.entrySet()) {
            if (category.getValue().matches(host)) return new Decision(Verdict.BLOCK_CATEGORY, category.getKey());
        }
        for (ScheduledProfile profile : active) {
            for (String name : profile.categories) {
                DomainSet category = scheduledCategories.get(name);
                if (category != null && category.matches(host))
                    return new Decision(Verdict.BLOCK_CATEGORY, "profile:" + profile.name + ":" + name);
            }
        }
        return DEFAULT_ALLOW;
    }

    private List<ScheduledProfile> activeProfiles(long nowMillis, TimeZone zone) {
        if (profiles.isEmpty()) return Collections.emptyList();
        Calendar local = WeeklySchedule.localTime(nowMillis, zone);
        int day = WeeklySchedule.isoDay(local), minute = WeeklySchedule.minuteOfDay(local);
        List<ScheduledProfile> active = new ArrayList<>();
        for (ScheduledProfile profile : profiles) {
            if (profile.schedule.isActive(day, minute)) active.add(profile);
        }
        return active;
    }

    /** Loaded rules, not a count of active rules or attributed applications. */
    public int size() {
        int n = allowCount() + blockedApps.size() + denyList.size();
        for (DomainSet set : categories.values()) n += set.size();
        for (ScheduledProfile profile : profiles) {
            n += profile.blockedUids.size();
            for (String name : profile.categories) {
                DomainSet category = scheduledCategories.get(name);
                if (category != null) n += category.size();
            }
        }
        return n;
    }

    public boolean isAppBlocked(int uid) {
        return isAppBlocked(uid, System.currentTimeMillis(), TimeZone.getDefault());
    }

    public boolean isAppBlocked(int uid, long nowMillis, TimeZone zone) {
        if (blockedApps.contains(uid) || (managedPolicy != null && managedPolicy.isAppBlocked(uid, nowMillis, zone))) return true;
        for (ScheduledProfile profile : activeProfiles(nowMillis, zone)) {
            if (profile.blockedUids.contains(uid)) return true;
        }
        return false;
    }

    public int categoryCount() { return categories.size(); }
    public int allowCount() { return allowList.size() + temporaryAllows.size(); }
    public int blockedAppCount() { return blockedApps.size(); }
    public int denyCount() { return denyList.size(); }
    public int profileCount() { return profiles.size(); }

    public String summary() {
        return categoryCount() + " categories / " + size() + " rules / "
                + allowCount() + " allowed / " + blockedAppCount() + " blocked apps / "
                + denyCount() + " custom denies / " + profileCount() + " schedules";
    }
}
