/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.blocklist;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Snapshot-backed editor. A missing first snapshot must never become an empty push. */
public final class RuleLists {
    private final Set<String> allow = new LinkedHashSet<>();
    private final Set<Integer> blocked = new LinkedHashSet<>();
    private boolean ready;

    public void load(Collection<String> allows, Collection<Integer> uids) {
        allow.clear();
        allow.addAll(allows);
        blocked.clear();
        blocked.addAll(uids);
        ready = true;
    }
    public boolean isReady() { return ready; }
    public void pause() { ready = false; }
    private void requireReady() {
        if (!ready) throw new IllegalStateException("Wait for rules snapshot");
    }
    public void addAllow(String host) { requireReady(); allow.add(host); }
    public void removeAllow(String host) { requireReady(); allow.remove(host); }
    public void block(int uid) { requireReady(); blocked.add(uid); }
    public void unblock(int uid) { requireReady(); blocked.remove(uid); }
    public List<String> allows() { requireReady(); return new ArrayList<>(allow); }
    public List<Integer> blockedUids() { requireReady(); return new ArrayList<>(blocked); }
}
