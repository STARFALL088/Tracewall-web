/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.blocklist;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * A set of patterns with O(1) exact lookup.
 *
 * Exact hosts go into a HashSet (the overwhelming majority of a real blocklist
 * is exact). Wildcards are few, so they stay in a small list and are scanned.
 * That split keeps a 200k-domain list cheap to build and cheap to query.
 */
public final class DomainSet {

    private final Set<String> exact;
    private final List<DomainPattern> wildcards;

    public DomainSet() { this(Collections.<DomainPattern>emptyList()); }

    public DomainSet(Collection<DomainPattern> patterns) {
        this.exact = new HashSet<>(Math.max(patterns.size(), 16));
        this.wildcards = new ArrayList<>();
        for (DomainPattern p : patterns) {
            if (p.kind() == DomainPattern.Kind.EXACT) exact.add(p.text());
            else wildcards.add(p);
        }
    }

    /** A defensive, sorted copy for validated list merging and serialization. */
    public Set<String> patterns() {
        Set<String> out = new java.util.TreeSet<>(exact);
        for (DomainPattern pattern : wildcards) out.add(pattern.text());
        return out;
    }

    public int size() { return exact.size() + wildcards.size(); }
    public int wildcardCount() { return wildcards.size(); }

    public boolean matches(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        int end = h.length();
        while (end > 0 && h.charAt(end - 1) == '.') end--;
        h = h.substring(0, end);
        if (exact.contains(h)) return true;
        for (int i = 0; i < wildcards.size(); i++) {
            if (wildcards.get(i).matches(h)) return true;
        }
        return false;
    }

    public static DomainSet of(Iterable<String> raw) {
        List<DomainPattern> list = new ArrayList<>();
        for (String s : raw) {
            DomainPattern p = DomainPattern.parse(s);
            if (p != null) list.add(p);
        }
        return new DomainSet(list);
    }
}