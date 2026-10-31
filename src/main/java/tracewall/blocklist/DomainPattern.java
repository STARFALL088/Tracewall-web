/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.blocklist;

import java.util.Locale;

/**
 * A single domain pattern.
 *
 * Two shapes only, because two shapes cover every real blocklist:
 * <ul>
 *   <li>EXACT    "example.com"     matches that host and nothing below it</li>
 *   <li>WILDCARD "*.example.com"   matches any depth below, but NOT "example.com"</li>
 * </ul>
 *
 * Sub-domain matching is always case-insensitive and always label-aligned:
 * "*.example.com" matches "a.b.example.com" but never "notexample.com". That
 * label alignment is the difference between a filter that works and one that
 * gets bypassed by "evil-example.com.attacker.net".
 */
public final class DomainPattern {

    public enum Kind { EXACT, WILDCARD }

    private final Kind kind;
    private final String text;          // as written, lowercased
    private final String suffix;        // WILDCARD: ".example.com";  EXACT: "example.com"

    private DomainPattern(Kind kind, String text, String suffix) {
        this.kind = kind;
        this.text = text;
        this.suffix = suffix;
    }

    public Kind kind() { return kind; }
    public String text() { return text; }

    /** Allocation-light membership test. */
    public boolean matches(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        int end = h.length();
        while (end > 0 && h.charAt(end - 1) == '.') end--;
        h = h.substring(0, end);
        if (kind == Kind.EXACT) {
            return h.equals(suffix);
        }
        return h.endsWith(suffix) && h.length() > suffix.length();
    }

    @Override public String toString() { return text; }

    @Override public boolean equals(Object o) {
        return (o instanceof DomainPattern) && ((DomainPattern) o).text.equals(text);
    }

    @Override public int hashCode() { return text.hashCode(); }

    /**
     * Parse one pattern. Returns null for anything that is not a usable domain
     * pattern, so callers can filter a raw list without try/catch.
     *
     * Rejects: empty, leading/trailing dots, "*", "*.", bare "*", empty labels,
     * labels over 63 chars, non-ASCII (IDNs must arrive punycoded already).
     */
    public static DomainPattern parse(String raw) {
        if (raw == null) return null;
        String text = raw.trim().toLowerCase(Locale.ROOT);
        while (text.endsWith(".")) {
            text = text.substring(0, text.length() - 1);
        }
        if (text.isEmpty() || text.length() > 253) return null;

        boolean wild = text.startsWith("*.");
        String body = wild ? text.substring(2) : text;
        if (body.isEmpty() || body.indexOf('*') >= 0) return null;
        if (body.startsWith(".") || body.endsWith(".")) return null;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            boolean legal = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.';
            if (!legal) return null;
        }
        // Label alignment: every label must be non-empty and <= 63 chars.
        for (String label : body.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63) return null;
        }
        return wild
                ? new DomainPattern(Kind.WILDCARD, text, "." + body)
                : new DomainPattern(Kind.EXACT, text, body);
    }
}