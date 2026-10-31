package tracewall.desktop;

import tracewall.blocklist.DomainPattern;
import tracewall.blocklist.DomainSet;
import tracewall.blocklist.PolicyEngine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Owns the immutable {@link PolicyEngine} snapshot and the dashboard overrides
 * that feed into it.
 *
 * <p>Overrides are not a separate decision path: an allow override is merged
 * into the engine's allow list and a block override into its custom deny list,
 * so precedence stays exactly the one the engine documents (allow beats custom
 * deny beats category beats default allow). A change rebuilds the snapshot and
 * publishes it atomically; readers always see a complete engine.</p>
 */
public final class PolicyHolder {

    private final Map<String, DomainSet> categories;
    private final DomainSet baseAllow;
    private final DomainSet baseDeny;
    private final Set<String> allowOverrides = ConcurrentHashMap.newKeySet();
    private final Set<String> blockOverrides = ConcurrentHashMap.newKeySet();
    private final Path overridesFile;
    private volatile PolicyEngine engine;

    public PolicyHolder(DomainSet baseAllow, Map<String, DomainSet> categories, DomainSet baseDeny,
                        Path overridesFile) {
        this.baseAllow = baseAllow == null ? new DomainSet() : baseAllow;
        this.categories = categories == null ? Collections.emptyMap() : new TreeMap<>(categories);
        this.baseDeny = baseDeny == null ? new DomainSet() : baseDeny;
        this.overridesFile = overridesFile;
        loadOverrides();
        rebuild();
    }

    public PolicyEngine engine() {
        return engine;
    }

    /** Current decision for a name, for the chat helper; null when it is not a domain. */
    public PolicyEngine.Decision decide(String domain) {
        String d = normalise(domain);
        return d == null ? null : engine.decide(d, -1);
    }

    public Set<String> allowOverrides() {
        return Set.copyOf(allowOverrides);
    }

    public Set<String> blockOverrides() {
        return Set.copyOf(blockOverrides);
    }

    /** Dashboard "Mark safe": allow wins over categories and over a model verdict. */
    public void markSafe(String domain) {
        String d = normalise(domain);
        if (d == null) return;
        blockOverrides.remove(d);
        allowOverrides.add(d);
        persist("allow", d, true);
        rebuild();
    }

    /** Dashboard "Block": a custom deny, which still loses to an explicit allow. */
    public void markBlocked(String domain) {
        String d = normalise(domain);
        if (d == null) return;
        allowOverrides.remove(d);
        blockOverrides.add(d);
        persist("block", d, true);
        rebuild();
    }

    private void rebuild() {
        DomainSet allow = union(baseAllow, allowOverrides);
        DomainSet deny = union(baseDeny, blockOverrides);
        engine = new PolicyEngine(allow, categories, Collections.emptySet(), deny,
                null, null, null);
    }

    private static DomainSet union(DomainSet base, Set<String> extra) {
        if (extra.isEmpty()) return base;
        Set<String> all = new LinkedHashSet<>(base.patterns());
        all.addAll(extra);
        return DomainSet.of(all);
    }

    /** Only plain hostnames are accepted, so a hand-edited file cannot inject patterns. */
    static String normalise(String domain) {
        if (domain == null) return null;
        String d = domain.trim().toLowerCase(java.util.Locale.ROOT);
        while (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        if (d.isEmpty() || d.length() > 253) return null;
        DomainPattern p = DomainPattern.parse(d);
        return p == null ? null : p.text();
    }

    private void loadOverrides() {
        if (overridesFile == null || !Files.exists(overridesFile)) return;
        try {
            for (String line : Files.readAllLines(overridesFile, StandardCharsets.UTF_8)) {
                String[] f = line.split("\t");
                if (f.length != 2) continue;
                String d = normalise(f[1]);
                if (d == null) continue;
                if (f[0].equals("allow")) allowOverrides.add(d);
                else if (f[0].equals("block")) blockOverrides.add(d);
            }
        } catch (IOException ignored) {
            // A corrupt override file must not stop the filter from starting.
        }
    }

    private synchronized void persist(String action, String domain, boolean append) {
        if (overridesFile == null) return;
        try {
            if (overridesFile.getParent() != null) Files.createDirectories(overridesFile.getParent());
            Files.write(overridesFile, (action + "\t" + domain + "\n").getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // Losing a persisted override is better than failing the request.
        }
    }

    /** Rewrites the file compactly; used by tests and by the dashboard on demand. */
    public synchronized void compact() {
        if (overridesFile == null) return;
        List<String> lines = new ArrayList<>();
        for (String d : new java.util.TreeSet<>(allowOverrides)) lines.add("allow\t" + d);
        for (String d : new java.util.TreeSet<>(blockOverrides)) lines.add("block\t" + d);
        try {
            Files.write(overridesFile, lines, StandardCharsets.UTF_8);
        } catch (IOException ignored) {
            // Best effort.
        }
    }
}
