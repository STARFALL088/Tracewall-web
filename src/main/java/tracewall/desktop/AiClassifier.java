package tracewall.desktop;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Asks a local open-weight model, served by Ollama, to classify a domain that
 * no blocklist knows.
 *
 * <p>The classifier is advisory and fail-open: if the model is slow, down or
 * unsure the query is allowed and the engine's normal rules still apply.
 * Verdicts are cached on disk so a demo is repeatable and works offline.</p>
 */
public final class AiClassifier {

    /** A model answer. {@code unknown} means "no opinion". */
    public record Verdict(String category, double confidence) {
        public boolean shouldBlock(double threshold) {
            return (category.equals("adult") || category.equals("gambling") || category.equals("malware"))
                    && confidence >= threshold;
        }

        @Override
        public String toString() {
            return category + " " + String.format(Locale.ROOT, "%.2f", confidence);
        }
    }

    static final Pattern VALID = Pattern.compile(
            "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$");
    static final Set<String> SKIP_TLD = new HashSet<>(Arrays.asList(
            "arpa", "local", "lan", "internal", "localhost", "home", "corp", "test", "invalid"));
    static final Set<String> SECOND = new HashSet<>(Arrays.asList(
            "co", "com", "org", "net", "gov", "edu", "ac"));
    static final Set<String> CATEGORIES = new HashSet<>(Arrays.asList(
            "adult", "gambling", "malware", "ads", "safe"));

    private final OllamaClient client;
    private final String model;
    private final long waitMs;
    private final Path cacheFile;
    private final Map<String, Verdict> cache = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<Verdict>> pending = new ConcurrentHashMap<>();
    private final ExecutorService pool = Executors.newFixedThreadPool(2, runnable -> {
        Thread t = new Thread(runnable, "ai-classifier");
        t.setDaemon(true);
        return t;
    });

    public AiClassifier(OllamaClient client, String model, long waitMs, Path cacheFile) {
        this.client = client;
        this.model = model;
        this.waitMs = waitMs;
        this.cacheFile = cacheFile;
        loadCache();
    }

    /** null means "no opinion": invalid name, model slow, model down, or model unsure. */
    public Verdict lookup(String host) {
        String domain = registrable(host);
        if (domain == null) return null;
        Verdict cached = cache.get(domain);
        if (cached != null) {
            return cached.category().equals("unknown") ? null : cached;
        }
        CompletableFuture<Verdict> future = pending.computeIfAbsent(domain,
                key -> CompletableFuture.supplyAsync(() -> classify(key), pool));
        try {
            Verdict verdict = future.get(waitMs, TimeUnit.MILLISECONDS);
            return verdict == null || verdict.category().equals("unknown") ? null : verdict;
        } catch (Exception timeoutOrFailure) {
            return null; // fail open; the pending task keeps running and fills the cache
        }
    }

    /**
     * The registrable domain, naively: last two labels, or the last three for
     * second-level public suffixes such as {@code co.uk}.
     *
     * <p>Only a plain hostname may reach the prompt. Anything with spaces,
     * quotes, braces, underscores, a trailing dot trick or an internal TLD is
     * rejected outright, so a hostile query name cannot smuggle instructions
     * into the model.</p>
     */
    public static String registrable(String host) {
        if (host == null) return null;
        String h = host.toLowerCase(Locale.ROOT);
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (h.isEmpty() || h.length() > 100 || !VALID.matcher(h).matches()) return null;
        String[] parts = h.split("\\.");
        if (SKIP_TLD.contains(parts[parts.length - 1])) return null;
        int keep = (parts.length >= 3 && parts[parts.length - 1].length() == 2
                && SECOND.contains(parts[parts.length - 2])) ? 3 : 2;
        return String.join(".", Arrays.copyOfRange(parts, Math.max(0, parts.length - keep), parts.length));
    }

    private Verdict classify(String domain) {
        Verdict out = new Verdict("unknown", 0);
        try {
            String prompt = "You classify domain names for a parental-control DNS filter. "
                    + "Categories: adult, gambling, malware, ads, safe. Judge only from the name. "
                    + "If unsure, answer safe with low confidence. Domain: " + domain
                    + "\nReply with JSON only: {\"category\":\"...\",\"confidence\":0.0}";
            String response = client.generate(model, prompt, "\"json\"", "30m");
            String inner = jsonStringField(response, "response");
            if (inner == null) return out;
            Matcher category = Pattern.compile("\"category\"\\s*:\\s*\"(\\w+)\"").matcher(inner);
            Matcher confidence = Pattern.compile("\"confidence\"\\s*:\\s*([0-9.]+)").matcher(inner);
            if (!category.find() || !confidence.find()) return out;
            String cat = category.group(1).toLowerCase(Locale.ROOT);
            if (!CATEGORIES.contains(cat)) return out;
            double conf = Math.max(0, Math.min(1, Double.parseDouble(confidence.group(1))));
            out = new Verdict(cat, conf);
            persist(domain, out);
        } catch (Exception e) {
            // out stays "unknown"
        } finally {
            cache.put(domain, out);
            pending.remove(domain);
        }
        return out;
    }

    private void loadCache() {
        if (cacheFile == null || !Files.exists(cacheFile)) return;
        try {
            for (String line : Files.readAllLines(cacheFile, StandardCharsets.UTF_8)) {
                String[] fields = line.split("\t");
                if (fields.length == 3 && CATEGORIES.contains(fields[1])) {
                    cache.put(fields[0], new Verdict(fields[1], Double.parseDouble(fields[2])));
                }
            }
        } catch (Exception ignored) {
            // A corrupt cache is not fatal: it only costs a model call.
        }
    }

    private synchronized void persist(String domain, Verdict verdict) {
        if (cacheFile == null) return;
        try {
            if (cacheFile.getParent() != null) Files.createDirectories(cacheFile.getParent());
            Files.write(cacheFile,
                    (domain + "\t" + verdict.category() + "\t" + verdict.confidence() + "\n")
                            .getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // Best effort.
        }
    }

    /** Reads one top-level JSON string field without a JSON library. */
    public static String jsonStringField(String json, String name) {
        if (json == null) return null;
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*\"").matcher(json);
        if (!m.find()) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = m.end(); i < json.length(); i++) {
            char ch = json.charAt(i);
            if (ch == '"') return sb.toString();
            if (ch == '\\' && i + 1 < json.length()) {
                char next = json.charAt(++i);
                switch (next) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case 'u' -> {
                        if (i + 4 < json.length()) {
                            sb.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
                            i += 4;
                        }
                    }
                    default -> sb.append(next);
                }
            } else {
                sb.append(ch);
            }
        }
        return null;
    }

    public int cacheSize() {
        return cache.size();
    }

    public void shutdown() {
        pool.shutdownNow();
    }
}
