package tracewall.desktop;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Asks a local open-weight model, served by Ollama, to classify a domain that
 * no blocklist knows.
 *
 * <p>The classifier is advisory and fail-open: if the model is slow, down or
 * unsure the query is allowed and the engine's normal rules still apply.
 * Successful verdicts are cached on disk so a demo is repeatable and works
 * offline.</p>
 *
 * <p>Failures are different from verdicts. A timeout, an HTTP error or an
 * unparseable answer is cached in memory for a short time only
 * ({@link Options#failureTtlMs}, 60 s by default) and never written to the
 * cache file, so one cold start cannot pin a domain to "no opinion" for the
 * rest of the process's life.</p>
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

    /**
     * @param structuredOutput send a JSON schema in {@code format} instead of
     *                         the plain {@code "json"} mode; off by default
     *                         because it needs a recent Ollama
     * @param failureTtlMs     how long a failed classification is remembered
     * @param maxPending       hard cap on in-flight classifications
     * @param keepAlive        how long Ollama keeps the model loaded
     */
    public record Options(boolean structuredOutput, long failureTtlMs, int maxPending, String keepAlive) {
        public static Options defaults() {
            return new Options(false, 60_000, 1024, "30m");
        }

        public Options withStructuredOutput(boolean value) {
            return new Options(value, failureTtlMs, maxPending, keepAlive);
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

    /** Ollama's structured-output schema. Every category is enumerated. */
    static final String SCHEMA = "{\"type\":\"object\",\"properties\":{"
            + "\"category\":{\"type\":\"string\",\"enum\":[\"adult\",\"gambling\",\"malware\",\"ads\",\"safe\"]},"
            + "\"confidence\":{\"type\":\"number\"}},"
            + "\"required\":[\"category\",\"confidence\"]}";

    private static final Pattern CATEGORY_FIELD =
            Pattern.compile("\"category\"\\s*:\\s*\"(\\w+)\"");
    private static final Pattern CONFIDENCE_FIELD =
            Pattern.compile("\"confidence\"\\s*:\\s*([0-9.]+)");

    private final OllamaClient client;
    private final String model;
    private final long waitMs;
    private final Path cacheFile;
    private final Options options;
    private final Clock clock;
    private final Stats stats;
    private final Map<String, Verdict> cache = new ConcurrentHashMap<>();
    private final Map<String, Long> retryAfter = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<Verdict>> pending = new ConcurrentHashMap<>();
    private final ExecutorService pool = Executors.newFixedThreadPool(2, runnable -> {
        Thread thread = new Thread(runnable, "ai-classifier");
        thread.setDaemon(true);
        return thread;
    });

    public AiClassifier(OllamaClient client, String model, long waitMs, Path cacheFile) {
        this(client, model, waitMs, cacheFile, Options.defaults(), Clock.systemUTC(), new Stats());
    }

    public AiClassifier(OllamaClient client, String model, long waitMs, Path cacheFile, Options options) {
        this(client, model, waitMs, cacheFile, options, Clock.systemUTC(), new Stats());
    }

    public AiClassifier(OllamaClient client, String model, long waitMs, Path cacheFile,
                        Options options, Clock clock, Stats stats) {
        this.client = client;
        this.model = model;
        this.waitMs = waitMs;
        this.cacheFile = cacheFile;
        this.options = options;
        this.clock = clock;
        this.stats = stats;
        loadCache();
    }

    /** null means "no opinion": invalid name, model slow, model down, or model unsure. */
    public Verdict lookup(String host) {
        String domain = registrable(host);
        if (domain == null) return null;

        Verdict cached = cache.get(domain);
        if (cached != null) {
            stats.aiCacheHits.incrementAndGet();
            return cached.category().equals("unknown") ? null : cached;
        }

        Long retryAt = retryAfter.get(domain);
        if (retryAt != null) {
            if (clock.millis() < retryAt) return null;
            retryAfter.remove(domain);
        }

        if (pending.size() >= options.maxPending()) {
            // A flood of unique names must not grow this map without limit.
            // Dropping the lookup keeps the process responsive; the engine's
            // rules still apply.
            return null;
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
        try {
            stats.aiCalls.incrementAndGet();
            String response = client.generate(model, buildPrompt(domain), formatValue(),
                    options.keepAlive());
            Verdict verdict = parse(response);
            if (verdict == null) {
                fail(domain);
                return new Verdict("unknown", 0);
            }
            cache.put(domain, verdict);
            retryAfter.remove(domain);
            persist(domain, verdict);
            return verdict;
        } catch (Exception e) {
            fail(domain);
            return new Verdict("unknown", 0);
        } finally {
            pending.remove(domain);
        }
    }

    private String formatValue() {
        return options.structuredOutput() ? SCHEMA : "\"json\"";
    }

    /** Parse the model's answer; null means "not usable". */
    static Verdict parse(String response) {
        String inner = jsonStringField(response, "response");
        if (inner == null) return null;
        Matcher category = CATEGORY_FIELD.matcher(inner);
        Matcher confidence = CONFIDENCE_FIELD.matcher(inner);
        if (!category.find() || !confidence.find()) return null;
        String cat = category.group(1).toLowerCase(Locale.ROOT);
        if (!CATEGORIES.contains(cat)) return null;
        double conf;
        try {
            conf = Double.parseDouble(confidence.group(1));
        } catch (NumberFormatException e) {
            return null;
        }
        return new Verdict(cat, Math.max(0, Math.min(1, conf)));
    }

    private void fail(String domain) {
        long ttl = Math.max(1, options.failureTtlMs());
        retryAfter.put(domain, clock.millis() + ttl);
    }

    /** Six examples, including benign words that contain risky-looking substrings. */
    static String buildPrompt(String domain) {
        return "You classify domain names for a parental-control DNS filter. "
                + "Categories: adult, gambling, malware, ads, safe. "
                + "Judge only from the name. A risky-looking substring inside an ordinary word is not evidence. "
                + "Examples:\n"
                + "sussex-community.net -> {\"category\":\"safe\",\"confidence\":0.92}\n"
                + "assessment-tools.org -> {\"category\":\"safe\",\"confidence\":0.9}\n"
                + "alphabet-school.com -> {\"category\":\"safe\",\"confidence\":0.88}\n"
                + "slotsbonus.xyz -> {\"category\":\"gambling\",\"confidence\":0.86}\n"
                + "free-adult-vids.xyz -> {\"category\":\"adult\",\"confidence\":0.9}\n"
                + "ad-tracker.net -> {\"category\":\"ads\",\"confidence\":0.7}\n"
                + "If unsure, answer safe with low confidence. "
                + "Domain: " + domain + "\n"
                + "Reply with JSON only: {\"category\":\"...\",\"confidence\":0.0}";
    }

    private void loadCache() {
        if (cacheFile == null || !Files.exists(cacheFile)) return;
        try {
            for (String line : Files.readAllLines(cacheFile, StandardCharsets.UTF_8)) {
                String[] fields = line.split("\t");
                if (fields.length != 3 || !CATEGORIES.contains(fields[1])) continue;
                try {
                    cache.put(fields[0], new Verdict(fields[1], Double.parseDouble(fields[2])));
                } catch (NumberFormatException ignored) {
                    // One bad line does not invalidate the rest of the cache.
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

    /**
     * Classify a list of domains before the server starts, so the first real
     * query does not pay the model's cold-load cost. Two workers, progress on
     * stdout, invalid lines skipped.
     *
     * @return how many domains ended up with a usable verdict
     */
    public int prewarm(Path file) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        List<String> domains = new ArrayList<>();
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            String domain = registrable(trimmed);
            if (domain != null) domains.add(domain);
        }
        if (domains.isEmpty()) {
            System.out.println("prewarm: no usable domains in " + file);
            return 0;
        }
        System.out.println("prewarm: classifying " + domains.size() + " domains with model " + model);
        ExecutorService warmPool = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "ai-prewarm");
            thread.setDaemon(true);
            return thread;
        });
        AtomicInteger done = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (String domain : domains) {
            futures.add(warmPool.submit(() -> {
                Verdict verdict = classify(domain);
                int n = done.incrementAndGet();
                System.out.printf("prewarm %d/%d %-40s %s%n", n, domains.size(), domain,
                        verdict.category().equals("unknown") ? "no opinion" : verdict);
            }));
        }
        for (Future<?> future : futures) {
            try {
                future.get(180, TimeUnit.SECONDS);
            } catch (Exception e) {
                // A failed prewarm entry is not fatal; the query path retries.
            }
        }
        warmPool.shutdownNow();
        int usable = 0;
        for (String domain : domains) {
            Verdict verdict = cache.get(domain);
            if (verdict != null && !verdict.category().equals("unknown")) usable++;
        }
        System.out.println("prewarm: " + usable + "/" + domains.size() + " domains have a verdict");
        return usable;
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
                            try {
                                sb.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
                                i += 4;
                            } catch (NumberFormatException ignored) {
                                // Leave the escape as-is rather than failing the whole field.
                            }
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

    /**
     * One classification for the evaluation harness: always asks the model,
     * even when a cached verdict exists, so the latency numbers are real.
     */
    public Verdict evaluate(String host) {
        String domain = registrable(host);
        if (domain == null) return null;
        Verdict verdict = classify(domain);
        return verdict.category().equals("unknown") ? null : verdict;
    }

    public void shutdown() {
        pool.shutdownNow();
    }
}
