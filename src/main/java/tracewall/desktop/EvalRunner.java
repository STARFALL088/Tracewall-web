package tracewall.desktop;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Accuracy check for the classifier against a labelled TSV file.
 *
 * <p>This measures how well the model guesses a category from a hostname
 * alone. It is a sanity check, not a benchmark: the positive rows are sampled
 * from the same blocklists the engine already ships, so the model is being
 * asked about names that are already known to be bad. Performance on genuinely
 * unseen domains will be lower.</p>
 */
public final class EvalRunner {

    public record Row(String domain, String expected, String actual, double confidence,
                      boolean wouldBlock, boolean shouldBlock, long latencyMs) {
        public boolean noOpinion() {
            return actual == null;
        }
    }

    private EvalRunner() { }

    /**
     * @return the number of rows evaluated
     */
    public static int run(Path file, AiClassifier classifier, double threshold, PrintStream out)
            throws IOException {
        List<String[]> input = new ArrayList<>();
        int lineNumber = 0;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            lineNumber++;
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            String[] fields = line.split("\t");
            if (fields.length < 2) {
                out.printf("skip line %d: expected domain<TAB>category%n", lineNumber);
                continue;
            }
            String expected = fields[1].trim().toLowerCase(Locale.ROOT);
            if (!AiClassifier.CATEGORIES.contains(expected)) {
                out.printf("skip line %d: unknown category %s%n", lineNumber, expected);
                continue;
            }
            input.add(new String[] {fields[0].trim(), expected});
        }
        if (input.isEmpty()) {
            out.println("no usable rows in " + file);
            return 0;
        }

        out.printf("%-34s %-9s %-11s %5s %7s %6s%n",
                "domain", "expected", "actual", "conf", "verdict", "ms");
        List<Row> rows = new ArrayList<>();
        for (String[] pair : input) {
            String domain = pair[0];
            String expected = pair[1];
            long started = System.nanoTime();
            AiClassifier.Verdict verdict = classifier.evaluate(domain);
            long latencyMs = (System.nanoTime() - started) / 1_000_000;
            String actual = verdict == null ? null : verdict.category();
            double confidence = verdict == null ? 0 : verdict.confidence();
            boolean shouldBlock = blocks(expected);
            boolean wouldBlock = verdict != null && verdict.shouldBlock(threshold);
            Row row = new Row(domain, expected, actual, confidence, wouldBlock, shouldBlock, latencyMs);
            rows.add(row);
            out.printf("%-34s %-9s %-11s %5s %7s %6d%n",
                    domain, expected, actual == null ? "no-opinion" : actual,
                    verdict == null ? "-" : String.format(Locale.ROOT, "%.2f", confidence),
                    wouldBlock ? "BLOCK" : "allow", latencyMs);
        }

        report(rows, threshold, out);
        return rows.size();
    }

    private static void report(List<Row> rows, double threshold, PrintStream out) {
        int correct = 0;
        int truePositive = 0, falsePositive = 0, trueNegative = 0, falseNegative = 0;
        int safeRows = 0;
        List<Long> latencies = new ArrayList<>();
        for (Row row : rows) {
            if (row.expected().equals(row.actual())) correct++;
            if (row.expected().equals("safe")) safeRows++;
            if (row.shouldBlock() && row.wouldBlock()) truePositive++;
            else if (!row.shouldBlock() && row.wouldBlock()) falsePositive++;
            else if (!row.shouldBlock()) trueNegative++;
            else falseNegative++;
            latencies.add(row.latencyMs());
        }
        int n = rows.size();
        double precision = truePositive + falsePositive == 0 ? 0
                : (double) truePositive / (truePositive + falsePositive);
        double recall = truePositive + falseNegative == 0 ? 0
                : (double) truePositive / (truePositive + falseNegative);
        double falseBlockRate = safeRows == 0 ? 0 : (double) falsePositive / safeRows;
        latencies.sort(Long::compareTo);

        out.println();
        out.printf("rows=%d exact-category-correct=%d accuracy=%.1f%%%n",
                n, correct, 100.0 * correct / n);
        out.printf("block decisions: tp=%d fp=%d tn=%d fn=%d precision=%.2f recall=%.2f%n",
                truePositive, falsePositive, trueNegative, falseNegative, precision, recall);
        out.printf("false-block rate on safe domains: %d/%d = %.1f%%%n",
                falsePositive, safeRows, 100.0 * falseBlockRate);
        out.printf("latency: p50=%dms p95=%dms n=%d (threshold=%.2f)%n",
                percentile(latencies, 50), percentile(latencies, 95), n, threshold);
        long noOpinion = rows.stream().filter(Row::noOpinion).count();
        out.printf("no-opinion rows: %d (%.1f%%) - these are allowed%n",
                noOpinion, 100.0 * noOpinion / n);
    }

    static long percentile(List<Long> sorted, int percent) {
        if (sorted.isEmpty()) return 0;
        int index = (int) Math.ceil(percent / 100.0 * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, index)));
    }

    static boolean blocks(String category) {
        return category.equals("adult") || category.equals("gambling") || category.equals("malware");
    }
}
