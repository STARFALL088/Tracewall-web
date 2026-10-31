package tracewall.desktop;

import tracewall.blocklist.DomainSet;
import tracewall.blocklist.HostListParser;
import tracewall.net.DnsForwarder;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Command-line entry point. Parses arguments, loads the lists, wires the
 * components together and runs until interrupted.
 */
public final class Main {

    private static final int DEFAULT_PORT = 5354;

    public static void main(String[] args) {
        try {
            run(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println("run with --help for usage");
            System.exit(2);
        } catch (Exception e) {
            System.err.println("fatal: " + e.getMessage());
            System.exit(1);
        }
    }

    static void run(String[] args) throws Exception {
        Config config = Config.parse(args);
        if (config.help) {
            Config.printUsage();
            return;
        }

        Map<String, DomainSet> categories = new TreeMap<>();
        long started = System.nanoTime();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(config.lists, "*.txt")) {
            for (Path file : stream) {
                String name = file.getFileName().toString().replaceFirst("\\.txt$", "");
                String text = Files.readString(file, StandardCharsets.UTF_8);
                HostListParser.Result parsed = HostListParser.parse(text);
                categories.put(name, parsed.set());
            }
        }
        if (categories.isEmpty()) {
            throw new IllegalArgumentException("no *.txt category lists found in " + config.lists);
        }

        DomainSet allow = DomainSet.of(config.allow);
        PolicyHolder policy = new PolicyHolder(allow, categories, new DomainSet(), config.overridesFile());
        long loadMs = (System.nanoTime() - started) / 1_000_000;
        System.out.printf("loaded %s in %d ms%n", policy.engine().summary(), loadMs);

        DnsForwarder forwarder = new DnsForwarder(config.upstream, DnsForwarder.DEFAULT_TIMEOUT_MS, null);
        System.out.println("upstream: " + forwarder.resolvers());

        Stats stats = new Stats();
        EventLog events = new EventLog(200);
        AiClassifier ai = null;
        if (config.aiModel != null) {
            OllamaClient client = new OllamaClient(config.aiUrl, java.time.Duration.ofSeconds(2),
                    java.time.Duration.ofSeconds(120), java.time.Duration.ofSeconds(30));
            ai = new AiClassifier(client, config.aiModel, config.aiWaitMs, config.aiCache);
            System.out.println("AI classifier: model=" + config.aiModel + " url=" + client.baseUrl()
                    + " wait=" + config.aiWaitMs + "ms threshold=" + config.aiThreshold
                    + " cache=" + config.aiCache);
        } else {
            System.out.println("AI classifier: off (no --ai-model)");
        }

        QueryHandler handler = new QueryHandler(policy, new Forwarder.Udp(forwarder), ai,
                config.aiThreshold, stats, events);
        DnsServer server = new DnsServer(config.bind, config.port, handler, stats, List.of());
        server.start();
        System.out.println("listening on UDP " + config.bind.getHostAddress() + ":" + server.port());
        System.out.println("try: dig @127.0.0.1 -p " + server.port() + " xvideos.com");

        AiClassifier classifier = ai;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            if (classifier != null) classifier.shutdown();
        }, "shutdown"));

        // Keep the main thread alive; the receive loop is a daemon.
        Thread.currentThread().join();
    }

    /** Parsed command line. Package-private so tests can build one without a process. */
    static final class Config {
        int port = DEFAULT_PORT;
        InetAddress bind = InetAddress.getLoopbackAddress();
        Path lists = Paths.get("lists");
        Path overrides = Paths.get("overrides.tsv");
        List<String> allow = new ArrayList<>();
        List<String> upstream = new ArrayList<>();
        String aiModel;
        String aiUrl = OllamaClient.DEFAULT_BASE_URL;
        long aiWaitMs = 1500;
        double aiThreshold = 0.8;
        Path aiCache = Paths.get("ai-cache.tsv");
        boolean help;

        Path overridesFile() {
            return overrides;
        }

        static Config parse(String[] args) throws IOException {
            Config c = new Config();
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--help", "-h" -> c.help = true;
                    case "--port" -> c.port = Integer.parseInt(next(args, ++i));
                    case "--bind" -> c.bind = InetAddress.getByName(next(args, ++i));
                    case "--lists" -> c.lists = Paths.get(next(args, ++i));
                    case "--allow" -> c.allow.add(next(args, ++i));
                    case "--upstream" -> c.upstream.addAll(List.of(next(args, ++i).split(",")));
                    case "--ai-model" -> c.aiModel = next(args, ++i);
                    case "--ai-url" -> c.aiUrl = next(args, ++i);
                    case "--ai-wait-ms" -> c.aiWaitMs = Long.parseLong(next(args, ++i));
                    case "--ai-threshold" -> c.aiThreshold = Double.parseDouble(next(args, ++i));
                    case "--ai-cache" -> c.aiCache = Paths.get(next(args, ++i));
                    default -> throw new IllegalArgumentException("unknown option " + args[i]);
                }
            }
            return c;
        }

        private static String next(String[] args, int index) {
            if (index >= args.length) throw new IllegalArgumentException("missing value for " + args[index - 1]);
            return args[index];
        }

        static void printUsage() {
            System.out.println("""
                    Tracewall Desktop - a local DNS sinkhole with an optional AI classifier

                    Usage: ./gradlew run --args="--lists lists [options]"

                      --port N            UDP port to listen on (default 5354)
                      --bind ADDR         address to bind (default 127.0.0.1)
                      --lists DIR         directory of hosts-format *.txt lists (default lists)
                      --allow DOMAIN      allowlist entry, repeatable
                      --upstream IP[,IP]  upstream resolvers (default 1.1.1.1,8.8.8.8)
                      --ai-model TAG      Ollama model tag; omit to disable the AI layer
                      --ai-url URL        Ollama base URL (default http://127.0.0.1:11434)
                      --ai-wait-ms N      how long a query waits for the model (default 1500)
                      --ai-threshold F    confidence needed to block (default 0.8)
                      --ai-cache FILE     verdict cache (default ai-cache.tsv)
                      --help              this text
                    """);
        }
    }
}
