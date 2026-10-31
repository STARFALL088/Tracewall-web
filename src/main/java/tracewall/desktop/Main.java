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
        OllamaClient chatClient = null;
        String aiModel = config.aiModel != null ? config.aiModel : System.getenv("TRACEWALL_AI_MODEL");
        if (aiModel != null && !aiModel.isBlank()) {
            OllamaClient client = new OllamaClient(config.aiUrl, java.time.Duration.ofSeconds(2),
                    java.time.Duration.ofSeconds(120), java.time.Duration.ofSeconds(30));
            AiClassifier.Options options = AiClassifier.Options.defaults()
                    .withStructuredOutput(config.aiSchema);
            chatClient = client;
            ai = new AiClassifier(client, aiModel, config.aiWaitMs, config.aiCache,
                    options, java.time.Clock.systemUTC(), stats);
            System.out.println("AI classifier: model=" + aiModel + " url=" + client.baseUrl()
                    + " wait=" + config.aiWaitMs + "ms threshold=" + config.aiThreshold
                    + " format=" + (config.aiSchema ? "schema" : "json")
                    + " cache=" + config.aiCache);
            if (config.aiPrewarm != null) {
                ai.prewarm(config.aiPrewarm);
            }
        } else {
            if (config.aiPrewarm != null) {
                throw new IllegalArgumentException("--ai-prewarm needs --ai-model or TRACEWALL_AI_MODEL");
            }
            System.out.println("AI classifier: off (no --ai-model and no TRACEWALL_AI_MODEL)");
        }

        // The dashboard chat can use its own model, so turning it on does not
        // also make every unseen DNS name wait on a model call.
        String chatModel = config.chatModel != null ? config.chatModel
                : System.getenv("TRACEWALL_CHAT_MODEL");
        if (chatModel == null || chatModel.isBlank()) chatModel = aiModel;
        if (chatModel != null && !chatModel.isBlank() && chatClient == null) {
            chatClient = new OllamaClient(config.aiUrl, java.time.Duration.ofSeconds(2),
                    java.time.Duration.ofSeconds(120), java.time.Duration.ofSeconds(30));
        }

        if (config.aiEval != null) {
            if (ai == null) {
                throw new IllegalArgumentException("--ai-eval needs --ai-model or TRACEWALL_AI_MODEL");
            }
            EvalRunner.run(config.aiEval, ai, config.aiThreshold, System.out);
            ai.shutdown();
            return;
        }

        QueryHandler handler = new QueryHandler(policy, new Forwarder.Udp(forwarder), ai,
                config.aiThreshold, stats, events);
        List<Cidr> allowClients = new ArrayList<>();
        for (String cidr : config.allowClients) allowClients.add(Cidr.parse(cidr));
        DnsServer server = new DnsServer(config.bind, config.port, handler, stats, allowClients);
        server.start();
        System.out.println("listening on UDP " + config.bind.getHostAddress() + ":" + server.port());
        if (config.bind.isAnyLocalAddress()) {
            System.out.println("WARNING: bound to " + config.bind.getHostAddress()
                    + " - this is an OPEN RESOLVER for every host that can reach this machine."
                    + " Use --allow-client to restrict it.");
        }
        if (!allowClients.isEmpty()) {
            System.out.println("serving only: " + allowClients);
        }
        System.out.println("try: dig @127.0.0.1 -p " + server.port() + " xvideos.com");

        Thread statsThread = null;
        if (config.statsIntervalSeconds > 0) {
            statsThread = new Thread(() -> {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(config.statsIntervalSeconds * 1000L);
                    } catch (InterruptedException e) {
                        return;
                    }
                    System.out.println(stats.oneLine());
                }
            }, "stats");
            statsThread.setDaemon(true);
            statsThread.start();
        }

        AiClassifier classifier = ai;
        Dashboard dashboard = null;
        if (config.dashboardPort > 0) {
            ChatBot chat = new ChatBot(chatClient, chatModel, stats, events, policy::decide);
            dashboard = new Dashboard(InetAddress.getByName("127.0.0.1"), config.dashboardPort,
                    policy, stats, events, ai, chat);
            dashboard.start();
            System.out.println("chat helper: " + (chat.usesModel() ? "model=" + chatModel : "docs only (no model)"));
            System.out.println("dashboard: http://127.0.0.1:" + dashboard.port()
                    + "  (write token: " + dashboard.token() + ")");
        }
        Dashboard finalDashboard = dashboard;
        Thread finalStatsThread = statsThread;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            if (finalDashboard != null) finalDashboard.close();
            if (finalStatsThread != null) finalStatsThread.interrupt();
            if (classifier != null) classifier.shutdown();
        }, "shutdown"));

        // Keep the main thread alive; the receive loop is a daemon.
        Thread.currentThread().join();
    }

    /** Parsed command line. Package-private so tests can build one without a process. */
    static final class Config {
        int port = DEFAULT_PORT;
        InetAddress bind;
        Path lists = Paths.get("lists");
        Path overrides = Paths.get("overrides.tsv");
        List<String> allow = new ArrayList<>();
        List<String> upstream = new ArrayList<>();
        List<String> allowClients = new ArrayList<>();
        long statsIntervalSeconds = 10;
        int dashboardPort = 8080;
        String aiModel;
        String chatModel;
        String aiUrl = OllamaClient.DEFAULT_BASE_URL;
        long aiWaitMs = 1500;
        double aiThreshold = 0.8;
        Path aiCache = Paths.get("ai-cache.tsv");
        boolean aiSchema;
        Path aiPrewarm;
        Path aiEval;
        boolean help;

        Path overridesFile() {
            return overrides;
        }

        static Config parse(String[] args) throws IOException {
            Config c = new Config();
            c.bind = InetAddress.getByName("127.0.0.1");
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--help", "-h" -> c.help = true;
                    case "--port" -> c.port = Integer.parseInt(next(args, ++i));
                    case "--bind" -> c.bind = InetAddress.getByName(next(args, ++i));
                    case "--lists" -> c.lists = Paths.get(next(args, ++i));
                    case "--allow" -> c.allow.add(next(args, ++i));
                    case "--allow-client" -> c.allowClients.add(next(args, ++i));
                    case "--stats-interval" -> c.statsIntervalSeconds = Long.parseLong(next(args, ++i));
                    case "--dashboard-port" -> c.dashboardPort = Integer.parseInt(next(args, ++i));
                    case "--upstream" -> c.upstream.addAll(List.of(next(args, ++i).split(",")));
                    case "--ai-model" -> c.aiModel = next(args, ++i);
                    case "--chat-model" -> c.chatModel = next(args, ++i);
                    case "--ai-url" -> c.aiUrl = next(args, ++i);
                    case "--ai-wait-ms" -> c.aiWaitMs = Long.parseLong(next(args, ++i));
                    case "--ai-threshold" -> c.aiThreshold = Double.parseDouble(next(args, ++i));
                    case "--ai-cache" -> c.aiCache = Paths.get(next(args, ++i));
                    case "--ai-format" -> {
                        String format = next(args, ++i);
                        if (format.equals("schema")) c.aiSchema = true;
                        else if (format.equals("json")) c.aiSchema = false;
                        else throw new IllegalArgumentException("--ai-format must be json or schema");
                    }
                    case "--ai-prewarm" -> c.aiPrewarm = Paths.get(next(args, ++i));
                    case "--ai-eval" -> c.aiEval = Paths.get(next(args, ++i));
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
                      --allow-client CIDR serve only these client IPs, repeatable
                      --stats-interval N  print a stats line every N seconds (0 disables)
                      --dashboard-port N  loopback dashboard port (default 8080, 0 disables)
                      --upstream IP[,IP]  upstream resolvers (default 1.1.1.1,8.8.8.8)
                      --ai-model TAG      Ollama model tag; omit to disable the AI layer
                                          (or set TRACEWALL_AI_MODEL)
                      --chat-model TAG    model for the dashboard chat helper only; does not
                                          turn on DNS classification (or TRACEWALL_CHAT_MODEL)
                      --ai-url URL        Ollama base URL (default http://127.0.0.1:11434)
                      --ai-wait-ms N      how long a query waits for the model (default 1500)
                      --ai-threshold F    confidence needed to block (default 0.8)
                      --ai-cache FILE     verdict cache (default ai-cache.tsv)
                      --ai-format MODE    json (default, works everywhere) or schema
                                          (Ollama structured outputs, needs a recent Ollama)
                      --ai-prewarm FILE   classify one domain per line before serving
                      --ai-eval FILE      TSV domain<TAB>category; print accuracy and exit
                      --help              this text
                    """);
        }
    }
}
