package tracewall.desktop;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A one-page dashboard on loopback.
 *
 * <p>It is deliberately small: an embedded HTML page, four JSON endpoints and
 * one write endpoint. The write endpoint is protected by a random token that
 * is printed at startup and embedded in the page, and by Origin/Host checks
 * that keep a random website from driving it through the browser.</p>
 */
public final class Dashboard implements AutoCloseable {

    private static final Pattern DOMAIN_FIELD =
            Pattern.compile("\"domain\"\\s*:\\s*\"([^\"]{1,253})\"");
    private static final Pattern ACTION_FIELD =
            Pattern.compile("\"action\"\\s*:\\s*\"(allow|block)\"");

    private final HttpServer server;
    private final String token;
    private final PolicyHolder policy;
    private final Stats stats;
    private final EventLog events;
    private final AiClassifier ai;
    private final String page;
    private final int port;

    public Dashboard(InetAddress bind, int port, PolicyHolder policy, Stats stats,
                     EventLog events, AiClassifier ai) throws IOException {
        this.policy = policy;
        this.stats = stats;
        this.events = events;
        this.ai = ai;
        this.token = randomToken();
        this.server = HttpServer.create(new InetSocketAddress(bind, port), 0);
        this.port = server.getAddress().getPort();
        this.page = loadPage().replace("__TOKEN__", token);
        server.createContext("/", this::handle);
        server.setExecutor(Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "dashboard");
            thread.setDaemon(true);
            return thread;
        }));
    }

    public String token() {
        return token;
    }

    public int port() {
        return port;
    }

    public void start() {
        server.start();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (!hostAllowed(exchange.getRequestHeaders().getFirst("Host"), port)) {
                send(exchange, 403, "text/plain", "forbidden host\n");
                return;
            }
            String method = exchange.getRequestMethod();
            if ("POST".equals(method)) {
                if (!path.equals("/api/override")) {
                    send(exchange, 405, "text/plain", "method not allowed\n");
                    return;
                }
                handleOverride(exchange);
                return;
            }
            if (!"GET".equals(method)) {
                send(exchange, 405, "text/plain", "method not allowed\n");
                return;
            }
            switch (path) {
                case "/" -> send(exchange, 200, "text/html", page);
                case "/api/stats" -> send(exchange, 200, "application/json", statsJson());
                case "/api/events" -> send(exchange, 200, "application/json", eventsJson());
                case "/api/verdicts" -> send(exchange, 200, "application/json", verdictsJson());
                default -> send(exchange, 404, "text/plain", "not found\n");
            }
        } catch (RuntimeException e) {
            send(exchange, 500, "text/plain", "internal error\n");
        } finally {
            exchange.close();
        }
    }

    private void handleOverride(HttpExchange exchange) throws IOException {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (origin != null && !originAllowed(origin, port)) {
            send(exchange, 403, "application/json", "{\"ok\":false,\"error\":\"bad origin\"}");
            return;
        }
        String supplied = exchange.getRequestHeaders().getFirst("X-Tracewall-Token");
        if (!tokenMatches(supplied)) {
            send(exchange, 403, "application/json", "{\"ok\":false,\"error\":\"bad token\"}");
            return;
        }
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Matcher domainMatcher = DOMAIN_FIELD.matcher(body);
        Matcher actionMatcher = ACTION_FIELD.matcher(body);
        if (!domainMatcher.find() || !actionMatcher.find()) {
            send(exchange, 400, "application/json", "{\"ok\":false,\"error\":\"expected domain and action\"}");
            return;
        }
        String domain = PolicyHolder.normalise(domainMatcher.group(1));
        if (domain == null) {
            send(exchange, 400, "application/json", "{\"ok\":false,\"error\":\"invalid domain\"}");
            return;
        }
        String action = actionMatcher.group(1);
        if (action.equals("allow")) policy.markSafe(domain);
        else policy.markBlocked(domain);

        send(exchange, 200, "application/json",
                "{\"ok\":true,\"domain\":\"" + json(domain) + "\",\"action\":\"" + action + "\"}");
    }

    private boolean tokenMatches(String supplied) {
        if (supplied == null) return false;
        return MessageDigest.isEqual(supplied.getBytes(StandardCharsets.UTF_8),
                token.getBytes(StandardCharsets.UTF_8));
    }

    /** Only the loopback dashboard's own host names are accepted. */
    static boolean hostAllowed(String host, int port) {
        if (host == null) return false;
        String h = host.toLowerCase(Locale.ROOT);
        return h.equals("127.0.0.1:" + port) || h.equals("localhost:" + port)
                || h.equals("[::1]:" + port);
    }

    /** A browser Origin, when present, must be this dashboard. */
    static boolean originAllowed(String origin, int port) {
        String o = origin.toLowerCase(Locale.ROOT);
        return o.equals("http://127.0.0.1:" + port) || o.equals("http://localhost:" + port)
                || o.equals("http://[::1]:" + port);
    }

    private String statsJson() {
        return "{\"total\":" + stats.total.get()
                + ",\"blocked\":" + stats.blocked()
                + ",\"blockedCategory\":" + stats.blockedCategory.get()
                + ",\"blockedCustom\":" + stats.blockedCustom.get()
                + ",\"blockedAi\":" + stats.blockedAi.get()
                + ",\"allowed\":" + stats.allowed.get()
                + ",\"servfail\":" + stats.servfail.get()
                + ",\"dropped\":" + stats.dropped.get()
                + ",\"aiCalls\":" + stats.aiCalls.get()
                + ",\"aiCacheHits\":" + stats.aiCacheHits.get() + "}";
    }

    private String eventsJson() {
        List<EventLog.Event> recent = events.recent(200);
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < recent.size(); i++) {
            EventLog.Event event = recent.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"time\":").append(event.timeMillis())
                    .append(",\"action\":\"").append(json(event.action()))
                    .append("\",\"host\":\"").append(json(event.host()))
                    .append("\",\"reason\":\"").append(json(event.reason()))
                    .append("\",\"category\":").append(event.category() == null
                            ? "null" : "\"" + json(event.category()) + "\"")
                    .append(",\"confidence\":").append(event.confidence() == null
                            ? "null" : event.confidence())
                    .append(",\"client\":\"").append(json(event.client())).append("\"}");
        }
        return sb.append(']').toString();
    }

    private String verdictsJson() {
        if (ai == null) return "[]";
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Map.Entry<String, AiClassifier.Verdict> entry : ai.verdicts().entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"domain\":\"").append(json(entry.getKey()))
                    .append("\",\"category\":\"").append(json(entry.getValue().category()))
                    .append("\",\"confidence\":").append(entry.getValue().confidence()).append('}');
        }
        return sb.append(']').toString();
    }

    static String json(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    private static void send(HttpExchange exchange, int status, String type, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", type + "; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String loadPage() {
        try (InputStream in = Dashboard.class.getResourceAsStream("/dashboard.html")) {
            if (in == null) return "<!doctype html><title>Tracewall</title><p>dashboard.html missing";
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "<!doctype html><title>Tracewall</title><p>dashboard.html unreadable";
        }
    }

    private static String randomToken() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder(32);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
