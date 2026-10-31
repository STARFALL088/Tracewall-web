package tracewall.desktop;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-process stand-in for Ollama. No test in this project talks to a real
 * model or to the internet.
 */
final class FakeOllama implements AutoCloseable {

    private final HttpServer server;
    final AtomicInteger requests = new AtomicInteger();
    volatile String inner = "{\"category\":\"gambling\",\"confidence\":0.9}";
    volatile int status = 200;
    volatile long delayMillis;
    volatile String lastBody;

    FakeOllama() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/api/generate", this::handle);
        server.setExecutor(Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "fake-ollama");
            thread.setDaemon(true);
            return thread;
        }));
        server.start();
    }

    private void handle(HttpExchange exchange) throws IOException {
        lastBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requests.incrementAndGet();
        if (delayMillis > 0) {
            try {
                Thread.sleep(delayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        String body = status == 200
                ? "{\"response\":" + quote(inner) + ",\"done\":true}"
                : "{\"error\":\"boom\"}";
        byte[] out = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, out.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(out);
        }
    }

    String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                default -> sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
