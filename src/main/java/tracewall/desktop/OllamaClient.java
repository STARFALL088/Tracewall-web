package tracewall.desktop;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * The only network client in the project besides DNS forwarding.
 *
 * <p>It talks to a local Ollama instance over its plain HTTP API
 * ({@code POST /api/generate}). No SDK, no API key, no cloud endpoint: the
 * default base URL is loopback and nothing here would authenticate against a
 * remote service anyway.</p>
 */
public final class OllamaClient {

    public static final String DEFAULT_BASE_URL = "http://127.0.0.1:11434";

    private final HttpClient http;
    private final URI endpoint;
    private final Duration coldReadTimeout;
    private final Duration warmReadTimeout;
    private volatile boolean modelWarm;

    public OllamaClient(String baseUrl, Duration connectTimeout,
                        Duration coldReadTimeout, Duration warmReadTimeout) {
        String base = baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE_URL : baseUrl.trim();
        base = base.replaceAll("/+$", "");
        this.endpoint = URI.create(base + "/api/generate");
        this.coldReadTimeout = coldReadTimeout;
        this.warmReadTimeout = warmReadTimeout;
        this.http = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public String baseUrl() {
        return endpoint.toString().replace("/api/generate", "");
    }

    /**
     * Ask the model for one completion.
     *
     * @param model     the Ollama model tag, e.g. a small instruction model
     * @param prompt    the full prompt
     * @param format    a JSON value already encoded for the request body:
     *                  {@code "json"} or a JSON-schema object
     * @param keepAlive how long Ollama should keep the model resident
     * @return the raw JSON response body
     * @throws IOException          on transport failure or a non-200 answer
     * @throws InterruptedException when the calling thread is interrupted
     */
    public String generate(String model, String prompt, String format, String keepAlive)
            throws IOException, InterruptedException {
        String body = "{\"model\":\"" + jsonEscape(model) + "\""
                + ",\"prompt\":\"" + jsonEscape(prompt) + "\""
                + ",\"stream\":false"
                + ",\"format\":" + format
                + ",\"keep_alive\":\"" + jsonEscape(keepAlive) + "\""
                + ",\"options\":{\"temperature\":0}}";
        return send(body);
    }

    /**
     * Ask the model for free-form text (no JSON constraint), capped at
     * {@code maxTokens} generated tokens. Used by the dashboard's chat helper.
     *
     * @return the raw JSON response body; the text is in its {@code response} field
     */
    public String generateText(String model, String prompt, String keepAlive, int maxTokens)
            throws IOException, InterruptedException {
        String body = "{\"model\":\"" + jsonEscape(model) + "\""
                + ",\"prompt\":\"" + jsonEscape(prompt) + "\""
                + ",\"stream\":false"
                + ",\"keep_alive\":\"" + jsonEscape(keepAlive) + "\""
                + ",\"options\":{\"temperature\":0,\"num_predict\":" + Math.max(16, maxTokens) + "}}";
        return send(body);
    }

    private String send(String body) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(modelWarm ? warmReadTimeout : coldReadTimeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response =
                http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            throw new IOException("ollama HTTP " + response.statusCode());
        }
        // The first successful call may have loaded a multi-GB model; later
        // calls get the short timeout.
        modelWarm = true;
        return response.body();
    }

    public boolean isModelWarm() {
        return modelWarm;
    }

    /** Package-private for tests: forget that the model was warm. */
    void resetWarm() {
        modelWarm = false;
    }

    static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
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
}
