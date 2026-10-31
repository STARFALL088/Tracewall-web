package tracewall.desktop;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tracewall.blocklist.DomainSet;
import tracewall.blocklist.PolicyEngine;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DashboardTest {

    @TempDir
    Path tmp;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2)).build();

    private Dashboard dashboard(PolicyHolder policy) throws Exception {
        Dashboard dashboard = new Dashboard(InetAddress.getByName("127.0.0.1"), 0, policy,
                new Stats(), new EventLog(10), null);
        dashboard.start();
        return dashboard;
    }

    private static PolicyHolder policy(Path overrides) {
        Map<String, DomainSet> categories = new TreeMap<>();
        categories.put("adult", DomainSet.of(java.util.List.of("xvideos.com")));
        return new PolicyHolder(new DomainSet(), categories, new DomainSet(), overrides);
    }

    @Test
    void statsEndpointIsJson() throws Exception {
        try (Dashboard dashboard = dashboard(policy(tmp.resolve("o.tsv")))) {
            HttpResponse<String> response = get(dashboard, "/api/stats");
            assertEquals(200, response.statusCode());
            assertTrue(response.body().startsWith("{"));
            assertTrue(response.body().contains("\"total\":0"));
        }
    }

    @Test
    void eventsAndVerdictsAreArrays() throws Exception {
        try (Dashboard dashboard = dashboard(policy(tmp.resolve("o.tsv")))) {
            assertEquals("[]", get(dashboard, "/api/events").body());
            assertEquals("[]", get(dashboard, "/api/verdicts").body());
        }
    }

    @Test
    void pageEmbedsTheTokenAndNoExternalResources() throws Exception {
        try (Dashboard dashboard = dashboard(policy(tmp.resolve("o.tsv")))) {
            String page = get(dashboard, "/").body();
            assertTrue(page.contains(dashboard.token()));
            assertFalse(page.contains("http://"), "page must not load external resources");
            assertTrue(page.contains("prefers-color-scheme"));
        }
    }

    @Test
    void postWithoutTokenIsRejected() throws Exception {
        try (Dashboard dashboard = dashboard(policy(tmp.resolve("o.tsv")))) {
            HttpResponse<String> response = post(dashboard, null, null,
                    "{\"domain\":\"casino-bonus.xyz\",\"action\":\"allow\"}");
            assertEquals(403, response.statusCode());
        }
    }

    @Test
    void postWithWrongTokenIsRejected() throws Exception {
        try (Dashboard dashboard = dashboard(policy(tmp.resolve("o.tsv")))) {
            HttpResponse<String> response = post(dashboard, "deadbeef", null,
                    "{\"domain\":\"casino-bonus.xyz\",\"action\":\"allow\"}");
            assertEquals(403, response.statusCode());
        }
    }

    @Test
    void postFromAForeignOriginIsRejected() throws Exception {
        try (Dashboard dashboard = dashboard(policy(tmp.resolve("o.tsv")))) {
            HttpResponse<String> response = post(dashboard, dashboard.token(),
                    "http://evil.example", "{\"domain\":\"casino-bonus.xyz\",\"action\":\"allow\"}");
            assertEquals(403, response.statusCode());
        }
    }

    @Test
    void allowOverrideGoesThroughTheEngineAllowList() throws Exception {
        PolicyHolder policy = policy(tmp.resolve("o.tsv"));
        try (Dashboard dashboard = dashboard(policy)) {
            HttpResponse<String> response = post(dashboard, dashboard.token(), null,
                    "{\"domain\":\"casino-bonus.xyz\",\"action\":\"allow\"}");
            assertEquals(200, response.statusCode());
            assertEquals(PolicyEngine.Verdict.ALLOW_LISTED,
                    policy.engine().decide("casino-bonus.xyz", -1).verdict);
        }
    }

    @Test
    void blockOverrideBecomesACustomDeny() throws Exception {
        PolicyHolder policy = policy(tmp.resolve("o.tsv"));
        try (Dashboard dashboard = dashboard(policy)) {
            post(dashboard, dashboard.token(), null,
                    "{\"domain\":\"annoying-ads.xyz\",\"action\":\"block\"}");
            assertEquals(PolicyEngine.Verdict.BLOCK_CUSTOM,
                    policy.engine().decide("annoying-ads.xyz", -1).verdict);
        }
    }

    @Test
    void hostAndOriginChecksOnlyAcceptLoopback() {
        assertTrue(Dashboard.hostAllowed("127.0.0.1:8080", 8080));
        assertTrue(Dashboard.hostAllowed("localhost:8080", 8080));
        assertFalse(Dashboard.hostAllowed("evil.example:8080", 8080));
        assertFalse(Dashboard.hostAllowed(null, 8080));
        assertTrue(Dashboard.originAllowed("http://127.0.0.1:8080", 8080));
        assertFalse(Dashboard.originAllowed("http://evil.example", 8080));
    }

    private static HttpResponse<String> get(Dashboard dashboard, String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + dashboard.port() + path)).GET().build();
        return HTTP.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(Dashboard dashboard, String token, String origin,
                                             String body) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + dashboard.port() + "/api/override"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) builder.header("X-Tracewall-Token", token);
        if (origin != null) builder.header("Origin", origin);
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }
}
