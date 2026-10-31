package tracewall.desktop;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tracewall.blocklist.DomainSet;
import tracewall.net.DnsMessage;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class QueryHandlerTest {

    @TempDir
    Path tmp;

    private static PolicyHolder policy() {
        Map<String, DomainSet> categories = new TreeMap<>();
        categories.put("adult", DomainSet.of(List.of("xvideos.com", "example.com")));
        return new PolicyHolder(DomainSet.of(List.of("example.com")), categories,
                new DomainSet(), null);
    }

    private static QueryHandler handler(PolicyHolder policy, Forwarder forwarder,
                                        AiClassifier ai, double threshold) {
        return new QueryHandler(policy, forwarder, ai, threshold, new Stats(), new EventLog(50));
    }

    private static InetSocketAddress client() throws Exception {
        return new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 40000);
    }

    @Test
    void blockedAQueryAnswersZeroAddress() throws Exception {
        DnsTestSupport.FakeForwarder forwarder = new DnsTestSupport.FakeForwarder();
        byte[] response = handler(policy(), forwarder, null, 0.8)
                .handle(DnsTestSupport.query("xvideos.com", DnsMessage.TYPE_A), client());

        assertNotNull(response);
        assertArrayEquals(new byte[] {0, 0, 0, 0}, DnsTestSupport.firstA(response));
        assertEquals(0, forwarder.calls.get(), "a blocked query must not be forwarded");
    }

    @Test
    void blockedAaaaQueryIsEmptyNoError() throws Exception {
        byte[] response = handler(policy(), new DnsTestSupport.FakeForwarder(), null, 0.8)
                .handle(DnsTestSupport.query("xvideos.com", DnsMessage.TYPE_AAAA), client());

        DnsMessage parsed = DnsMessage.parse(response);
        assertNotNull(parsed);
        assertEquals(DnsMessage.RCODE_NOERROR, parsed.rCode());
        assertEquals(0, parsed.anCount());
    }

    @Test
    void blockedResponseEchoesTheQuestion() throws Exception {
        byte[] query = DnsTestSupport.query(0x4242, "xvideos.com", DnsMessage.TYPE_A);
        byte[] response = handler(policy(), new DnsTestSupport.FakeForwarder(), null, 0.8)
                .handle(query, client());

        DnsMessage parsed = DnsMessage.parse(response);
        assertNotNull(parsed);
        assertEquals(0x4242, parsed.id());
        assertEquals("xvideos.com", parsed.qName());
        assertEquals(DnsMessage.TYPE_A, parsed.qType());
    }

    @Test
    void allowlistBeatsCategory() throws Exception {
        DnsTestSupport.FakeForwarder forwarder = new DnsTestSupport.FakeForwarder();
        byte[] response = handler(policy(), forwarder, null, 0.8)
                .handle(DnsTestSupport.query("example.com", DnsMessage.TYPE_A), client());

        assertEquals(1, forwarder.calls.get(), "allowlisted name must be forwarded");
        assertEquals("93.184.216.34", DnsTestSupport.ip(DnsTestSupport.firstA(response)));
    }

    @Test
    void forwardedAnswerReachesTheClientUnchanged() throws Exception {
        byte[] response = handler(policy(), new DnsTestSupport.FakeForwarder(), null, 0.8)
                .handle(DnsTestSupport.query("allowed-host.xyz", DnsMessage.TYPE_A), client());

        assertEquals("93.184.216.34", DnsTestSupport.ip(DnsTestSupport.firstA(response)));
    }

    @Test
    void listBlockedDomainsNeverReachTheModel() throws Exception {
        try (FakeOllama fake = new FakeOllama()) {
            AiClassifier ai = classifier(fake);
            byte[] response = handler(policy(), new DnsTestSupport.FakeForwarder(), ai, 0.8)
                    .handle(DnsTestSupport.query("xvideos.com", DnsMessage.TYPE_A), client());

            assertArrayEquals(new byte[] {0, 0, 0, 0}, DnsTestSupport.firstA(response));
            assertEquals(0, fake.requests.get(), "the engine's verdict must short-circuit the model");
        }
    }

    @Test
    void aiVerdictAboveThresholdBlocks() throws Exception {
        try (FakeOllama fake = new FakeOllama()) {
            fake.inner = "{\"category\":\"gambling\",\"confidence\":0.93}";
            AiClassifier ai = classifier(fake);
            byte[] response = handler(policy(), new DnsTestSupport.FakeForwarder(), ai, 0.8)
                    .handle(DnsTestSupport.query("casino-bonus.xyz", DnsMessage.TYPE_A), client());

            assertArrayEquals(new byte[] {0, 0, 0, 0}, DnsTestSupport.firstA(response));
            assertEquals(1, fake.requests.get());
        }
    }

    @Test
    void aiVerdictBelowThresholdIsAllowed() throws Exception {
        try (FakeOllama fake = new FakeOllama()) {
            fake.inner = "{\"category\":\"gambling\",\"confidence\":0.55}";
            AiClassifier ai = classifier(fake);
            byte[] response = handler(policy(), new DnsTestSupport.FakeForwarder(), ai, 0.8)
                    .handle(DnsTestSupport.query("maybe-casino.xyz", DnsMessage.TYPE_A), client());

            assertEquals("93.184.216.34", DnsTestSupport.ip(DnsTestSupport.firstA(response)));
        }
    }

    @Test
    void malformedPacketsAreDropped() throws Exception {
        byte[] garbage = {0x01, 0x02, 0x03};
        assertNull(handler(policy(), new DnsTestSupport.FakeForwarder(), null, 0.8)
                .handle(garbage, client()));
    }

    private static AiClassifier classifier(FakeOllama fake) {
        OllamaClient client = new OllamaClient(fake.url(), Duration.ofMillis(500),
                Duration.ofSeconds(2), Duration.ofSeconds(2));
        return new AiClassifier(client, "test-model", 2000, null,
                new AiClassifier.Options(false, 60_000, 64, "30m"), Clock.systemUTC(), new Stats());
    }
}
