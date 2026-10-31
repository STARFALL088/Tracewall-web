package tracewall.desktop;

import tracewall.blocklist.PolicyEngine;
import tracewall.net.DnsMessage;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Turns one DNS query into one DNS answer.
 *
 * <p>Order of decisions, matching the engine's own precedence:</p>
 * <ol>
 *   <li>the {@link PolicyEngine} decides (allow list, custom deny, categories);</li>
 *   <li>only when the engine says {@code ALLOW_DEFAULT} is the AI classifier asked;</li>
 *   <li>anything not blocked is forwarded to the configured upstream resolvers.</li>
 * </ol>
 *
 * <p>A blocked A query answers {@code 0.0.0.0}; every other blocked type gets
 * an empty NOERROR answer, which is what the Android app does and what stops
 * clients from falling back to the blocked address over another record type.</p>
 */
public final class QueryHandler {

    private static final byte[] ZERO_ADDRESS = {0, 0, 0, 0};

    private final PolicyHolder policy;
    private final Forwarder forwarder;
    private final AiClassifier ai;
    private final double aiThreshold;
    private final Stats stats;
    private final EventLog events;
    private final AtomicInteger queryIds = new AtomicInteger(0x2000);

    public QueryHandler(PolicyHolder policy, Forwarder forwarder, AiClassifier ai,
                        double aiThreshold, Stats stats, EventLog events) {
        this.policy = policy;
        this.forwarder = forwarder;
        this.ai = ai;
        this.aiThreshold = aiThreshold;
        this.stats = stats;
        this.events = events;
    }

    /**
     * @return the response bytes, or {@code null} when the query must be
     *         dropped silently (unparseable or not a simple query)
     */
    public byte[] handle(byte[] query, InetSocketAddress client) {
        stats.total.incrementAndGet();
        DnsMessage q = DnsMessage.parse(query);
        if (q == null || !q.isSimpleQuery()) {
            stats.malformed.incrementAndGet();
            return null;
        }

        String host = q.qName();
        String clientText = client == null ? "-" : client.getAddress().getHostAddress();
        PolicyEngine.Decision decision = policy.engine().decide(host, -1);

        String action;
        String reason;
        String category = null;
        Double confidence = null;
        AiClassifier.Verdict aiVerdict = null;

        if (decision.blocked()) {
            if (decision.verdict == PolicyEngine.Verdict.BLOCK_CATEGORY) {
                stats.blockedCategory.incrementAndGet();
                category = decision.reason;
            } else {
                stats.blockedCustom.incrementAndGet();
            }
            action = "BLOCK";
            reason = decision.toString();
        } else if (decision.verdict == PolicyEngine.Verdict.ALLOW_DEFAULT && ai != null) {
            aiVerdict = ai.lookup(host);
            if (aiVerdict != null && aiVerdict.shouldBlock(aiThreshold)) {
                stats.blockedAi.incrementAndGet();
                action = "BLOCK";
                category = aiVerdict.category();
                confidence = aiVerdict.confidence();
                reason = "AI:" + aiVerdict;
            } else {
                action = null;
                reason = null;
            }
        } else {
            action = null;
            reason = null;
        }

        byte[] answer;
        if ("BLOCK".equals(action)) {
            answer = blockedAnswer(q);
        } else {
            try {
                Forwarder.Reply reply = forwarder.forward(query, queryIds.incrementAndGet() & 0xFFFF);
                answer = DnsMessage.normalizeResponse(reply.bytes(), q.id(), false);
                if (answer == null) {
                    stats.servfail.incrementAndGet();
                    answer = DnsMessage.buildServFail(q);
                    action = "SERVFAIL";
                    reason = "unparseable upstream reply";
                } else {
                    stats.allowed.incrementAndGet();
                    action = "ALLOW";
                    reason = decision.verdict == PolicyEngine.Verdict.ALLOW_LISTED
                            ? decision.reason : "";
                }
            } catch (Exception e) {
                stats.servfail.incrementAndGet();
                answer = DnsMessage.buildServFail(q);
                action = "SERVFAIL";
                reason = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            }
        }

        if (events != null) {
            events.add(new EventLog.Event(System.currentTimeMillis(), action, host, reason,
                    category, confidence, clientText));
        }
        return answer;
    }

    private static byte[] blockedAnswer(DnsMessage q) {
        if (q.qType() == DnsMessage.TYPE_A) {
            byte[] a = DnsMessage.buildAResponse(q, ZERO_ADDRESS);
            if (a != null) return a;
        }
        return DnsMessage.buildEmptyResponse(q);
    }
}
