package tracewall.desktop;

/**
 * The one network dependency of the query path.
 *
 * <p>Production wires this to {@link tracewall.net.DnsForwarder}. Tests supply
 * their own, so no test ever touches the real internet.</p>
 */
public interface Forwarder {

    /** A resolver reply, already normalised by the caller. */
    record Reply(byte[] bytes, String resolver) { }

    /**
     * Forward a raw query.
     *
     * @param query   the original query bytes
     * @param queryId the transaction id the resolver should answer with
     * @throws Exception when every configured resolver failed
     */
    Reply forward(byte[] query, int queryId) throws Exception;

    /** Adapter over the engine's UDP/TCP forwarder. */
    final class Udp implements Forwarder {
        private final tracewall.net.DnsForwarder delegate;

        public Udp(tracewall.net.DnsForwarder delegate) {
            this.delegate = delegate;
        }

        @Override
        public Reply forward(byte[] query, int queryId) throws Exception {
            tracewall.net.DnsForwarder.Reply reply = delegate.forward(query, queryId);
            return new Reply(reply.bytes, reply.resolver);
        }
    }
}
