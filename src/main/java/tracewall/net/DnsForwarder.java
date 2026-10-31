/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Forwards a DNS query to an upstream resolver and returns the reply, with one
 * retry over TCP when the answer comes back truncated.
 *
 * Plain UDP on purpose: the whole point of Tracewall is that no root and no
 * server of ours is involved, so the upstream has to be something the phone
 * already has - the network's own resolver, or a public one the user names.
 * The UI reports which resolver is in use so nobody is surprised.
 *
 * Sockets must be bound outside the VPN by the caller through
 * {@link SocketBinder} before they are connected. Missing that one step is the
 * classic cause of a DNS VPN that resolves nothing: the query goes out of the
 * TUN, comes straight back in, and loops.
 */
public final class DnsForwarder {

    public static final int DEFAULT_TIMEOUT_MS = 5000;
    public static final int TCP_TIMEOUT_MS = 10000;

    private static final String[] PUBLIC_FALLBACK = {
            "1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4",
    };

    /** Lets the service bind our sockets to the physical network, not the TUN. */
    public interface SocketBinder {
        void bind(DatagramSocket s) throws IOException;
        void bind(Socket s) throws IOException;
    }

    public static final class Reply {
        public final byte[] bytes;
        public final boolean overTcp;
        public final String resolver;

        Reply(byte[] bytes, boolean overTcp, String resolver) {
            this.bytes = bytes;
            this.overTcp = overTcp;
            this.resolver = resolver;
        }
    }

    public static final class ForwardException extends Exception {
        public ForwardException(String m) { super(m); }
    }

    private final List<String> resolvers;
    private final int timeoutMs;
    private final SocketBinder binder;
    private final BlockingQueue<DatagramSocket> pool = new ArrayBlockingQueue<>(64);
    private volatile boolean closed;
    private final AtomicInteger idSeq = new AtomicInteger(0x2000);

    public DnsForwarder(List<String> resolvers, int timeoutMs, SocketBinder binder) {
        this.resolvers = (resolvers == null || resolvers.isEmpty())
                ? new ArrayList<>(java.util.Arrays.asList(PUBLIC_FALLBACK))
                : new ArrayList<>(resolvers);
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
        this.binder = binder;
    }

    public List<String> resolvers() { return Collections.unmodifiableList(resolvers); }

    /** Transaction ids are ours, not the client's - we rewrite on the way out. */
    public int nextId() { return idSeq.incrementAndGet() & 0xFFFF; }

    /**
     * Forward one query, trying each resolver in turn. Throws only when every
     * resolver failed; the caller turns that into SERVFAIL so the client
     * gives up instead of retrying forever.
     */
    public Reply forward(byte[] query, int queryId) throws ForwardException {
        if (query == null || query.length < DnsMessage.HEADER_LEN) {
            throw new ForwardException("query too short");
        }
        if (query.length > IpPacket.MAX_DNS_BYTES) {
            throw new ForwardException("query too large: " + query.length);
        }
        StringBuilder tried = new StringBuilder();
        for (String r : resolvers) {
            if (closed) throw new ForwardException("forwarder closed");
            if (r == null || r.trim().isEmpty()) continue;
            try {
                return forwardOne(r.trim(), query, queryId);
            } catch (ForwardException e) {
                tried.append(tried.length() == 0 ? "" : "; ").append(e.getMessage());
            }
        }
        throw new ForwardException(tried.length() == 0 ? "no resolver configured" : tried.toString());
    }

    private Reply forwardOne(String resolver, byte[] query, int queryId)
            throws ForwardException {
        InetAddress addr;
        try {
            addr = InetAddress.getByName(resolver);
        } catch (IOException e) {
            throw new ForwardException(resolver + ": unresolvable (" + e.getMessage() + ")");
        }

        byte[] wire = DnsMessage.copy(query, 0, query.length);
        DnsMessage.putU16(wire, 0, queryId);

        DatagramSocket sock = null;
        try {
            sock = acquire();
            if (binder != null) binder.bind(sock);
            sock.connect(addr, IpPacket.PORT_DNS);
            sock.setSoTimeout(timeoutMs);
            sock.send(new DatagramPacket(wire, wire.length));

            byte[] buf = new byte[IpPacket.MAX_DNS_BYTES + 512];
            DatagramPacket in = new DatagramPacket(buf, buf.length);
            sock.receive(in);

            if (in.getLength() > IpPacket.MAX_DNS_BYTES) {
                throw new ForwardException(resolver + ": reply too large");
            }
            byte[] reply = DnsMessage.copy(buf, 0, in.getLength());
            DnsMessage msg = DnsMessage.parse(reply);
            if (msg == null) throw new ForwardException(resolver + ": unparseable reply");
            if (msg.id() != (queryId & 0xFFFF)) {
                throw new ForwardException(resolver + ": id mismatch " + msg.id() + " != " + queryId);
            }
            if (!msg.isResponse()) {
                throw new ForwardException(resolver + ": reply has QR clear");
            }
            if (msg.isTruncated()) {
                Reply tcp = retryOverTcp(addr, wire, queryId);
                if (tcp != null) return tcp;
                throw new ForwardException(resolver + ": truncated, TCP retry failed");
            }
            return new Reply(reply, false, addr.getHostAddress());
        } catch (SocketTimeoutException e) {
            throw new ForwardException(resolver + ": timeout");
        } catch (IOException e) {
            throw new ForwardException(resolver + ": " + e.getMessage());
        } finally {
            if (sock != null) release(sock);
        }
    }

    /**
     * Truncation retry over TCP. The 2-byte length prefix is mandatory and the
     * client will not retry for us, so this returns null on any failure and
     * the caller reports SERVFAIL rather than the truncated answer.
     */
    private Reply retryOverTcp(InetAddress addr, byte[] query, int queryId) {
        Socket s = null;
        try {
            s = new Socket();
            if (binder != null) binder.bind(s);
            s.connect(new java.net.InetSocketAddress(addr, IpPacket.PORT_DNS), TCP_TIMEOUT_MS);
            s.setSoTimeout(TCP_TIMEOUT_MS);

            OutputStream os = s.getOutputStream();
            os.write((query.length >>> 8) & 0xFF);
            os.write(query.length & 0xFF);
            os.write(query);
            os.flush();

            byte[] out = readTcpReply(s.getInputStream(), queryId);
            return out == null ? null : new Reply(out, true, addr.getHostAddress());
        } catch (IOException e) {
            return null;
        } finally {
            if (s != null) try { s.close(); } catch (IOException ignored) { }
        }
    }

    /** Read and validate one TCP frame before normalization can hide a bad ID or flags. */
    static byte[] readTcpReply(InputStream in, int queryId) throws IOException {
        int hi = in.read();
        if (hi < 0) return null;
        int lo = in.read();
        if (lo < 0) return null;
        int len = (hi << 8) | lo;
        if (len < DnsMessage.HEADER_LEN || len > IpPacket.MAX_DNS_BYTES) return null;

        byte[] body = new byte[len];
        readFully(in, body);
        DnsMessage msg = DnsMessage.parse(body);
        if (msg == null || msg.id() != (queryId & 0xFFFF)
                || !msg.isResponse() || msg.isTruncated()) return null;
        return DnsMessage.normalizeResponse(body, queryId, true);
    }

    private static void readFully(InputStream in, byte[] buf) throws IOException {
        int read = 0;
        while (read < buf.length) {
            int n = in.read(buf, read, buf.length - read);
            if (n < 0) throw new IOException("short read: " + read + "/" + buf.length);
            if (n == 0) {
                // Ensure progress even for streams that return zero on a bulk read.
                int next = in.read();
                if (next < 0) throw new IOException("short read: " + read + "/" + buf.length);
                buf[read++] = (byte) next;
            } else {
                read += n;
            }
        }
    }

    // ------------------------------------------------------------ socket pool

    /**
     * Capped pool of DatagramSockets. One socket per lookup is measurable
     * overhead at a hundred lookups a minute, and Android rate-limits
     * ephemeral port allocation, so reuse pays. Capped so a burst of queries
     * cannot exhaust the process's file descriptors.
     */
    private synchronized DatagramSocket acquire() throws IOException {
        if (closed) throw new IOException("forwarder closed");
        DatagramSocket s = pool.poll();
        return s != null ? s : new DatagramSocket();
    }

    private synchronized void release(DatagramSocket s) {
        if (closed) {
            if (s != null) s.close();
            return;
        }
        if (s == null || s.isClosed()) return;
        try {
            s.disconnect();
        } catch (RuntimeException ignored) { }
        if (!pool.offer(s)) s.close();
    }

    public boolean isClosed() { return closed; }

    public synchronized void close() {
        closed = true;
        DatagramSocket s;
        while ((s = pool.poll()) != null) {
            s.close();
        }
    }
}
