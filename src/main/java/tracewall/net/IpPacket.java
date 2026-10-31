/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.net;

import java.util.Arrays;

/**
 * Just enough IPv4 + IPv6 + UDP to move a DNS query off the TUN, forward it,
 * and put a response back on the wire with correct checksums.
 *
 * Everything here is untrusted input. Every length is validated against the
 * actual buffer before it is used as an index, and no method throws for
 * malformed input - they return null and the caller drops the packet.
 *
 * Checksums are computed for real rather than trusted: a TUN device delivers
 * packets with the checksum already validated by nothing at all, and if we
 * write back a bad UDP checksum the client silently discards our answer and
 * the app looks broken. Getting this wrong is invisible in testing and very
 * visible in a demo.
 */
public final class IpPacket {

    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;

    public static final int PROTO_UDP = 17;
    public static final int PROTO_TCP = 6;

    public static final int PORT_DNS = 53;

    /** Largest DNS message we accept; anything larger is malformed or abuse. */
    public static final int MAX_DNS_BYTES = 4096;

    /** Largest packet we will read from the TUN in one go. */
    public static final int TUN_MTU = 1500;

    public static final int IPV4_HEADER_LEN = 20;
    public static final int IPV6_HEADER_LEN = 40;
    public static final int UDP_HEADER_LEN = 8;

    private final int version;          // 4 or 6
    private final int srcIp;            // IPv4: raw 4 bytes as int; IPv6: low 64 bits
    private final int dstIp;
    private final byte[] srcIpBytes;    // 4 or 16 bytes, always
    private final byte[] dstIpBytes;
    private final int protocol;
    private final int srcPort;
    private final int dstPort;
    private final byte[] payload;       // the UDP payload
    private final int identification;
    private final int ttl;
    private final int ipv6PayloadLength;
    private final int trafficClass;
    private final int flowLabel;

    private IpPacket(int version, byte[] srcIp, byte[] dstIp, int protocol,
                     int srcPort, int dstPort, byte[] payload, int identification,
                     int ttl, int ipv6PayloadLength, int trafficClass, int flowLabel) {
        this.version = version;
        this.srcIpBytes = srcIp;
        this.dstIpBytes = dstIp;
        this.srcIp = ipToInt(srcIp);
        this.dstIp = ipToInt(dstIp);
        this.protocol = protocol;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.payload = payload;
        this.identification = identification;
        this.ttl = ttl;
        this.ipv6PayloadLength = ipv6PayloadLength;
        this.trafficClass = trafficClass;
        this.flowLabel = flowLabel;
    }

    public int version() { return version; }
    public boolean isV4() { return version == 4; }
    public int protocol() { return protocol; }
    public boolean isUdp() { return protocol == PROTO_UDP; }
    public int srcPort() { return srcPort; }
    public int dstPort() { return dstPort; }
    public boolean isDnsQuery() {
        return protocol == PROTO_UDP
                && (srcPort == PORT_DNS || dstPort == PORT_DNS);
    }
    public byte[] payload() { return payload; }
    public byte[] srcIpBytes() { return srcIpBytes; }
    public byte[] dstIpBytes() { return dstIpBytes; }
    public String srcIpText() { return toText(srcIpBytes); }
    public String dstIpText() { return toText(dstIpBytes); }

    /** Only meaningful for IPv4; returns 0 for IPv6. */
    public int identification() { return version == 4 ? identification : 0; }

    // ---------------------------------------------------------------- parse

    /**
     * Parse an IP packet. Handles a raw IP packet with no link-layer header -
     * which is what a TUN device in {@code IFF_NO_PI} mode delivers. Returns
     * null for anything that is not a UDP packet we can address, including
     * TCP: TCP on port 53 is rare (fallback after truncation) and is dropped
     * rather than half-supported, because a half-supported TCP path that
     * silently drops is worse than an honest gap.
     */
    public static IpPacket parse(byte[] buf, int off, int len) {
        if (buf == null || len < 1) return null;
        if (off < 0 || off > buf.length || len > buf.length - off) return null;
        int version = (buf[off] & 0xF0) >>> 4;
        if (version == 4) return parseV4(buf, off, len);
        if (version == 6) return parseV6(buf, off, len);
        return null;
    }

    public static IpPacket parse(byte[] buf) {
        return buf == null ? null : parse(buf, 0, buf.length);
    }

    private static IpPacket parseV4(byte[] buf, int off, int len) {
        if (len < IPV4_HEADER_LEN) return null;
        int p = off;
        int ihl = (buf[p] & 0x0F) * 4;
        if (ihl < IPV4_HEADER_LEN || ihl > len) return null;

        int totalLen = DnsMessage.u16(buf, p + 2);
        // A total length of 0 is what some TUN writers emit when the kernel
        // fills it in later. Nonzero lengths must fit the supplied slice;
        // clamping them would turn a truncated datagram into a different one.
        if (totalLen == 0) totalLen = len;
        if (totalLen > len || totalLen < ihl + UDP_HEADER_LEN) return null;

        int ident = DnsMessage.u16(buf, p + 4);
        int flagsFrag = DnsMessage.u16(buf, p + 6);
        // Fragmented packets must be reassembled before anything else; we do
        // not reassemble, and a fragment is not something to forward blindly.
        if ((flagsFrag & 0x2000) != 0 || (flagsFrag & 0x1FFF) != 0) return null;

        int ttl = buf[p + 8] & 0xFF;
        int proto = buf[p + 9] & 0xFF;
        if (proto != PROTO_UDP) return null;

        byte[] src = Arrays.copyOfRange(buf, p + 12, p + 16);
        byte[] dst = Arrays.copyOfRange(buf, p + 16, p + 20);

        int u = p + ihl;
        int sport = DnsMessage.u16(buf, u);
        int dport = DnsMessage.u16(buf, u + 2);
        int udpLen = DnsMessage.u16(buf, u + 4);
        if (udpLen < UDP_HEADER_LEN || udpLen > totalLen - ihl) return null;

        byte[] body = Arrays.copyOfRange(buf, u + UDP_HEADER_LEN, u + udpLen);
        return new IpPacket(4, src, dst, proto, sport, dport, body, ident, ttl, 0, 0, 0);
    }

    private static IpPacket parseV6(byte[] buf, int off, int len) {
        if (len < IPV6_HEADER_LEN) return null;
        int p = off;
        int trafficClass = ((buf[p] & 0x0F) << 4) | ((buf[p + 1] & 0xF0) >>> 4);
        int flowLabel = ((buf[p + 1] & 0x0F) << 16)
                | (DnsMessage.u16(buf, p + 2) & 0xFFFF);
        int payloadLen = DnsMessage.u16(buf, p + 4);
        int next = buf[p + 6] & 0xFF;
        int hopLimit = buf[p + 7] & 0xFF;
        if (payloadLen == 0) payloadLen = len - IPV6_HEADER_LEN;
        if (payloadLen < UDP_HEADER_LEN || payloadLen > len - IPV6_HEADER_LEN) return null;
        if (next != PROTO_UDP) return null;   // no extension-header walk

        byte[] src = Arrays.copyOfRange(buf, p + 8, p + 24);
        byte[] dst = Arrays.copyOfRange(buf, p + 24, p + 40);

        int u = p + IPV6_HEADER_LEN;
        int sport = DnsMessage.u16(buf, u);
        int dport = DnsMessage.u16(buf, u + 2);
        int udpLen = DnsMessage.u16(buf, u + 4);
        if (udpLen < UDP_HEADER_LEN || udpLen > payloadLen) return null;

        byte[] body = Arrays.copyOfRange(buf, u + UDP_HEADER_LEN, u + udpLen);
        return new IpPacket(6, src, dst, PROTO_UDP, sport, dport, body, 0,
                hopLimit, payloadLen, trafficClass, flowLabel);
    }

    // ---------------------------------------------------------------- build

    /**
     * Build a fresh packet carrying {@code payload} from {@code src} to
     * {@code dst}, with a new IPv4 identification and a correct IPv4 header
     * checksum and UDP checksum.
     *
     * Checksum rules that matter here: IPv6 requires a UDP pseudo-header
     * checksum, and an IPv4 UDP checksum of zero means "not computed" so a
     * real zero is transmitted as 0xFFFF.
     */
    public byte[] buildResponse(byte[] src, byte[] dst, byte[] newPayload, int newIdentification) {
        int addressLength = isV4() ? 4 : 16;
        int headerLength = isV4() ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
        if (src == null || dst == null || src.length != addressLength
                || dst.length != addressLength || newPayload == null) return null;
        if (newPayload.length > 65535 - headerLength - UDP_HEADER_LEN) return null;
        int udpLen = UDP_HEADER_LEN + newPayload.length;
        int total = headerLength + udpLen;
        byte[] out = new byte[total];

        if (isV4()) {
            int p = 0;
            out[p] = 0x45;                                  // v4, 5 words of header
            out[p + 1] = 0;                                // DSCP/ECN
            DnsMessage.putU16(out, p + 2, total);
            DnsMessage.putU16(out, p + 4, newIdentification & 0xFFFF);
            DnsMessage.putU16(out, p + 6, 0x4000);          // DF
            out[p + 8] = (byte) Math.max(ttl(), 64);       // generous TTL so
            out[p + 9] = (byte) PROTO_UDP;                 // it survives a
            System.arraycopy(src, 0, out, p + 12, 4);      // flaky hotspot
            System.arraycopy(dst, 0, out, p + 16, 4);
            int sum = checksum(out, p, IPV4_HEADER_LEN, 0);
            DnsMessage.putU16(out, p + 10, sum);
        } else {
            int p = 0;
            out[p] = (byte) (((6 << 4) | ((trafficClass() >> 4) & 0x0F)));
            out[p + 1] = (byte) (((trafficClass() & 0x0F) << 4) | ((flowLabel() >> 16) & 0x0F));
            DnsMessage.putU16(out, p + 2, flowLabel() & 0xFFFF);
            DnsMessage.putU16(out, p + 4, udpLen);
            out[p + 6] = (byte) PROTO_UDP;
            out[p + 7] = (byte) Math.max(ttl(), 64);
            System.arraycopy(src, 0, out, p + 8, 16);
            System.arraycopy(dst, 0, out, p + 24, 16);
        }

        int u = isV4() ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
        DnsMessage.putU16(out, u, dstPort());               // reversed
        DnsMessage.putU16(out, u + 2, srcPort());
        DnsMessage.putU16(out, u + 4, udpLen);
        DnsMessage.putU16(out, u + 6, 0);                   // placeholder
        System.arraycopy(newPayload, 0, out, u + UDP_HEADER_LEN, newPayload.length);

        int sum = udpChecksum(out, src, dst);
        if (sum == 0) sum = 0xFFFF;
        DnsMessage.putU16(out, u + 6, sum);
        return out;
    }

    /**
     * One's-complement sum over a region, with pseudo-header included for UDP.
     * Returns the value already folded and ready to write into the header.
     * Returns -1 for an invalid buffer slice (outside the 16-bit checksum range).
     */
    public static int checksum(byte[] buf, int off, int len, int seed) {
        if (buf == null || off < 0 || len < 0 || off > buf.length
                || len > buf.length - off) return -1;
        long sum = seed & 0xFFFFFFFFL;
        int i = 0;
        for (; i + 1 < len; i += 2) {
            sum += ((buf[off + i] & 0xFF) << 8) | (buf[off + i + 1] & 0xFF);
        }
        if (i < len) sum += (buf[off + i] & 0xFF) << 8;      // odd trailing byte
        while ((sum >>> 16) != 0) sum = (sum & 0xFFFF) + (sum >>> 16);
        return (int) (~sum) & 0xFFFF;
    }

    private int udpChecksum(byte[] buf, byte[] src, byte[] dst) {
        int u = isV4() ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
        int len = buf.length - u;
        int sum = 0;
        // Both pseudo-headers reduce to the same 16-bit words: the addresses,
        // protocol 17 and the UDP length. IPv4 puts a zero byte before the
        // protocol and IPv6 pads the length to 32 bits, but zeros contribute
        // nothing to a one's-complement sum, so one loop covers both.
        if (src == null || dst == null || src.length != dst.length) {
            throw new IllegalArgumentException("pseudo-header needs both addresses");
        }
        for (int i = 0; i < src.length; i += 2) {
            sum += ((src[i] & 0xFF) << 8) | (src[i + 1] & 0xFF);
            sum += ((dst[i] & 0xFF) << 8) | (dst[i + 1] & 0xFF);
        }
        sum += PROTO_UDP;
        sum += len;
        int c = checksum(buf, u, len, sum);
        return (c == 0) ? 0xFFFF : c;
    }

    // -------------------------------------------------------------- helpers

    static int ipToInt(byte[] ip) {
        if (ip == null || ip.length != 4) return 0;
        return ((ip[0] & 0xFF) << 24) | ((ip[1] & 0xFF) << 16)
                | ((ip[2] & 0xFF) << 8) | (ip[3] & 0xFF);
    }

    int trafficClass() { return trafficClass; }
    int flowLabel() { return flowLabel; }
    int ttl() { return ttl; }

    public static String toText(byte[] ip) {
        if (ip == null) return "?";
        StringBuilder sb = new StringBuilder();
        if (ip.length == 4) {
            for (int i = 0; i < 4; i++) {
                if (i > 0) sb.append('.');
                sb.append(ip[i] & 0xFF);
            }
            return sb.toString();
        }
        if (ip.length == 16) {
            int[] g = new int[8];
            for (int i = 0; i < 8; i++) {
                g[i] = ((ip[i * 2] & 0xFF) << 8) | (ip[i * 2 + 1] & 0xFF);
            }
            for (int i = 0; i < 8; i++) {
                if (i > 0) sb.append(':');
                sb.append(Integer.toHexString(g[i]));
            }
            return sb.toString();
        }
        return "?";
    }

    /** The set of ports a DNS client uses on the device side: 53 only, in practice. */
    public boolean isFromClientDnsPort() { return srcPort == PORT_DNS; }

    @Override public String toString() {
        return "Ip{" + srcIpText() + ":" + srcPort + " -> " + dstIpText() + ":" + dstPort
                + " v" + version + " len=" + payload.length + "}";
    }
}
