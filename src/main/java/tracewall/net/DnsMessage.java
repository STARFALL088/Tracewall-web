/*
 * Copied from Tracewall @ e5c7c0d (github.com/STARFALL088/Tracewall, blocklist module).
 * Unchanged apart from this header.
 */
package tracewall.net;

/**
 * A DNS message in RFC 1035 wire format - just enough of it to be a firewall.
 *
 * Scope, deliberately narrow:
 * <ul>
 *   <li>Header (12 bytes) and the question section are parsed properly.</li>
 *   <li>Names are decoded with full compression-pointer support, including
 *       pointer chains, with a loop guard.</li>
 *   <li>EDNS0 OPT records and unknown RR types are tolerated and ignored -
 *       we never need to understand them, only to skip them correctly.</li>
 * </ul>
 *
 * The answers section is NOT parsed into objects. When we forward a query we
 * hand the resolver's response back almost byte-for-byte, and when we block we
 * synthesise our own. Parsing 4KB of A/AAAA/SOA records into objects on every
 * lookup would be pure waste, so it is not done.
 *
 * All methods are allocation-conscious: this runs on the hot path of a VPN
 * packet loop where every byte allocated matters.
 */
public final class DnsMessage {

    public static final int HEADER_LEN = 12;

    public static final int TYPE_A = 1;
    public static final int TYPE_NS = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA = 6;
    public static final int TYPE_PTR = 12;
    public static final int TYPE_MX = 15;
    public static final int TYPE_TXT = 16;
    public static final int TYPE_AAAA = 28;
    public static final int TYPE_SRV = 33;
    public static final int TYPE_OPT = 41;
    /** SVCB (RFC 9460) - the encrypted-DNS server-discovery record type. */
    public static final int TYPE_SVCB = 64;
    /** HTTPS (RFC 9460) - the HTTPS-specific variant of SVCB. */
    public static final int TYPE_HTTPS = 65;

    public static final int CLASS_IN = 1;

    public static final int RCODE_NOERROR = 0;
    public static final int RCODE_FORMERR = 1;
    public static final int RCODE_SERVFAIL = 2;
    public static final int RCODE_NXDOMAIN = 3;
    public static final int RCODE_NOTIMP = 4;
    public static final int RCODE_REFUSED = 5;

    /** Header + flags word. */
    public static final int FLAGS_QR = 0x8000; // query=0, response=1
    public static final int FLAGS_TC = 0x0200; // truncated
    public static final int FLAGS_RD = 0x0100; // recursion desired
    public static final int FLAGS_RA = 0x0080; // recursion available

    private final int id;
    private final int flags;
    private final int qdCount;
    private final int anCount;
    private final int nsCount;
    private final int arCount;
    private final String qName;
    private final int qType;
    private final int qClass;
    private final byte[] raw;

    private DnsMessage(
        int id,
        int flags,
        int qdCount,
        int anCount,
        int nsCount,
        int arCount,
        String qName,
        int qType,
        int qClass,
        byte[] raw
    ) {
        this.id = id;
        this.flags = flags;
        this.qdCount = qdCount;
        this.anCount = anCount;
        this.nsCount = nsCount;
        this.arCount = arCount;
        this.qName = qName;
        this.qType = qType;
        this.qClass = qClass;
        this.raw = raw;
    }

    public int id() {
        return id;
    }

    public int flags() {
        return flags;
    }

    public boolean isResponse() {
        return (flags & FLAGS_QR) != 0;
    }

    public boolean isTruncated() {
        return (flags & FLAGS_TC) != 0;
    }

    public int rCode() {
        return flags & 0x000F;
    }

    public int qdCount() {
        return qdCount;
    }

    public int anCount() {
        return anCount;
    }

    public int arCount() {
        return arCount;
    }

    public byte[] raw() {
        return raw;
    }

    /** The wire bytes of this packet, safe to write back to the TUN fd. */
    public byte[] toBytes() {
        return raw;
    }

    /**
     * The queried name, or {@code null} when this message has no question or
     * could not be parsed past the header. Never throws.
     */
    public String qName() {
        return qName;
    }

    public int qType() {
        return qType;
    }

    public int qClass() {
        return qClass;
    }

    /** True when this message is a plain recursive query for one question. */
    public boolean isSimpleQuery() {
        return !isResponse() && qdCount == 1 && qName != null;
    }

    // ---------------------------------------------------------------- parse

    /**
     * Parse a DNS message. Returns {@code null} on anything malformed rather
     * than throwing - a VPN is a hostile network position and every byte on
     * the wire is untrusted input. A packet we cannot parse is a packet we
     * drop, and dropping must not cost the caller an exception.
     */
    public static DnsMessage parse(byte[] buf, int off, int len) {
        if (buf == null || len < HEADER_LEN) return null;
        if (off < 0 || off > buf.length || len > buf.length - off) return null;
        int limit = off + len;

        int id = u16(buf, off);
        int flags = u16(buf, off + 2);
        int qd = u16(buf, off + 4);
        int an = u16(buf, off + 6);
        int ns = u16(buf, off + 8);
        int ar = u16(buf, off + 10);

        if (qd > 1 || qd == 0) {
            // qd == 0 is legal for some response shapes, and qd > 1 means we
            // have no single name to attribute or log. Both go to the slow
            // path in the service; parse the header only.
            return new DnsMessage(
                id,
                flags,
                qd,
                an,
                ns,
                ar,
                null,
                0,
                0,
                copy(buf, off, len)
            );
        }

        int p = off + HEADER_LEN;
        int[] end = new int[] { p };
        String name = readName(buf, off, limit, end);
        if (name == null) return null;
        if (limit - end[0] < 4) return null;
        int qtype = u16(buf, end[0]);
        int qclass = u16(buf, end[0] + 2);
        return new DnsMessage(
            id,
            flags,
            qd,
            an,
            ns,
            ar,
            name,
            qtype,
            qclass,
            copy(buf, off, len)
        );
    }

    public static DnsMessage parse(byte[] buf) {
        return buf == null ? null : parse(buf, 0, buf.length);
    }

    /**
     * Read a (possibly compressed) name within {@code [base, limit)}, starting
     * at {@code cursor[0]}. Compression offsets are relative to {@code base}.
     * Advances {@code cursor[0]} past the name as it appears at that position
     * - the pointer target bytes are never re-consumed by the caller.
     *
     * Returns {@code null} if the name runs off the end or the pointer chain
     * loops. Dot-decoded with escapes preserved as raw ASCII; this is a
     * firewall, not a resolver, so exotic IDN handling is left to the
     * upstream server that will actually answer the query.
     */
    static String readName(byte[] buf, int base, int limit, int[] cursor) {
        if (buf == null || cursor == null || cursor.length == 0
                || base < 0 || limit < base || limit > buf.length) return null;
        int p = cursor[0];
        StringBuilder sb = new StringBuilder(64);
        boolean jumped = false;
        int resume = p;
        int hops = 0;
        int wireLength = 1; // include the terminating root label

        while (true) {
            if (p < base || p >= limit) return null;
            int len = buf[p] & 0xFF;
            if ((len & 0xC0) == 0xC0) {
                // compression pointer
                if (limit - p < 2) return null;
                int target = ((len & 0x3F) << 8) | (buf[p + 1] & 0xFF);
                // Compare in message-relative coordinates before adding base.
                // Every hop must be backward, not just the first pointer.
                if (target >= limit - base || target >= p - base) return null;
                if (!jumped) {
                    resume = p + 2; // caller resumes after the ptr
                    jumped = true;
                }
                if (++hops > 64) return null; // pointer loop guard
                p = base + target;
                continue;
            }
            if ((len & 0xC0) != 0) return null; // reserved label type
            if (len == 0) {
                // end of name
                if (!jumped) resume = p + 1;
                cursor[0] = resume;
                return sb.length() == 0 ? "." : sb.toString();
            }
            if (len > 63) return null;
            if (len > limit - p - 1) return null;
            wireLength += 1 + len;
            if (wireLength > 255) return null;
            if (sb.length() > 0) sb.append('.');
            appendLabel(sb, buf, p + 1, len);
            p += 1 + len;
        }
    }

    /** Append one label, escaping the three bytes that are not plain text. */
    private static void appendLabel(
        StringBuilder sb,
        byte[] buf,
        int off,
        int len
    ) {
        for (int i = 0; i < len; i++) {
            int c = buf[off + i] & 0xFF;
            if (c == '.' || c == '\\') {
                sb.append('\\');
                sb.append((char) c);
            } else if (c < 0x21 || c > 0x7E) {
                sb.append('\\');
                sb.append((char) ('0' + c / 100));
                sb.append((char) ('0' + ((c / 10) % 10)));
                sb.append((char) ('0' + (c % 10)));
            } else {
                sb.append((char) c);
            }
        }
    }

    // ------------------------------------------------------------- builders

    /**
     * Build a response that answers {@code query} with a single A record
     * pointing at {@code address} (normally 0.0.0.0 - "this host does not
     * exist as far as you are concerned").
     *
     * Includes the query's question, opcode and RD bit, sets QR and RA, and
     * uses TTL 0 so the client does not cache a blocking answer. A null
     * address defaults to 0.0.0.0; non-IPv4 address lengths are rejected.
     */
    public static byte[] buildAResponse(DnsMessage query, byte[] address) {
        if (address != null && address.length != 4) return null;
        return buildSynthetic(query, TYPE_A, address == null ? new byte[4] : address);
    }

    /**
     * Build an empty NOERROR answer - correct for blocking AAAA, where
     * answering ::0 would be a type error rather than a denial, and for
     * opt-out A records that must resolve to nothing.
     */
    public static byte[] buildEmptyResponse(DnsMessage query) {
        return buildSynthetic(query, TYPE_A, null);
    }

    public static byte[] buildNxDomain(DnsMessage query) {
        return buildSynthetic(query, -1, null, RCODE_NXDOMAIN);
    }

    public static byte[] buildRefused(DnsMessage query) {
        return buildSynthetic(query, -1, null, RCODE_REFUSED);
    }

    public static byte[] buildServFail(DnsMessage query) {
        return buildSynthetic(query, -1, null, RCODE_SERVFAIL);
    }

    /** Build a synthetic answer with optional RDATA and TTL 0. */
    private static byte[] buildSynthetic(
        DnsMessage query,
        int rtype,
        byte[] rdata
    ) {
        return buildSynthetic(query, rtype, rdata, RCODE_NOERROR);
    }

    private static byte[] buildSynthetic(
        DnsMessage query,
        int rtype,
        byte[] rdata,
        int rcode
    ) {
        if (query == null || query.qName() == null) return null;
        byte[] name = encodeName(query.qName());
        if (name == null) return null;

        int rdlen = rdata == null ? 0 : rdata.length;
        int ancount = rdlen > 0 ? 1 : 0;
        // header(12) + question(name + TYPE(2) + CLASS(2))
        // + answer(name + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + rdata)
        int total =
            HEADER_LEN +
            name.length +
            4 +
            (ancount == 1 ? name.length + 10 + rdlen : 0);
        byte[] out = new byte[total];
        int p = 0;

        putU16(out, p, query.id());
        p += 2;
        // QR=1, copy RD from the query, set RA, preserve opcode, set rcode.
        int qflags = query.flags();
        // 0x7900 = opcode (0x7800) + RD (0x0100). Dropping RD makes some
        // stub resolvers treat the answer as unsolicited and ignore it.
        int flags = FLAGS_QR | (qflags & 0x7900) | FLAGS_RA | (rcode & 0x0F);
        putU16(out, p, flags);
        p += 2;
        putU16(out, p, 1);
        p += 2; // QDCOUNT
        putU16(out, p, ancount);
        p += 2; // ANCOUNT
        putU16(out, p, 0);
        p += 2; // NSCOUNT
        putU16(out, p, 0);
        p += 2; // ARCOUNT

        System.arraycopy(name, 0, out, p, name.length);
        p += name.length;
        putU16(out, p, query.qType());
        p += 2;
        putU16(out, p, query.qClass());
        p += 2;

        if (ancount == 1) {
            // Answer reuses the question's name (allowed, and avoids a pointer).
            System.arraycopy(name, 0, out, p, name.length);
            p += name.length;
            putU16(out, p, rtype);
            p += 2;
            putU16(out, p, CLASS_IN);
            p += 2;
            putU16(out, p, 0);
            p += 2; // TTL high  -> 0
            putU16(out, p, 0);
            p += 2; // TTL low   -> 0, do not cache
            putU16(out, p, rdlen);
            p += 2; // RDLENGTH
            System.arraycopy(rdata, 0, out, p, rdlen);
        }
        return out;
    }

    /**
     * Rewrite a resolver's response so it matches the query we sent:
     * transaction id corrected to ours, QR set, recursion-available set,
     * the truncated bit cleared (we may have completed it over TCP).
     *
     * Returning the resolver's bytes untouched except for those fields is
     * what makes every record type, DNSSEC AD bit and EDNS padding survive
     * untouched - we never have to understand a record to relay it.
     */
    public static byte[] normalizeResponse(
        byte[] upstream,
        int queryId,
        boolean wasTruncatedOverTcp
    ) {
        DnsMessage parsed = parse(upstream);
        if (parsed == null) return null;
        byte[] out = parsed.raw;
        putU16(out, 0, queryId & 0xFFFF);
        int flags = u16(out, 2) | FLAGS_QR | FLAGS_RA;
        if (wasTruncatedOverTcp) flags &= ~FLAGS_TC;
        putU16(out, 2, flags);
        return out;
    }

    /**
     * Encode a dotted name as length-prefixed labels. FQDN dot optional.
     * Accepts the escaped dots, backslashes and decimal octets emitted by readName.
     * Non-ASCII text must arrive punycoded rather than being replaced with '?'.
     */
    public static byte[] encodeName(String name) {
        if (name == null || name.isEmpty() || name.equals(".")) return new byte[] { 0 };
        if (name.length() > 255 * 4) return null; // even escaped names have a bounded size
        byte[] out = new byte[255];
        int labelStart = 0;
        int labelLength = 0;
        int p = 1;
        for (int i = 0; i < name.length(); i++) {
            int c = name.charAt(i);
            if (c == '.') {
                if (labelLength == 0) return null;
                out[labelStart] = (byte) labelLength;
                if (i == name.length() - 1) {
                    out[p++] = 0;
                    return copy(out, 0, p);
                }
                if (p >= out.length - 1) return null;
                labelStart = p++;
                labelLength = 0;
                continue;
            }
            if (c == '\\') {
                if (++i >= name.length()) return null;
                c = name.charAt(i);
                if (c >= '0' && c <= '9') {
                    if (name.length() - i < 3) return null;
                    int tens = name.charAt(i + 1) - '0';
                    int ones = name.charAt(i + 2) - '0';
                    if (tens < 0 || tens > 9 || ones < 0 || ones > 9) return null;
                    c = (c - '0') * 100 + tens * 10 + ones;
                    if (c > 255) return null;
                    i += 2;
                } else if (c > 0x7F) return null;
            } else if (c > 0x7F) return null;
            if (labelLength == 63 || p >= out.length - 1) return null;
            out[p++] = (byte) c;
            labelLength++;
        }
        if (labelLength == 0) return null;
        out[labelStart] = (byte) labelLength;
        out[p++] = 0;
        return copy(out, 0, p);
    }

    // -------------------------------------------------------------- helpers

    static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    static void putU16(byte[] b, int i, int v) {
        b[i] = (byte) ((v >>> 8) & 0xFF);
        b[i + 1] = (byte) (v & 0xFF);
    }

    static byte[] copy(byte[] b, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(b, off, out, 0, len);
        return out;
    }

    @Override
    public String toString() {
        return (
            "Dns{id=" +
            id() +
            " " +
            (isResponse() ? "resp" : "query") +
            " q=" +
            qName +
            " type=" +
            typeName(qType) +
            " rcode=" +
            rCode() +
            "}"
        );
    }

    public static String typeName(int t) {
        switch (t) {
            case TYPE_A:
                return "A";
            case TYPE_NS:
                return "NS";
            case TYPE_CNAME:
                return "CNAME";
            case TYPE_SOA:
                return "SOA";
            case TYPE_PTR:
                return "PTR";
            case TYPE_MX:
                return "MX";
            case TYPE_TXT:
                return "TXT";
            case TYPE_AAAA:
                return "AAAA";
            case TYPE_SRV:
                return "SRV";
            case TYPE_OPT:
                return "OPT";
            case TYPE_SVCB:
                return "SVCB";
            case TYPE_HTTPS:
                return "HTTPS";
            default:
                return "T" + t;
        }
    }
}
