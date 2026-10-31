package tracewall.desktop;

import tracewall.net.DnsMessage;

import java.io.ByteArrayOutputStream;
import java.util.concurrent.atomic.AtomicInteger;

/** Test doubles and wire helpers. No real DNS traffic leaves the process. */
final class DnsTestSupport {

    private DnsTestSupport() { }

    /** A forwarder that answers every A query with 93.184.216.34. */
    static final class FakeForwarder implements Forwarder {
        final AtomicInteger calls = new AtomicInteger();

        @Override
        public Reply forward(byte[] query, int queryId) {
            calls.incrementAndGet();
            DnsMessage parsed = DnsMessage.parse(query);
            byte[] response = DnsMessage.buildAResponse(parsed,
                    new byte[] {(byte) 93, (byte) 184, (byte) 216, 34});
            return new Reply(response, "fake");
        }
    }

    static byte[] query(String name, int type) {
        return query(0x1234, name, type);
    }

    static byte[] query(int id, String name, int type) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {
                (byte) (id >> 8), (byte) id,
                0x01, 0x00, // RD
                0x00, 0x01, // qdcount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        });
        out.writeBytes(DnsMessage.encodeName(name));
        out.writeBytes(new byte[] {0x00, (byte) type, 0x00, 0x01});
        return out.toByteArray();
    }

    /** The first A record's address, or null when the answer has none. */
    static byte[] firstA(byte[] message) {
        if (message == null || message.length < 12) return null;
        int anCount = u16(message, 6);
        if (anCount == 0) return null;
        int offset = 12;
        offset = skipName(message, offset); // question name
        offset += 4; // qtype + qclass
        if (offset >= message.length) return null;
        offset = skipName(message, offset); // answer name
        if (offset + 10 > message.length) return null;
        int type = u16(message, offset);
        offset += 2;
        offset += 2; // class
        offset += 4; // ttl
        int rdLength = u16(message, offset);
        offset += 2;
        if (type != 1 || rdLength != 4 || offset + 4 > message.length) return null;
        return new byte[] {message[offset], message[offset + 1], message[offset + 2], message[offset + 3]};
    }

    private static int skipName(byte[] message, int offset) {
        while (offset < message.length) {
            int length = message[offset] & 0xFF;
            if (length == 0) return offset + 1;
            if ((length & 0xC0) == 0xC0) return offset + 2;
            offset += 1 + length;
        }
        return offset;
    }

    static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }

    static String ip(byte[] address) {
        if (address == null) return "none";
        return (address[0] & 0xFF) + "." + (address[1] & 0xFF) + "."
                + (address[2] & 0xFF) + "." + (address[3] & 0xFF);
    }
}
