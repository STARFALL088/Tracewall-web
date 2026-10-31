package tracewall.desktop;

import java.net.Inet4Address;
import java.net.InetAddress;

/**
 * A minimal IPv4 CIDR block, enough for {@code --allow-client 192.168.1.0/24}.
 * IPv6 clients never match an IPv4 rule, which is the safe direction: they are
 * dropped rather than served.
 */
public final class Cidr {

    private final byte[] network;
    private final int prefix;

    private Cidr(byte[] network, int prefix) {
        this.network = network;
        this.prefix = prefix;
    }

    /** Accepts {@code a.b.c.d} (a /32) or {@code a.b.c.d/n}. */
    public static Cidr parse(String text) {
        if (text == null || text.isBlank()) throw new IllegalArgumentException("empty CIDR");
        String s = text.trim();
        int slash = s.indexOf('/');
        String address = slash < 0 ? s : s.substring(0, slash);
        int prefix = slash < 0 ? 32 : Integer.parseInt(s.substring(slash + 1).trim());
        if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("bad prefix: " + text);
        byte[] bytes = parseIpv4(address);
        if (bytes == null) throw new IllegalArgumentException("not an IPv4 address: " + text);
        long value = toLong(bytes);
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return new Cidr(fromLong(value & mask), prefix);
    }

    public boolean contains(InetAddress address) {
        if (!(address instanceof Inet4Address)) return false;
        byte[] bytes = address.getAddress();
        if (bytes.length != 4) return false;
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return (toLong(bytes) & mask) == toLong(network);
    }

    @Override
    public String toString() {
        return (network[0] & 0xFF) + "." + (network[1] & 0xFF) + "." + (network[2] & 0xFF)
                + "." + (network[3] & 0xFF) + "/" + prefix;
    }

    private static byte[] parseIpv4(String text) {
        String[] parts = text.split("\\.");
        if (parts.length != 4) return null;
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            try {
                int v = Integer.parseInt(parts[i]);
                if (v < 0 || v > 255) return null;
                out[i] = (byte) v;
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return out;
    }

    private static long toLong(byte[] bytes) {
        return ((long) (bytes[0] & 0xFF) << 24) | ((long) (bytes[1] & 0xFF) << 16)
                | ((long) (bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);
    }

    private static byte[] fromLong(long value) {
        return new byte[] {
                (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
        };
    }
}
