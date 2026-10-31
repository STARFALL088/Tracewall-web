package tracewall.desktop;

import org.junit.jupiter.api.Test;
import tracewall.blocklist.DomainSet;
import tracewall.net.DnsMessage;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DnsServerTest {

    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    private static DnsServer server(List<Cidr> allowedClients) throws Exception {
        Map<String, DomainSet> categories = new TreeMap<>();
        categories.put("adult", DomainSet.of(List.of("xvideos.com")));
        PolicyHolder policy = new PolicyHolder(new DomainSet(), categories, new DomainSet(), null);
        QueryHandler handler = new QueryHandler(policy, new DnsTestSupport.FakeForwarder(),
                null, 0.8, new Stats(), new EventLog(50));
        DnsServer server = new DnsServer(InetAddress.getByName("127.0.0.1"), 0, handler,
                new Stats(), allowedClients);
        server.start();
        return server;
    }

    @Test
    void answersOnLoopback() throws Exception {
        try (DnsServer server = server(List.of())) {
            byte[] response = exchange(server.port(),
                    DnsTestSupport.query("xvideos.com", DnsMessage.TYPE_A), 2000);
            assertNotNull(response);
            assertArrayEquals(new byte[] {0, 0, 0, 0}, DnsTestSupport.firstA(response));
        }
    }

    @Test
    void survivesGarbageInput() throws Exception {
        try (DnsServer server = server(List.of())) {
            byte[] garbage = new byte[64];
            new Random(7).nextBytes(garbage);
            garbage[4] = 0x7F; // absurd qdcount: must not be answered
            DatagramSocket socket = new DatagramSocket();
            socket.setSoTimeout(400);
            socket.send(new DatagramPacket(garbage, garbage.length,
                    InetAddress.getByName("127.0.0.1"), server.port()));
            assertThrows(SocketTimeoutException.class, () -> {
                byte[] buffer = new byte[512];
                socket.receive(new DatagramPacket(buffer, buffer.length));
            });
            socket.close();

            // The receive loop and the worker pool are still alive.
            byte[] response = exchange(server.port(),
                    DnsTestSupport.query("xvideos.com", DnsMessage.TYPE_A), 2000);
            assertNotNull(response, "server stopped answering after garbage input");
            assertArrayEquals(new byte[] {0, 0, 0, 0}, DnsTestSupport.firstA(response));
        }
    }

    @Test
    void clientsOutsideTheAllowlistAreDroppedSilently() throws Exception {
        try (DnsServer server = server(List.of(Cidr.parse("10.0.0.0/8")))) {
            assertThrows(SocketTimeoutException.class, () -> exchange(server.port(),
                    DnsTestSupport.query("xvideos.com", DnsMessage.TYPE_A), 400));
        }
    }

    @Test
    void cidrMatchesOnlyItsOwnRange() throws Exception {
        Cidr cidr = Cidr.parse("192.168.1.0/24");
        assertTrue(cidr.contains(InetAddress.getByName("192.168.1.55")));
        assertTrue(!cidr.contains(InetAddress.getByName("192.168.2.55")));
        assertTrue(!cidr.contains(InetAddress.getByName("127.0.0.1")));
        assertTrue(Cidr.parse("127.0.0.1").contains(InetAddress.getByName("127.0.0.1")));
    }

    private static byte[] exchange(int port, byte[] query, int timeoutMs) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            socket.send(new DatagramPacket(query, query.length,
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port)));
            byte[] buffer = new byte[2048];
            DatagramPacket response = new DatagramPacket(buffer, buffer.length);
            socket.receive(response);
            byte[] out = new byte[response.getLength()];
            System.arraycopy(response.getData(), 0, out, 0, response.getLength());
            return out;
        }
    }
}
