package tracewall.desktop;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The UDP listener. It owns exactly one job: read a datagram, hand a copy to a
 * bounded worker pool, never block on the workers.
 *
 * <p>When the queue is full the packet is dropped and counted. That is
 * deliberate: a DNS server that stalls its receive loop under load is worse
 * than one that drops, because the stalled one also stops answering everyone
 * else.</p>
 */
public final class DnsServer implements AutoCloseable {

    private static final int MAX_QUERY_BYTES = 4096;

    private final DatagramSocket socket;
    private final QueryHandler handler;
    private final Stats stats;
    private final List<Cidr> allowedClients;
    private final ExecutorService pool;
    private final AtomicBoolean running = new AtomicBoolean();
    private Thread receiver;

    public DnsServer(InetAddress bindAddress, int port, QueryHandler handler, Stats stats,
                     List<Cidr> allowedClients) throws SocketException {
        this.handler = handler;
        this.stats = stats;
        this.allowedClients = allowedClients == null ? List.of() : List.copyOf(allowedClients);
        this.socket = new DatagramSocket(null);
        this.socket.setReuseAddress(true);
        this.socket.bind(new InetSocketAddress(bindAddress, port));
        this.pool = new ThreadPoolExecutor(
                4, 8, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(1024),
                runnable -> {
                    Thread t = new Thread(runnable, "dns-worker");
                    t.setDaemon(true);
                    return t;
                },
                (runnable, executor) -> stats.dropped.incrementAndGet());
    }

    public int port() {
        return socket.getLocalPort();
    }

    public void start() {
        if (!running.compareAndSet(false, true)) return;
        receiver = new Thread(this::receiveLoop, "dns-receive");
        receiver.setDaemon(true);
        receiver.start();
    }

    private void receiveLoop() {
        byte[] buffer = new byte[MAX_QUERY_BYTES];
        while (running.get() && !socket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
            } catch (SocketException e) {
                if (!running.get() || socket.isClosed()) return;
                stats.dropped.incrementAndGet();
                continue;
            } catch (IOException e) {
                stats.dropped.incrementAndGet();
                continue;
            }

            InetSocketAddress client = (InetSocketAddress) packet.getSocketAddress();
            if (!clientAllowed(client.getAddress())) {
                stats.dropped.incrementAndGet();
                continue;
            }

            byte[] query = Arrays.copyOf(packet.getData(), packet.getLength());
            try {
                pool.execute(() -> answer(query, client));
            } catch (RejectedExecutionException e) {
                stats.dropped.incrementAndGet();
            }
        }
    }

    private void answer(byte[] query, InetSocketAddress client) {
        try {
            byte[] response = handler.handle(query, client);
            if (response == null) return;
            socket.send(new DatagramPacket(response, response.length, client));
        } catch (IOException e) {
            stats.servfail.incrementAndGet();
        } catch (RuntimeException e) {
            // A malformed packet must never kill a worker; the receive loop and
            // every other client keep going.
            stats.malformed.incrementAndGet();
        }
    }

    private boolean clientAllowed(InetAddress address) {
        if (allowedClients.isEmpty()) return true;
        for (Cidr cidr : allowedClients) {
            if (cidr.contains(address)) return true;
        }
        return false;
    }

    public boolean isRunning() {
        return running.get();
    }

    @Override
    public void close() {
        running.set(false);
        socket.close();
        pool.shutdownNow();
    }
}
