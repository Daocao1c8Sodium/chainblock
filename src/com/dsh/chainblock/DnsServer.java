package com.dsh.chainblock;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自建 DNS 服务器(在 VPN 隧道的用户态里跑)。
 *
 * 工作方式:
 *   - 系统把 DNS 查询发往 FAKE_DNS(10.111.222.1),我们给这个地址加了 /32 路由,
 *     所以查询会以 UDP 报文形式被送进 tun;
 *   - 我们解析出域名 -> 交给 DomainRules 判定;
 *   - 判定 BLOCK:直接回 NXDOMAIN(不开严格模式时, 也可选择回 0.0.0.0);
 *   - 判定 ALLOW:向真实上游 DNS 代查(用被 protect() 保护的 socket, 走底层网络, 不会绕回隧道),
 *               把应答原样回写;
 *   - 每见到一个被拦的域名, 就通知外层"解析它、并把它的 IP 加进屏蔽路由",形成"域名+IP"双层拦截。
 */
public final class DnsServer {

    private static final String TAG = "ChainBlock";

    public static final String FAKE_DNS = "10.111.222.1";

    /** 上游 DNS 候选(按顺序尝试) */
    private static final String[] UPSTREAM = {
            "223.5.5.5",        // 阿里 DNS(国内快)
            "119.29.29.29",     // 腾讯 DNS
            "1.1.1.1",
            "8.8.8.8",
    };

    public interface Listener {
        void onVerdict(String host, String type, boolean blocked);
        void onBlockedHost(String host);
        /** 放行的域名解析出了哪些地址(用于"解析后加黑洞路由"这一层) */
        void onResolved(String host, List<String> addresses);
        void onError(String msg);
    }

    private final Context ctx;
    private final DomainRules rules;
    private final Listener listener;
    private final int mtu;

    private DatagramSocket upstream;
    private Thread worker;
    private volatile boolean running;

    private final Set<String> seenBlocked = Collections.synchronizedSet(new HashSet<String>());
    private final AtomicLong queries = new AtomicLong();
    private final AtomicLong blockedCount = new AtomicLong();

    public DnsServer(Context ctx, DomainRules rules, Listener listener, int mtu) {
        this.ctx = ctx.getApplicationContext();
        this.rules = rules;
        this.listener = listener;
        this.mtu = mtu;
    }

    public long queryCount() { return queries.get(); }
    public long blockedCount() { return blockedCount.get(); }

    // ------------------------------------------------------------ 生命周期

    public void start(FileInputStream in, FileOutputStream out) {
        running = true;
        openUpstream();
        worker = new Thread(() -> runLoop(in, out), "dns-pump");
        worker.start();
    }

    public void stop() {
        running = false;
        if (upstream != null) upstream.close();
        if (worker != null) worker.interrupt();
    }

    private void openUpstream() {
        try {
            upstream = new DatagramSocket(null);
            upstream.setReuseAddress(true);
            upstream.bind(new InetSocketAddress(0));
            upstream.setSoTimeout(2500);
            // 关键: 必须 protect(), 否则本进程发出的 DNS 包会被自己建立的隧道吃掉,
            // 表现为"解析失败"(实测黑洞路由一直是 0 条就是这个原因)。
            boolean ok = FilterVpnService.protectSocket(upstream);
            if (!ok) {
                Network net = null;
                ConnectivityManager cm =
                        (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) net = cm.getActiveNetwork();
                if (net != null) net.bindSocket(upstream);
            }
        } catch (Exception e) {
            quiet("绑定上游 DNS socket 失败: " + e);
        }
    }

    // ------------------------------------------------------------ 主循环

    private void runLoop(FileInputStream in, FileOutputStream out) {
        byte[] buf = new byte[mtu];
        byte[] outbuf = new byte[mtu];
        while (running) {
            int n;
            try {
                n = in.read(buf);
            } catch (IOException e) {
                if (running) quiet("读 tun 失败: " + e);
                break;
            }
            if (n <= 0) continue;
            try {
                handleIpPacket(buf, n, outbuf, out);
            } catch (Exception e) {
                quiet("处理报文出错: " + e);
            }
        }
    }

    // ------------------------------------------------------------ 报文处理

    private void handleIpPacket(byte[] p, int len, byte[] out, FileOutputStream os) throws IOException {
        if (len < 28) return;
        int ver = (p[0] & 0xf0) >> 4;
        if (ver != 4) return;                       // 只处理 IPv4

        int ihl = (p[0] & 0x0f) * 4;
        if (ihl < 20 || ihl + 8 > len) return;
        int totalLen = ((p[2] & 0xff) << 8) | (p[3] & 0xff);
        if (totalLen < ihl + 8 || totalLen > len) totalLen = len;

        if ((p[9] & 0xff) != 17) return;             // 只要 UDP

        int srcIpOff = 12, dstIpOff = 16;
        int udp = ihl;
        int sport = ((p[udp] & 0xff) << 8) | (p[udp + 1] & 0xff);
        int dport = ((p[udp + 2] & 0xff) << 8) | (p[udp + 3] & 0xff);
        if (dport != 53) return;

        int dnsOff = udp + 8;
        int dnsLen = totalLen - dnsOff;
        if (dnsLen < 12) return;

        // 把 DNS 载荷单独切出来再解析(DnsCodec 从偏移 0 开始)
        byte[] dnsPacket = new byte[dnsLen];
        System.arraycopy(p, dnsOff, dnsPacket, 0, dnsLen);
        DnsCodec.Query q = DnsCodec.parse(dnsPacket, dnsLen);
        if (q == null) return;

        queries.incrementAndGet();
        DomainRules.Verdict v = rules.judge(q.qname);
        boolean block = (v == DomainRules.Verdict.BLOCK);

        byte[] dnsResp;
        if (block) {
            blockedCount.incrementAndGet();
            if (seenBlocked.add(q.qname)) listener.onBlockedHost(q.qname);
            listener.onVerdict(q.qname, typeName(q.qtype), true);
            if (q.qtype == DnsCodec.TYPE_AAAA) {
                // 回 :: 而不是空应答: 让对方拿到一个必定连不通的地址, 立刻失败,
                // 同时避免它改走真实 IPv6 地址(那是本方案的一个洞)
                List<byte[]> any = Collections.singletonList(DnsCodec.ipv6Any());
                dnsResp = DnsCodec.build(q, any, DnsCodec.RCODE_OK, 60, DnsCodec.TYPE_AAAA);
            } else {
                List<byte[]> zero = Collections.singletonList(new byte[]{0, 0, 0, 0});
                dnsResp = DnsCodec.build(q, zero, DnsCodec.RCODE_OK, 60, DnsCodec.TYPE_A);
            }
        } else {
            listener.onVerdict(q.qname, typeName(q.qtype), false);
            dnsResp = forward(dnsPacket, dnsLen);
            if (dnsResp != null) {
                // 汇报解析结果, 供外层把 IP 加进黑洞路由(IPv4 + IPv6 都收)
                List<String> addrs = new ArrayList<>();
                addrs.addAll(DnsCodec.extractRecords(dnsResp, dnsResp.length, DnsCodec.TYPE_A));
                addrs.addAll(DnsCodec.extractRecords(dnsResp, dnsResp.length, DnsCodec.TYPE_AAAA));
                if (!addrs.isEmpty()) listener.onResolved(q.qname, addrs);
            } else {
                dnsResp = DnsCodec.build(q, null, DnsCodec.RCODE_SERVFAIL, 1);
            }
        }
        if (dnsResp == null) return;

        int srcPort = dport;
        int dstPort = sport;
        int respLen = buildUdpIp(p, srcIpOff, dstIpOff, srcPort, dstPort, dnsResp, out);
        if (respLen > 0) os.write(out, 0, respLen);
    }

    // ------------------------------------------------------------ 上游代查

    private byte[] forward(byte[] query, int len) {
        if (upstream == null) return null;
        for (String server : UPSTREAM) {
            try {
                InetAddress addr = InetAddress.getByName(server);
                upstream.send(new DatagramPacket(query, len, addr, 53));
                byte[] rbuf = new byte[1500];
                DatagramPacket resp = new DatagramPacket(rbuf, rbuf.length);
                while (true) {
                    upstream.receive(resp);
                    if (resp.getLength() >= 2
                            && rbuf[0] == query[0] && rbuf[1] == query[1]) {
                        byte[] r = new byte[resp.getLength()];
                        System.arraycopy(rbuf, 0, r, 0, resp.getLength());
                        return r;
                    }
                }
            } catch (Exception e) {
                // 试下一个
            }
        }
        return null;
    }

    // ------------------------------------------------------------ 构造回包

    private static int buildUdpIp(byte[] orig, int srcIpOff, int dstIpOff,
                                  int sport, int dport, byte[] payload, byte[] out) {
        int ihl = 20;
        int total = ihl + 8 + payload.length;
        if (total > out.length) return 0;
        for (int i = 0; i < 20; i++) out[i] = 0;
        out[0] = 0x45;
        out[1] = 0;
        out[2] = (byte) ((total >> 8) & 0xff);
        out[3] = (byte) (total & 0xff);
        out[4] = 0; out[5] = 0;
        out[6] = 0x40; out[7] = 0;                     // DF
        out[8] = 64;                                   // TTL
        out[9] = 17;                                   // UDP
        out[10] = 0; out[11] = 0;
        // 交换源/目的 IP
        System.arraycopy(orig, dstIpOff, out, 12, 4);
        System.arraycopy(orig, srcIpOff, out, 16, 4);
        // IP 校验和
        int sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += ((out[i] & 0xff) << 8) | (out[i + 1] & 0xff);
        }
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        sum = ~sum & 0xffff;
        out[10] = (byte) ((sum >> 8) & 0xff);
        out[11] = (byte) (sum & 0xff);
        // UDP 头
        int u = 20;
        out[u] = (byte) ((sport >> 8) & 0xff);
        out[u + 1] = (byte) (sport & 0xff);
        out[u + 2] = (byte) ((dport >> 8) & 0xff);
        out[u + 3] = (byte) (dport & 0xff);
        int udpLen = 8 + payload.length;
        out[u + 4] = (byte) ((udpLen >> 8) & 0xff);
        out[u + 5] = (byte) (udpLen & 0xff);
        out[u + 6] = 0; out[u + 7] = 0;                // 校验和 0 = 不校验(IPv4 允许)
        System.arraycopy(payload, 0, out, u + 8, payload.length);
        return total;
    }

    private static String typeName(int t) {
        switch (t) {
            case DnsCodec.TYPE_A: return "A";
            case DnsCodec.TYPE_AAAA: return "AAAA";
            case DnsCodec.TYPE_HTTPS: return "HTTPS";
            default: return "T" + t;
        }
    }

    private void quiet(String msg) {
        if (listener != null) listener.onError(msg);
        else Log.w(TAG, msg);
    }

    // ------------------------------------------------------------ 供外层做 IP 层屏蔽

    /**
     * 用自建的原始 DNS 查询解析一个域名。
     *
     * 不用 InetAddress.getAllByName: 在 VPN 环境下它经常返回空(系统解析器
     * 依赖 DNS 服务器可达性, 实测返回 0 条), 这也是之前"IP 黑洞路由 0 条"的原因。
     */
    public static List<String> resolve(String host) {
        List<String> out = new java.util.ArrayList<>();
        for (String server : UPSTREAM) {
            DatagramSocket s = null;
            try {
                byte[] q = buildQuery(host, DnsCodec.TYPE_A);
                s = new DatagramSocket();
                // 同样必须 protect(), 否则解析包出不去(隧道里没人转发)
                FilterVpnService.protectSocket(s);
                s.setSoTimeout(2000);
                InetAddress addr = InetAddress.getByName(server);
                s.send(new DatagramPacket(q, q.length, addr, 53));
                byte[] rbuf = new byte[1500];
                DatagramPacket resp = new DatagramPacket(rbuf, rbuf.length);
                s.receive(resp);
                List<String> a = DnsCodec.extractRecords(rbuf, resp.getLength(), DnsCodec.TYPE_A);
                if (!a.isEmpty()) {
                    out.addAll(a);
                    break;
                }
            } catch (Exception ignored) {
            } finally {
                if (s != null) s.close();
            }
        }
        return out;
    }

    private static byte[] buildQuery(String host, int qtype) throws IOException {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream(64);
        int txid = (int) (System.nanoTime() & 0xffff);
        o.write((txid >> 8) & 0xff); o.write(txid & 0xff);
        o.write(0x01); o.write(0x00);          // RD
        o.write(0x00); o.write(0x01);          // QDCOUNT
        o.write(0x00); o.write(0x00);
        o.write(0x00); o.write(0x00);
        o.write(0x00); o.write(0x00);
        for (String label : host.split("\\.")) {
            byte[] b = label.getBytes("US-ASCII");
            if (b.length == 0 || b.length > 63) throw new IOException("bad label");
            o.write(b.length);
            o.write(b, 0, b.length);
        }
        o.write(0);
        o.write((qtype >> 8) & 0xff); o.write(qtype & 0xff);
        o.write(0x00); o.write(0x01);          // IN
        return o.toByteArray();
    }

    /** 把地址字符串转成 InetAddress; 失败返回 null。 */
    public static InetAddress toAddress(String ip) {
        try {
            return InetAddress.getByName(ip);
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unused")
    private static byte[] slice(ByteBuffer bb) {
        byte[] a = new byte[bb.remaining()];
        bb.get(a);
        return a;
    }
}
