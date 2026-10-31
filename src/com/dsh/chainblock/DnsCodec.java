package com.dsh.chainblock;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 极简 DNS 报文编解码。
 * 只处理我们需要的部分:解析 QNAME / QTYPE,构造 A、AAAA、NXDOMAIN、SERVFAIL 应答。
 */
public final class DnsCodec {

    public static final int TYPE_A = 1;
    public static final int TYPE_AAAA = 28;
    public static final int TYPE_HTTPS = 65;

    public static final int RCODE_OK = 0;
    public static final int RCODE_SERVFAIL = 2;
    public static final int RCODE_NXDOMAIN = 3;
    public static final int RCODE_NOTIMP = 4;

    private DnsCodec() {}

    public static final class Query {
        public byte[] packet;
        public String qname;      // 小写, 无尾点
        public int qtype;
        public int qclass;
        public int questionEnd;   // question 段结束的偏移
        public int txid;
        public boolean rd;
    }

    /** 解析 DNS 查询。无法解析时返回 null。 */
    public static Query parse(byte[] p, int len) {
        if (p == null || len < 12) return null;
        Query q = new Query();
        q.packet = p;
        int flags = ((p[2] & 0xff) << 8) | (p[3] & 0xff);
        if ((flags & 0x8000) != 0) return null;          // 是应答不是查询
        q.rd = (flags & 0x0100) != 0;
        q.txid = ((p[0] & 0xff) << 8) | (p[1] & 0xff);
        int qdcount = ((p[4] & 0xff) << 8) | (p[5] & 0xff);
        if (qdcount < 1) return null;

        int off = 12;
        StringBuilder sb = new StringBuilder();
        int guard = 0;
        while (off < len && guard++ < 128) {
            int l = p[off] & 0xff;
            if (l == 0) { off++; break; }
            if ((l & 0xc0) != 0) return null;             // 查询里的 QNAME 不该有压缩指针
            if (off + 1 + l > len) return null;
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(p, off + 1, l, StandardCharsets.US_ASCII));
            off += 1 + l;
        }
        if (off + 4 > len) return null;
        q.qtype = ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
        q.qclass = ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
        q.questionEnd = off + 4;
        q.qname = sb.toString().toLowerCase();
        return q;
    }

    private static void putHeader(ByteArrayOutputStream o, int txid, int flags, int qd, int an) {
        o.write((txid >> 8) & 0xff); o.write(txid & 0xff);
        o.write((flags >> 8) & 0xff); o.write(flags & 0xff);
        o.write((qd >> 8) & 0xff);   o.write(qd & 0xff);
        o.write((an >> 8) & 0xff);   o.write(an & 0xff);
        o.write(0); o.write(0);      // ns
        o.write(0); o.write(0);      // ar
    }

    /**
     * 构造应答。
     * @param ips 要返回的地址记录; 每个 4 字节 = A, 16 字节 = AAAA。传空数组表示 NOERROR 无记录。
     * @param qtype 必须与查询一致(A / AAAA), 否则记录类型会对不上。
     * @param rcode 响应码; 非 0 时忽略 ips
     */
    public static byte[] build(Query q, List<byte[]> ips, int rcode, int ttl, int qtype) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(64);
        int flags = 0x8000;                                   // QR
        if (q.rd) flags |= 0x0100;                            // 保留 RD
        flags |= 0x0080;                                      // RA
        flags |= (rcode & 0x0f);
        int an = (rcode == RCODE_OK && ips != null) ? ips.size() : 0;
        putHeader(o, q.txid, flags, 1, an);
        // question 段原样回抄
        o.write(q.packet, 12, q.questionEnd - 12);
        int rtype = (qtype == TYPE_AAAA) ? TYPE_AAAA : TYPE_A;
        if (an > 0) {
            for (byte[] ip : ips) {
                o.write(0xc0); o.write(0x0c);                 // 指向 question 里的名字
                o.write(0x00); o.write(rtype);
                o.write(0x00); o.write(0x01);                 // IN
                o.write((ttl >> 24) & 0xff); o.write((ttl >> 16) & 0xff);
                o.write((ttl >> 8) & 0xff);  o.write(ttl & 0xff);
                o.write((ip.length >> 8) & 0xff); o.write(ip.length & 0xff);
                o.write(ip, 0, ip.length);
            }
        }
        return o.toByteArray();
    }

    /** 兼容旧调用: 默认按 A 记录构造 */
    public static byte[] build(Query q, List<byte[]> ips, int rcode, int ttl) {
        return build(q, ips, rcode, ttl, TYPE_A);
    }

    /** :: 的 16 字节形式 */
    public static byte[] ipv6Any() {
        return new byte[16];
    }

    /** 把点分十进制转成 4 字节; 失败返回 null。 */
    public static byte[] ipv4(String s) {
        String[] parts = s.split("\\.");
        if (parts.length != 4) return null;
        byte[] r = new byte[4];
        for (int i = 0; i < 4; i++) {
            try {
                int v = Integer.parseInt(parts[i]);
                if (v < 0 || v > 255) return null;
                r[i] = (byte) v;
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return r;
    }

    /** 从应答里提取指定类型的地址记录(用于"解析后加黑洞路由"这一层)。 */
    public static List<String> extractRecords(byte[] p, int len, int wantType) {
        List<String> out = new ArrayList<>();
        if (p == null || len < 12) return out;
        int ancount = ((p[6] & 0xff) << 8) | (p[7] & 0xff);
        if (ancount == 0) return out;
        // 跳过 question
        int off = 12;
        int qd = ((p[4] & 0xff) << 8) | (p[5] & 0xff);
        for (int i = 0; i < qd && off < len; i++) {
            while (off < len) {
                int l = p[off] & 0xff;
                if (l == 0) { off++; break; }
                if ((l & 0xc0) != 0) { off += 2; break; }
                off += 1 + l;
            }
            off += 4;
        }
        for (int i = 0; i < ancount && off + 12 <= len; i++) {
            if ((p[off] & 0xc0) == 0xc0) off += 2;
            else {
                while (off < len && p[off] != 0) off += 1 + (p[off] & 0xff);
                off++;
            }
            if (off + 10 > len) break;
            int type = ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
            int rdlen = ((p[off + 8] & 0xff) << 8) | (p[off + 9] & 0xff);
            int rdstart = off + 10;
            if (type == wantType && rdstart + rdlen <= len) {
                if (wantType == TYPE_A && rdlen == 4) {
                    out.add((p[rdstart] & 0xff) + "." + (p[rdstart + 1] & 0xff) + "."
                            + (p[rdstart + 2] & 0xff) + "." + (p[rdstart + 3] & 0xff));
                } else if (wantType == TYPE_AAAA && rdlen == 16) {
                    out.add(formatIpv6(p, rdstart));
                }
            }
            off = rdstart + rdlen;
        }
        return out;
    }

    /** 把 16 字节压缩成标准 IPv6 文本(不做 :: 压缩, 直接足量写, 便于 addRoute 解析)。 */
    public static String formatIpv6(byte[] p, int off) {
        StringBuilder sb = new StringBuilder(40);
        for (int i = 0; i < 8; i++) {
            int v = ((p[off + i * 2] & 0xff) << 8) | (p[off + i * 2 + 1] & 0xff);
            if (i > 0) sb.append(':');
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }
}
