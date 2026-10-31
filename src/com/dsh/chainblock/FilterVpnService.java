package com.dsh.chainblock;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 本地 VPN 服务。只做拦截, 不转发到任何远端服务器。
 *
 * 隧道设计(重要):
 *   本应用 *不* 添加全网默认路由, 而是只添加 3 条路由:
 *     1) 10.111.222.1/32        自建 DNS 服务器的地址 -> 所有 DNS 查询走隧道
 *     2) 已知广告服务器的 IP/32   -> 即使对方用 IP 直连也会被黑洞
 *     3) 0.0.0.1/32             （占位, 保证隧道至少有一条非 DNS 路由）
 *   其余流量完全不走隧道, 因此不会拖慢网速、也不会影响跑步/定位/成绩上传。
 *
 * 判定流程:
 *   系统解析器 -> 10.111.222.1:53 -> 进隧道 -> DnsServer 解析域名
 *     -> DomainRules 判定 -> 放行则代查上游返回真实 IP / 拦截则回 0.0.0.0
 */
public final class FilterVpnService extends VpnService {

    private static final String TAG = "ChainBlock";
    private static final String CHANNEL = "chainblock";
    private static final int NOTIF_ID = 0x4b1d;

    public static final String ACTION_START = "com.dsh.chainblock.START";
    public static final String ACTION_STOP = "com.dsh.chainblock.STOP";

    /** 自建 DNS 地址与隧道内本机地址 */
    private static final String TUN_ADDR = "10.111.222.2";
    private static final int PREFIX = 32;
    private static final int MTU = 1500;

    // IP 层黑洞路由表已改为从 assets/ipblock.txt 读取(见 loadIpBlockAsset)。
    // 原因: 在手机端现解析每次都是"解析失败"(VPN 进程发出的 DNS 包出不去),
    //       而且即使解析成功也会被系统 DNS 缓存绕过。

    private static volatile FilterVpnService instance;

    private ParcelFileDescriptor tun;
    private Thread pump;
    private volatile boolean running;
    private DomainRules rules;
    private DnsServer dns;

    /**
     * 动态解析黑名单里的所有域名, 把解析到的 IP 逐一加进黑洞路由。
     *
     * 依赖 addDisallowedApplication: 本应用不在自己的隧道里, 所以这里发起的
     * DNS 查询走的是真实网络, 能正常拿到结果。
     *
     * 每次启动 / 每次「刷新」都会重跑一遍 —— 这就是应对 CDN IP 轮换的机制。
     */
    private void resolveAndBlackhole(int baseRoutes) {
        try {
            Thread.sleep(120);   // 只留极小等待, 让路由先下发
            Builder b = liveBuilder;
            if (b == null) {
                FileLog.w("dynamic-resolve: liveBuilder 为空, 跳过");
                return;
            }
            java.util.List<String> hosts = new ArrayList<>();
            try (java.io.InputStream is = getAssets().open("blocklist.txt");
                 java.io.BufferedReader br = new java.io.BufferedReader(
                         new java.io.InputStreamReader(is, "UTF-8"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    if (!line.contains(".")) continue;
                    if (line.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+.*")) continue;  // 跳过 IP 行
                    hosts.add(line.toLowerCase());
                }
            }

            int added = 0;
            int resolved = 0;
            java.util.Set<String> seen = new java.util.HashSet<>();
            for (String h : hosts) {
                List<String> ips = DnsServer.resolve(h);
                if (ips.isEmpty()) continue;
                resolved++;
                for (String ip : ips) {
                    if (!seen.add(ip)) continue;
                    if (routedAddrs.contains(ip)) continue;
                    InetAddress a = DnsServer.toAddress(ip);
                    if (a == null) continue;
                    if (a instanceof java.net.Inet6Address) continue;  // 只处理 IPv4
                    try {
                        b.addRoute(a, 32);
                        routedAddrs.add(ip);
                        added++;
                    } catch (Exception ignored) {
                    }
                }
            }
            FileLog.i("dynamic-resolve: 域名 " + hosts.size() + " 个, 解析成功 "
                    + resolved + " 个, 新增路由 " + added + " 条(基础 " + baseRoutes + ")");
            append("动态解析:新增 IP 路由 " + added + " 条(应对 CDN 轮换)");
        } catch (Exception e) {
            FileLog.w("dynamic-resolve 失败: " + e);
        }
    }

    /** 供 DnsServer 解析时 protect() 自己新建的 socket, 否则包会被自己的隧道吃掉 */
    private static volatile FilterVpnService self;

    /**
     * 读 assets/ipblock.txt, 返回 [IP, 前缀长度] 列表。
     * 支持 "1.2.3.0/24" 与裸 "1.2.3.4"(按 /32)。
     */
    private java.util.List<String[]> loadIpBlockAsset() {
        java.util.List<String[]> out = new ArrayList<>();
        try (java.io.InputStream is = getAssets().open("ipblock.txt");
             java.io.BufferedReader br = new java.io.BufferedReader(
                     new java.io.InputStreamReader(is, "UTF-8"))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int slash = line.indexOf('/');
                String ip;
                String prefix;
                if (slash > 0) {
                    ip = line.substring(0, slash).trim();
                    prefix = line.substring(slash + 1).trim();
                } else {
                    ip = line;
                    prefix = ip.contains(":") ? "128" : "32";
                }
                if (!ip.matches("[0-9a-fA-F:.]+")) continue;
                try {
                    Integer.parseInt(prefix);
                } catch (NumberFormatException e) {
                    continue;
                }
                out.add(new String[]{ip, prefix});
            }
        } catch (Exception e) {
            FileLog.w("读取 ipblock.txt 失败: " + e);
        }
        return out;
    }

    public static boolean protectSocket(java.net.DatagramSocket s) {
        FilterVpnService v = self;
        if (v == null) return false;
        try {
            return v.protect(s);
        } catch (Exception e) {
            return false;
        }
    }

    private long qTotal, qBlocked;
    private final List<String> recent = new ArrayList<>();
    private final List<String> blockedHosts = new ArrayList<>();
    private final Set<String> blockedSet = new LinkedHashSet<>();

    public static FilterVpnService get() { return instance; }
    public static boolean isRunning() { return instance != null; }

    public long queryTotal() { return qTotal; }
    public long queryBlocked() { return qBlocked; }

    public List<String> recentLines() {
        synchronized (recent) { return new ArrayList<>(recent); }
    }

    public List<String> blockedHostList() {
        synchronized (blockedHosts) { return new ArrayList<>(blockedHosts); }
    }

    /** 拦截列表持久化 —— 停止后不再丢失 */
    private void persistBlocked() {
        try {
            StringBuilder sb = new StringBuilder();
            synchronized (blockedHosts) {
                for (String h : blockedHosts) sb.append(h).append('\n');
            }
            java.io.FileOutputStream fo =
                    new java.io.FileOutputStream(new java.io.File(getFilesDir(), "hit.txt"));
            fo.write(sb.toString().getBytes("UTF-8"));
            fo.close();
        } catch (Exception ignored) {
        }
    }

    private void loadPersistedBlocked() {
        try {
            java.io.File f = new java.io.File(getFilesDir(), "hit.txt");
            if (!f.exists()) return;
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(new java.io.FileInputStream(f), "UTF-8"));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && blockedSet.add(line)) blockedHosts.add(line);
            }
            br.close();
        } catch (Exception ignored) {
        }
    }

    public DomainRules rules() { return rules; }

    /** 清空"已拦截域名"列表(同时删掉持久化文件), 返回清掉的条数。 */
    public int clearHitRecords() {
        int n;
        synchronized (blockedHosts) {
            n = blockedHosts.size();
            blockedHosts.clear();
        }
        blockedSet.clear();
        try {
            new java.io.File(getFilesDir(), "hit.txt").delete();
        } catch (Exception ignored) {
        }
        return n;
    }

    // ------------------------------------------------------------ 生命周期

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        self = this;
        FileLog.init(this);
        FileLog.i("onCreate pid=" + android.os.Process.myPid());
        rules = new DomainRules(this);
        loadPersistedBlocked();
        createChannel();
    }

    /**
     * 用户点了「刷新拦截」: 只重启隧道, 不杀进程。
     * 目的: 切换 VPN 会改变网络接口, 从而让系统 DNS 缓存失效 ——
     * 这是解决"广告域名被缓存导致漏拦"的关键动作。
     */
    public static final String ACTION_REFRESH = "com.dsh.chainblock.REFRESH";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopVpn();
            return START_NOT_STICKY;
        }
        startForeground(NOTIF_ID, buildNotification("已启用 · 拦截中"));
        if (ACTION_REFRESH.equals(action)) {
            FileLog.i("收到 REFRESH: 重建隧道以清空 DNS 缓存");
            rebuildTunnel();
            return START_STICKY;
        }
        if (!running) startVpn();
        return START_STICKY;
    }

    /** 重建隧道: 关掉旧 tun 再建新的。系统会因接口变化而丢弃 DNS 缓存。 */
    private void rebuildTunnel() {
        try {
            if (dns != null) { dns.stop(); dns = null; }
            if (tun != null) { try { tun.close(); } catch (Exception ignored) { } tun = null; }
            running = false;
            liveBuilder = null;
            Thread.sleep(300);
        } catch (Exception ignored) {
        }
        startVpn();
        append("隧道已重建(DNS 缓存已刷新)");
    }

    @Override
    public void onDestroy() {
        stopVpn();
        instance = null;
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        // 用户从系统里撤销了 VPN 授权
        prefs().edit().putBoolean("enabled", false).apply();
        stopVpn();
        super.onRevoke();
    }

    private SharedPreferences prefs() {
        return getSharedPreferences("cfg", Context.MODE_PRIVATE);
    }

    // ------------------------------------------------------------ 建立隧道

    private void startVpn() {
        try {
            Builder b = new Builder();
            b.setSession("链式安装拦截");
            b.addAddress(TUN_ADDR, PREFIX);
            // 关键: 把自己排除在自己的 VPN 之外。
            // 否则本进程发出的 DNS 查询会被自己的隧道吃掉, 表现为"解析失败"
            // (这是之前"黑洞路由永远 0 条"的真正原因)。
            try {
                b.addDisallowedApplication(getPackageName());
                FileLog.i("addDisallowedApplication(自己) -> ok");
            } catch (Exception e) {
                FileLog.w("addDisallowedApplication 失败(自解析将不可用): " + e);
            }
            // 只把 DNS 服务器地址导入隧道, 不抢默认路由
            b.addDnsServer(DnsServer.FAKE_DNS);
            b.addRoute(DnsServer.FAKE_DNS, 32);
            b.addRoute("0.0.0.1", 32);          // 占位非 DNS 路由
            // 先加资源表里写死的 IP(保证即使自解析失败也有一层兜底)
            int ipRoutes = 0;
            StringBuilder routeLog = new StringBuilder();
            for (String[] entry : loadIpBlockAsset()) {
                String ip = entry[0];
                int prefix = Integer.parseInt(entry[1]);
                InetAddress a = DnsServer.toAddress(ip);
                if (a == null) {
                    routeLog.append(ip).append("=(无法解析) ");
                    continue;
                }
                try {
                    b.addRoute(a, prefix);
                    ipRoutes++;
                    routeLog.append(ip).append('/').append(prefix).append(' ');
                } catch (Exception e) {
                    routeLog.append(ip).append("=(addRoute失败:").append(e).append(") ");
                }
            }
            FileLog.i("黑洞路由 " + ipRoutes + " 条: " + routeLog);
            if (ipRoutes == 0) {
                FileLog.w("黑洞路由为 0! IP 层屏蔽未生效(只靠 DNS 层)");
            }
            if (Build.VERSION.SDK_INT >= 29) {
                b.setMetered(false);
                b.setBlocking(true);
            }
            if (Build.VERSION.SDK_INT >= 31) {
                // 不声明任何用途, 尽量减少对系统策略的影响
            }
            tun = b.establish();
            liveBuilder = b;
            FileLog.i("establish() -> " + (tun == null ? "null(失败)" : "ok"));
            if (tun == null) {
                notifyText("建立隧道失败: 系统拒绝");
                prefs().edit().putBoolean("enabled", false).apply();
                stopSelf();
                return;
            }
            running = true;
            prefs().edit().putBoolean("enabled", true).apply();

            FileInputStream in = new FileInputStream(tun.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(tun.getFileDescriptor());

            dns = new DnsServer(this, rules, listener, MTU);
            dns.start(in, out);

            append("隧道已建立 · DNS 服务器 " + DnsServer.FAKE_DNS
                    + " · IP 黑洞路由 " + ipRoutes + " 条");

            // 隧道起来后立刻(不再等 1.5 秒)把黑名单域名解析一遍加路由。
            // 广告 CDN 的 IP 几小时就轮换(实测 151 个 IP 里 69 个是新的),
            // 静态列表必然过期, 所以每次启动/刷新都重新解析。
            final int baseRoutes = ipRoutes;
            new Thread(() -> resolveAndBlackhole(baseRoutes), "dynamic-resolve").start();
        } catch (Exception e) {
            notifyText("启动失败: " + e);
            Log.e(TAG, "startVpn", e);
            stopVpn();
        }
    }

    private void stopVpn() {
        running = false;
        if (dns != null) {
            dns.stop();
            dns = null;
        }
        if (tun != null) {
            try { tun.close(); } catch (Exception ignored) { }
            tun = null;
        }
        if (pump != null) {
            pump.interrupt();
            pump = null;
        }
        prefs().edit().putBoolean("enabled", false).apply();
        stopForeground(true);
        stopSelf();
        append("已停止");
    }

    // ------------------------------------------------------------ DnsServer 回调

    private final Set<String> loggedAllow = new LinkedHashSet<>();
    private final Set<String> routedAddrs = new LinkedHashSet<>();
    private volatile Builder liveBuilder;

    /** 把域名已解析出的地址加进黑洞路由(IPv4 /32 或 IPv6 /128)。 */
    private void blackhole(String ip) {
        if (ip == null || !routedAddrs.add(ip)) return;
        InetAddress a = DnsServer.toAddress(ip);
        if (a == null) return;
        Builder b = liveBuilder;
        if (b == null) return;
        try {
            b.addRoute(a, a instanceof java.net.Inet6Address ? 128 : 32);
        } catch (Exception e) {
            FileLog.w("addRoute 失败 " + ip + " :: " + e);
        }
    }

    private final DnsServer.Listener listener = new DnsServer.Listener() {
        @Override
        public void onVerdict(String host, String type, boolean blocked) {
            qTotal++;
            if (blocked) {
                qBlocked++;
                if (blockedSet.add(host)) {
                    synchronized (blockedHosts) { blockedHosts.add(0, host); }
                    persistBlocked();
                }
                FileLog.i("BLOCK " + host + " [" + type + "]");
                append("拦截  " + host + "  [" + type + "]");
                Intent i = new Intent("com.dsh.chainblock.UPDATE");
                i.setPackage(getPackageName());
                sendBroadcast(i);
            } else if (loggedAllow.add(host)) {
                // 放行的域名每个只记一次, 避免日志爆掉
                FileLog.i("ALLOW " + host + " [" + type + "]");
            }
        }

        @Override
        public void onBlockedHost(String host) {
            Intent i = new Intent("com.dsh.chainblock.UPDATE");
            i.setPackage(getPackageName());
            sendBroadcast(i);
        }

        @Override
        public void onResolved(String host, List<String> addresses) {
            // 只对"已在黑名单里的域"或"广告相关域"加路由, 避免把正常业务地址也黑洞掉
            if (rules == null) return;
            DomainRules.Verdict v = rules.judge(host);
            if (v != DomainRules.Verdict.BLOCK) return;
            for (String ip : addresses) blackhole(ip);
        }

        @Override
        public void onError(String msg) {
            FileLog.w("DnsServer: " + msg);
            append("! " + msg);
        }
    };

    private void append(String line) {
        synchronized (recent) {
            recent.add(0, line);
            while (recent.size() > 300) recent.remove(recent.size() - 1);
        }
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        FileLog.i("onTrimMemory level=" + level);
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        FileLog.w("onTaskRemoved: 被滑出最近任务。running=" + running);
        if (running && prefs().getBoolean("enabled", false)) {
            // 尝试让系统把我们拉回来。注意: HyperOS 的 SwipeUpClean 走的是
            // force-stop, 这种情况下这个回调可能根本不会被调用, 也无法恢复。
            // 真正的解法是到「设置 → 应用 → 链式安装拦截 → 自启动」放行。
            try {
                Intent svc = new Intent(this, FilterVpnService.class);
                svc.setAction(ACTION_START);
                startService(svc);
                FileLog.i("onTaskRemoved: 已请求重启服务");
            } catch (Exception e) {
                FileLog.e("onTaskRemoved: 重启失败", e);
            }
        }
        super.onTaskRemoved(rootIntent);
    }

    // ------------------------------------------------------------ 通知

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null && nm.getNotificationChannel(CHANNEL) == null) {
                NotificationChannel c = new NotificationChannel(
                        CHANNEL, "链式安装拦截", NotificationManager.IMPORTANCE_LOW);
                c.setShowBadge(false);
                nm.createNotificationChannel(c);
            }
        }
    }

    private Notification buildNotification(String text) {
        Intent i = new Intent(this, MainActivity.class);
        int fl = Build.VERSION.SDK_INT >= 23
                ? PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
                : PendingIntent.FLAG_UPDATE_CURRENT;
        PendingIntent pi = PendingIntent.getActivity(this, 0, i, fl);
        Notification.Builder b = new Notification.Builder(this, CHANNEL);
        return b.setContentTitle("链式安装拦截")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .setContentIntent(pi)
                .build();
    }

    private void notifyText(String text) {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) nm.notify(NOTIF_ID + 1, buildNotification(text));
        } catch (Exception ignored) {
        }
    }
}

