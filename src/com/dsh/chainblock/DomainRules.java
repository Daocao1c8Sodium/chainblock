package com.dsh.chainblock;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 规则引擎。
 *
 * 判定顺序(先放行后拦截, 放行优先):
 *   1. 内置保护白名单(critical)   -> ALLOW   (运动世界后端/定位/商店更新/系统)
 *   2. 用户白名单 allow.txt        -> ALLOW
 *   3. 用户黑名单 block.txt        -> BLOCK
 *   4. 内置黑名单 assets/blocklist.txt -> BLOCK
 *   5. 严格模式                 -> BLOCK (除 1、2 外一律断)
 *   6. 其余                     -> ALLOW (正常解析)
 *
 * 匹配方式:自身 + 逐级父域, 因此 "open.e.kuaishou.com" 可拦 ".kuaishou.com"。
 */
public final class DomainRules {

    public enum Verdict { ALLOW, BLOCK }

    /** 绝对不许拦的域; 拦了会挂掉跑步/定位/成绩上传/商店更新或系统功能。 */
    private static final String[] CRITICAL = {
            // ===== 运动世界自有后端(跑步记录 / 成绩上传 / 地图 / 社区) =====
            // 实测出现过的全部自有域名 + 预留常见子域。
            // 父域 iydsj.com 已覆盖所有子域, 这里额外列出是为了"一眼看清保了什么"。
            "iydsj.com",
            "gxapp.iydsj.com",
            "discovery.gxapp.iydsj.com",
            "run.gxapp.iydsj.com",
            "h5.gxapp.iydsj.com",
            "datapoint.gxapp.iydsj.com",
            "control.gxapp.iydsj.com",
            "swapp-images.iydsj.com",
            "gxapp-images.iydsj.com",
            "gxapp-video.iydsj.com",
            "gxapp-vedio.iydsj.com",
            "static.iydsj.com",
            "api.iydsj.com",
            "www.iydsj.com",
            "iydsj-hbase-hot.obs.cn-east-3.myhuaweicloud.com",
            "gxapp-vedio.obs.cn-east-3.myhuaweicloud.com",
            "gxapp-images.obs.cn-east-3.myhuaweicloud.com",
            // ===== 定位(跑步轨迹的命脉) =====
            "restsdk.amap.com",       // 高德定位
            "amap.com",
            "location.amap.com",
            "aloc-offline.amap.com",
            "aps.amap.com",
            "dualstack-a.apilocate.amap.com",
            "dualstack-arestapi.amap.com",
            "dualstack-mpsapi.amap.com",
            "apilocate.amap.com",
            "arestapi.amap.com",
            "mpsapi.amap.com",
            "amapauto.com",
            "gaode.com",
            // ===== 小米应用商店的正常功能(必须保留, 否则手动更新 App 会挂) =====
            // 注意: 绝对不要在这里放 app.market.xiaomi.com ——
            //       它是"推广下载指令"的下发接口(/apm/download/<id>), 正是打击点。
            //       一旦放进白名单, 会盖掉黑名单里的同名条目, 整条链就拦不住了。
            // ===== 小米应用商店:只保留"更新检查"这一条命 =====
            // 用户已授权: 商店其它功能可以不好用, 只要能在别的时间段手动更新 App。
            // 运动世界(跑步/定位/成绩上传)完全不依赖商店域名, 所以砍掉其余接口
            // 不影响核心功能。
            "updateinfo.market.xiaomi.com",
            // ===== 系统与账号 =====
            // ⚠️ 千万不要在这里放 "xiaomi.com" / "miui.com" 这种笼统的顶级域!
            //    匹配规则是"自身 + 逐级父域", 一条 "xiaomi.com" 会让
            //    app.market.xiaomi.com 的父域匹配上, 从而把整个
            //    .market.xiaomi.com 黑名单全部废掉(实测踩过这个坑)。
            //    所以这里只放具体到子域的条目。
            "account.xiaomi.com",
            "api.account.xiaomi.com",
            "xiaomi.net",
            "mi-img.com",
            "micloud.com",
            "mipush.com",
            "xmsf.xiaomi.com",
            "flash.sec.miui.com",
            "adv.sec.miui.com",
            "virus-engine.sec.miui.com",
            "auth.be.sec.miui.com",
            "auth-engine.sec.miui.com",
            "ccc.sys.miui.com",
            "metok.sys.miui.com",
            // ===== 推送(运动世界用个推 com.igexin.sdk.*) =====
            // 严格模式下如果断了, 可能收不到跑步/成绩相关通知。
            "getui.com",
            "getui.net",
            "gepush.com",
            "igexin.com",
            // ===== 登录 / 短信验证(中国移动一键登录、运营商认证) =====
            // 运动世界登录很可能走这条路; 断掉会登不上, 属于"命脉"级别。
            "cmpassport.com",
            "wosms.cn",
            "id6.me",
            "189.cn",
            "10086.cn",
            "monternet.com",
            // ===== 图形验证码(登录/活动可能用到) =====
            "geetest.com",
            "geetest.com.cn",
            // ===== 校园与政务, 避免误伤 =====
            "edu.cn",
            "gov.cn",
    };

    private final Set<String> userAllow = Collections.synchronizedSet(new HashSet<String>());
    private final Set<String> userBlock = Collections.synchronizedSet(new HashSet<String>());
    private final Set<String> builtinBlock = Collections.synchronizedSet(new HashSet<String>());
    private final Set<String> criticalSet = new HashSet<>();

    private volatile boolean strictMode = false;

    private final Context ctx;

    public DomainRules(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        for (String s : CRITICAL) criticalSet.add(s.toLowerCase());
        reload();
    }

    // ---------------------------------------------------------------- 匹配

    private static boolean matches(Set<String> set, String host, boolean exact) {
        if (host == null || host.isEmpty()) return false;
        String h = host.toLowerCase();
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (set.contains(h)) return true;
        if (exact) return false;
        int idx = h.indexOf('.');
        while (idx >= 0) {
            String parent = h.substring(idx + 1);
            if (!parent.contains(".")) return false;   // 不匹配单标签顶级域
            if (set.contains(parent)) return true;
            idx = h.indexOf('.', idx + 1);
        }
        return false;
    }

    public Verdict judge(String host) {
        if (host == null || host.isEmpty()) return Verdict.ALLOW;
        if (matches(criticalSet, host, false)) return Verdict.ALLOW;
        if (matches(userAllow, host, false)) return Verdict.ALLOW;
        if (matches(userBlock, host, false)) return Verdict.BLOCK;
        if (matches(builtinBlock, host, false)) return Verdict.BLOCK;
        if (strictMode) return Verdict.BLOCK;
        return Verdict.ALLOW;
    }

    // ---------------------------------------------------------------- 状态

    public boolean isStrictMode() { return strictMode; }

    public void setStrictMode(boolean v) {
        strictMode = v;
        ctx.getSharedPreferences("cfg", Context.MODE_PRIVATE)
                .edit().putBoolean("strict", v).apply();
    }

    public List<String> getUserBlock() { return new ArrayList<>(userBlock); }
    public List<String> getUserAllow() { return new ArrayList<>(userAllow); }
    public int builtinCount() { return builtinBlock.size(); }

    // ---------------------------------------------------------------- 读写

    public void reload() {
        strictMode = ctx.getSharedPreferences("cfg", Context.MODE_PRIVATE)
                .getBoolean("strict", false);
        builtinBlock.clear();
        builtinBlock.addAll(loadFromAsset("blocklist.txt"));
        userBlock.clear();
        userBlock.addAll(loadFromFile(fileBlock()));
        userAllow.clear();
        userAllow.addAll(loadFromFile(fileAllow()));
    }

    public void addBlock(String domain) {
        domain = normalize(domain);
        if (domain.isEmpty()) return;
        userBlock.add(domain);
        userAllow.remove(domain);
        save();
    }

    public void addAllow(String domain) {
        domain = normalize(domain);
        if (domain.isEmpty()) return;
        userAllow.add(domain);
        userBlock.remove(domain);
        save();
    }

    public void removeBlock(String domain) {
        userBlock.remove(normalize(domain));
        save();
    }

    public void removeAllow(String domain) {
        userAllow.remove(normalize(domain));
        save();
    }

    private static String normalize(String d) {
        if (d == null) return "";
        d = d.trim().toLowerCase();
        if (d.startsWith("||")) d = d.substring(2);
        if (d.startsWith("http://")) d = d.substring(7);
        if (d.startsWith("https://")) d = d.substring(8);
        while (d.startsWith(".")) d = d.substring(1);
        if (d.endsWith("^")) d = d.substring(0, d.length() - 1);
        int slash = d.indexOf('/');
        if (slash >= 0) d = d.substring(0, slash);
        if (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        if (d.isEmpty() || !d.contains(".")) return "";
        for (int i = 0; i < d.length(); i++) {
            char c = d.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-' || c == '_';
            if (!ok) return "";
        }
        return d;
    }

    private File fileBlock() { return new File(ctx.getFilesDir(), "block.txt"); }
    private File fileAllow() { return new File(ctx.getFilesDir(), "allow.txt"); }

    private void save() {
        writeLines(fileBlock(), userBlock);
        writeLines(fileAllow(), userAllow);
    }

    private static void writeLines(File f, Set<String> set) {
        try (FileOutputStream fo = new FileOutputStream(f)) {
            StringBuilder sb = new StringBuilder();
            synchronized (set) {
                for (String s : set) sb.append(s).append('\n');
            }
            fo.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {
        }
    }

    private static List<String> loadFromFile(File f) {
        List<String> out = new ArrayList<>();
        if (!f.exists()) return out;
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                String n = normalize(line);
                if (!n.isEmpty() && !n.startsWith("#")) out.add(n);
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private List<String> loadFromAsset(String name) {
        List<String> out = new ArrayList<>();
        try (InputStream is = ctx.getAssets().open(name);
             BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("#")) continue;
                String n = normalize(line);
                if (!n.isEmpty()) out.add(n);
            }
        } catch (Exception ignored) {
        }
        return out;
    }
}
