package com.dsh.chainblock;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.List;

/**
 * 界面(纯代码构建, 不依赖任何资源文件)。
 *
 * 三个区域:
 *   1. 开关与状态
 *   2. 新增拦截域名(回车即加入黑名单) / 放行域名 / 严格模式
 *   3. 被拦截的域名列表 + 实时日志
 */
public class MainActivity extends Activity {

    private static final int REQ_VPN = 1001;

    private TextView status, stats, logView, blockedView;
    private Button toggle, addBlockBtn, addAllowBtn;
    private EditText input;
    private CheckBox strict;
    private DomainRules pendingRules;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private BroadcastReceiver rx;
    private boolean refreshing;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        pendingRules = new DomainRules(this);
        setContentView(buildUi());

        rx = new BroadcastReceiver() {
            @Override public void onReceive(Context c, Intent i) { refresh(); }
        };
        IntentFilter f = new IntentFilter("com.dsh.chainblock.UPDATE");
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(rx, f, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(rx, f);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
        ui.postDelayed(ticker, 1200);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(ticker);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        try { unregisterReceiver(rx); } catch (Exception ignored) { }
    }

    private final Runnable ticker = new Runnable() {
        @Override public void run() {
            refresh();
            ui.postDelayed(this, 1200);
        }
    };

    // ------------------------------------------------------------ 界面构建

    private static int dp(Context c, int v) {
        return Math.round(c.getResources().getDisplayMetrics().density * v);
    }

    private View buildUi() {
        int pad = dp(this, 16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);
        root.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        title.setText("链式安装拦截");
        title.setTextSize(21);
        title.setTextColor(Color.BLACK);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("本地 DNS 拦截 · 不转发到任何服务器 · 无 root");
        sub.setTextSize(12);
        sub.setTextColor(Color.GRAY);
        root.addView(sub);

        status = new TextView(this);
        status.setTextSize(15);
        status.setPadding(0, dp(this, 14), 0, dp(this, 6));
        root.addView(status);

        stats = new TextView(this);
        stats.setTextSize(13);
        stats.setTextColor(Color.DKGRAY);
        root.addView(stats);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(this, 10), 0, dp(this, 10));
        toggle = new Button(this);
        toggle.setText("启用拦截");
        toggle.setOnClickListener(v -> onToggle());
        row.addView(toggle);

        Button refreshBtn = new Button(this);
        refreshBtn.setText("刷新拦截");
        refreshBtn.setOnClickListener(v -> doRefresh());
        row.addView(refreshBtn);

        Button reset = new Button(this);
        reset.setText("清零记录");
        reset.setOnClickListener(v -> {
            // 只清 App 内存里的命中记录(服务下次启动会重新加载 persist)
            int n = (FilterVpnService.get() == null) ? 0 : FilterVpnService.get().clearHitRecords();
            toast("已清空 " + n + " 条命中记录");
            refresh();
        });
        row.addView(reset);
        root.addView(row);

        // 刷新说明
        TextView refreshTip = new TextView(this);
        refreshTip.setText("「刷新拦截」= 重建隧道以清空系统 DNS 缓存。"
                + "如果发现广告又开始出现,点一下这个即可(不用重装、不用重启手机)。");
        refreshTip.setTextSize(11);
        refreshTip.setTextColor(Color.GRAY);
        refreshTip.setPadding(0, 0, 0, dp(this, 8));
        root.addView(refreshTip);

        // 开机自启开关
        CheckBox autostart = new CheckBox(this);
        autostart.setText("开机自动恢复拦截(重启手机后不用手动点)");
        autostart.setTextSize(12);
        autostart.setChecked(sp0().getBoolean("autostart", true));
        autostart.setOnCheckedChangeListener((b, checked) -> {
            sp0().edit().putBoolean("autostart", checked).apply();
            toast(checked ? "已开启开机自启" : "已关闭开机自启");
        });
        root.addView(autostart);
strict = new CheckBox(this);
        strict.setText("严格模式(只放行白名单, 其余全断 —— 最狠但可能误伤)");
        strict.setTextSize(12);
        strict.setOnCheckedChangeListener((b, checked) -> {
            pendingRules.setStrictMode(checked);
            toast(checked ? "严格模式已开:只放行白名单" : "严格模式已关:按黑名单拦截");
        });
        root.addView(strict);

        // ---- 新增规则
        LinearLayout addRow = new LinearLayout(this);
        addRow.setOrientation(LinearLayout.HORIZONTAL);
        addRow.setPadding(0, dp(this, 8), 0, 0);
        input = new EditText(this);
        input.setHint("例如 app.market.xiaomi.com");
        input.setTextSize(13);
        input.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        input.setLayoutParams(lp);
        addRow.addView(input);

        addBlockBtn = new Button(this);
        addBlockBtn.setText("拦截");
        addBlockBtn.setOnClickListener(v -> addRule(true));
        addRow.addView(addBlockBtn);

        addAllowBtn = new Button(this);
        addAllowBtn.setText("放行");
        addAllowBtn.setOnClickListener(v -> addRule(false));
        addRow.addView(addAllowBtn);
        root.addView(addRow);

        // ---- 被拦截域名
        TextView h2 = new TextView(this);
        h2.setText("已拦截的域名(本次运行)");
        h2.setTextSize(14);
        h2.setPadding(0, dp(this, 14), 0, dp(this, 4));
        root.addView(h2);

        blockedView = new TextView(this);
        blockedView.setTextSize(12);
        blockedView.setTextColor(Color.parseColor("#B00020"));
        blockedView.setPadding(0, 0, 0, dp(this, 10));
        root.addView(blockedView);

        // ---- 日志
        TextView h3 = new TextView(this);
        h3.setText("日志");
        h3.setTextSize(14);
        h3.setPadding(0, dp(this, 6), 0, dp(this, 4));
        root.addView(h3);

        ScrollView scroll = new ScrollView(this);
        scroll.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        logView = new TextView(this);
        logView.setTextSize(11);
        logView.setTextColor(Color.DKGRAY);
        logView.setGravity(Gravity.START);
        scroll.addView(logView);
        root.addView(scroll);

        return root;
    }

    // ------------------------------------------------------------ 交互

    private void onToggle() {
        if (FilterVpnService.isRunning()) {
            startService(new Intent(this, FilterVpnService.class)
                    .setAction(FilterVpnService.ACTION_STOP));
            toast("已停止");
            ui.postDelayed(this::refresh, 400);
            return;
        }
        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);
        } else {
            startService(new Intent(this, FilterVpnService.class)
                    .setAction(FilterVpnService.ACTION_START));
            ui.postDelayed(this::refresh, 600);
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_VPN) {
            if (res == RESULT_OK) {
                startService(new Intent(this, FilterVpnService.class)
                        .setAction(FilterVpnService.ACTION_START));
                ui.postDelayed(this::refresh, 600);
            } else {
                toast("你拒绝了 VPN 授权, 无法拦截");
            }
        }
    }

    private void addRule(boolean block) {
        String d = input.getText().toString().trim();
        if (d.isEmpty()) {
            toast("先填一个域名");
            return;
        }
        if (block) {
            pendingRules.addBlock(d);
            toast("已加入拦截: " + d);
        } else {
            pendingRules.addAllow(d);
            toast("已加入放行: " + d);
        }
        input.setText("");
        if (FilterVpnService.isRunning()) {
            FilterVpnService s = FilterVpnService.get();
            if (s != null && s.rules() != null) s.rules().reload();
        }
        refresh();
    }

    private void toast(String m) {
        Toast.makeText(this, m, Toast.LENGTH_SHORT).show();
    }

    private android.content.SharedPreferences sp0() {
        return getSharedPreferences("cfg", Context.MODE_PRIVATE);
    }

    /** 刷新: 只在拦截已启用时才重建隧道。没启用就明确提示, 绝不偷偷启动。 */
    private void doRefresh() {
        if (!FilterVpnService.isRunning()) {
            toast("拦截当前是关闭状态。请先点「启用拦截」");
            return;
        }
        Intent i = new Intent(this, FilterVpnService.class);
        i.setAction(FilterVpnService.ACTION_REFRESH);
        try {
            startService(i);
            toast("已刷新:隧道重建,DNS 缓存已失效");
        } catch (Exception e) {
            toast("刷新失败: " + e);
        }
        ui.postDelayed(this::refresh, 1200);
    }

    // ------------------------------------------------------------ 刷新

    private void refresh() {
        FilterVpnService s = FilterVpnService.get();
        boolean on = FilterVpnService.isRunning();
        SharedPreferences sp = getSharedPreferences("cfg", Context.MODE_PRIVATE);

        status.setText(on ? "● 拦截已启用" : "○ 未启用");
        status.setTextColor(on ? Color.parseColor("#1B7F3B") : Color.parseColor("#B00020"));
        toggle.setText(on ? "停止拦截" : "启用拦截");
        strict.setChecked(pendingRules.isStrictMode());

        long total = s == null ? 0 : s.queryTotal();
        long blocked = s == null ? 0 : s.queryBlocked();
        stats.setText("DNS 查询 " + total + " 条 · 已拦截 " + blocked
                + " 条 · 内置黑名单 " + pendingRules.builtinCount() + " 条"
                + (sp.getBoolean("strict", false) ? " · 严格模式" : ""));

        List<String> bh = s == null ? null : s.blockedHostList();
        if (bh == null || bh.isEmpty()) {
            blockedView.setText("(暂无。触发一次广告就知道了)");
        } else {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(bh.size(), 20); i++) {
                sb.append("  ").append(bh.get(i)).append('\n');
            }
            blockedView.setText(sb.toString().trim());
        }

        List<String> lines = s == null ? null : s.recentLines();
        if (lines == null || lines.isEmpty()) {
            logView.setText("(还没有日志)");
        } else {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(lines.size(), 120); i++) {
                sb.append(lines.get(i)).append('\n');
            }
            logView.setText(sb.toString());
        }
    }
}

