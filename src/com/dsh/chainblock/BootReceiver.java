package com.dsh.chainblock;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

/**
 * 开机自启。
 *
 * 只在"上次是用户主动启用拦截"的情况下才自动恢复 —— 用户手动点了停止之后,
 * 重启手机不应该又自己打开。
 *
 * 注意: HyperOS 可能会拦截第三方广播。如果发现重启后没自动恢复,
 * 需要到「设置 → 应用 → 链式安装拦截 → 自启动」里放行。
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context ctx, Intent intent) {
        String action = intent == null ? null : intent.getAction();
        boolean boot = Intent.ACTION_BOOT_COMPLETED.equals(action)
                || "android.intent.action.QUICKBOOT_POWERON".equals(action)
                || "com.htc.intent.action.QUICKBOOT_POWERON".equals(action);
        if (!boot) return;

        SharedPreferences sp = ctx.getSharedPreferences("cfg", Context.MODE_PRIVATE);
        // 用户最后一次操作是"启用"才恢复
        boolean wasEnabled = sp.getBoolean("enabled", false);
        // 允许用户关掉开机自启
        boolean autoStart = sp.getBoolean("autostart", true);

        FileLog.init(ctx);
        FileLog.i("BootReceiver: 开机完成, wasEnabled=" + wasEnabled + " autoStart=" + autoStart);

        if (!wasEnabled || !autoStart) {
            FileLog.i("BootReceiver: 不恢复(用户之前停用过或关了自启)");
            return;
        }
        try {
            Intent svc = new Intent(ctx, FilterVpnService.class);
            svc.setAction(FilterVpnService.ACTION_START);
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                ctx.startForegroundService(svc);
            } else {
                ctx.startService(svc);
            }
            FileLog.i("BootReceiver: 已请求重启拦截服务");
        } catch (Exception e) {
            FileLog.e("BootReceiver: 启动失败", e);
        }
    }
}
