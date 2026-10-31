package com.dsh.chainblock;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 诊断日志:同时写 logcat 和
 *   /sdcard/Android/data/com.dsh.chainblock/files/chainblock.log
 * 后者可以直接用 adb 读出, 不需要 root。
 * 超过 4MB 自动清空(只做一轮诊断, 不需要滚动归档)。
 */
public final class FileLog {

    public static final String TAG = "ChainBlock";
    private static final long MAX = 4L * 1024 * 1024;

    private static File file;
    private static final SimpleDateFormat FMT =
            new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US);

    private FileLog() {}

    public static synchronized void init(Context ctx) {
        try {
            File dir = ctx.getExternalFilesDir(null);
            if (dir != null) {
                if (!dir.exists()) dir.mkdirs();
                file = new File(dir, "chainblock.log");
            }
        } catch (Exception e) {
            file = null;
        }
        i("=== 会话开始 ===");
    }

    public static String path() {
        return file == null ? "(无)" : file.getAbsolutePath();
    }

    public static void i(String msg) {
        Log.i(TAG, msg);
        write("I", msg);
    }

    public static void w(String msg) {
        Log.w(TAG, msg);
        write("W", msg);
    }

    public static void e(String msg, Throwable t) {
        Log.e(TAG, msg, t);
        write("E", msg + (t == null ? "" : " :: " + t));
    }

    private static void write(String level, String msg) {
        if (file == null) return;
        try {
            if (file.length() > MAX) {
                FileOutputStream trunc = new FileOutputStream(file, false);
                trunc.close();
            }
            String line = FMT.format(new Date()) + " " + level + " " + msg + "\n";
            FileOutputStream fo = new FileOutputStream(file, true);
            fo.write(line.getBytes("UTF-8"));
            fo.close();
        } catch (IOException ignored) {
        }
    }

    /** 供外部快速拿到路径(即便 file 为 null 也给个合理提示) */
    public static String externalDirHint(Context ctx) {
        File d = ctx.getExternalFilesDir(null);
        if (d != null) return d.getAbsolutePath();
        return Environment.getExternalStorageDirectory() + "/Android/data/com.dsh.chainblock/files";
    }
}
