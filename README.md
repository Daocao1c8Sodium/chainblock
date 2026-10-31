# ChainBlock · 链式安装拦截

一个**无需 root** 的 Android 本地网络拦截器,专门用来阻断国产 App 通过
deeplink 拉起「小米应用商店」后**静默安装推广 App** 的行为。

> 思路不是去"禁止安装",而是让应用商店**没活可干**。

---

## 它解决什么问题

很多国产 App(典型如校园跑步类应用)内置多个广告 SDK。用户触发广告后:

```
广告 SDK  →  startActivity("market://details?id=xxx")
                    ↓
        小米应用商店(系统特权应用, 持 INSTALL_PACKAGES)
                    ↓
            未经确认直接下载并安装
```

**为什么常见方案都无效:**

| 方案 | 为什么不行 |
|---|---|
| AdGuard / DNS 过滤 | 拦截发生在**本地 Intent** 层面,不经过 DNS;广告 SDK 还可能用 HTTPDNS 直连 IP |
| 禁用「链式启动 / 关联启动」 | 商店是系统特权应用,在系统白名单里;而且该权限实际被设为 `ignore` 而非 `deny` |
| 商店里的"自动安装"开关 | **商店根本没有这个开关**(反编译确认) |
| Xposed / LSPosed 改 SDK | 目标 App 带环境检测,检测到 hook 会直接闪退 |
| `pm disable-user` 商店组件 | HyperOS 拒绝:`Shell cannot change component state` |

**ChainBlock 的做法:** 不管安装是谁执行的,只要让商店**拿不到"要装什么"的指令**、
**下载通道也连不通**,链条自然断掉。

---

## 工作原理

```
┌─ VpnService(不抢默认路由, 不影响网速)
│   只导入 3 类路由:
│     1. 10.111.222.1/32   ← 自建 DNS 服务器
│     2. 静态/动态 IP 黑洞   ← 下载通道 + 广告 CDN
│     3. 0.0.0.1/32         ← 占位
│
├─ 自建 DNS(用户态, 端口 53)
│   域名判定 → 放行: 代查上游返回真实 IP
│             → 拦截: 回 0.0.0.0(AAAA 回 ::)
│
└─ 判定顺序(放行优先)
    1. 内置白名单 CRITICAL      → ALLOW  (运动/定位/登录/推送/系统)
    2. 用户白名单 allow.txt     → ALLOW
    3. 用户黑名单 block.txt     → BLOCK
    4. 内置黑名单 assets/blocklist.txt → BLOCK
    5. 严格模式(默认关)        → BLOCK
    6. 其余                     → ALLOW
```

### 三个关键实现细节

**1. 必须 `addDisallowedApplication(自己)`**

否则 VPN 进程自己发出的 DNS 查询会被自己的隧道吃掉,表现为"解析全部失败"。
这是最初版本黑洞路由一直为 0 条的根本原因。

**2. DNS 会被系统缓存绕过,所以必须有 IP 层**

一旦某次 VPN 未开启,系统就会把域名→IP 缓存下来;之后即使开启拦截,
请求也不再发 DNS 查询。**IP 路由不受缓存影响**,是这一层的兜底。

**3. 广告 CDN 的 IP 几小时就轮换**

实测:151 个广告 IP 里 **69 个是几小时后新出现的**。所以静态 IP 列表必然过期,
必须在每次启动/刷新时**重新解析**一遍黑名单域名并补加路由。

---

## 功能

- **147 条**拦截域名(快手 / 穿山甲 / 优量汇 / 百度联盟 / 亿帆 / 天幕 / 友盟 / 京东 等)
- **210+ 条** IP 黑洞路由(迅雷下载 CDN、小米加速节点、商店主 API、广告 CDN)
- 界面:**启用/停止**、**刷新拦截**(重建隧道以清空系统 DNS 缓存)、**清零记录**、
  **开机自启**、手动**拦截/放行**任意域名
- 诊断日志: `/sdcard/Android/data/com.dsh.chainblock/files/chainblock.log`

---

## 构建

**依赖**(只用 SDK 自带工具链,**不需要 Gradle / Android Studio**):

- JDK 17+
- Android SDK:`build-tools` + `platforms`

```bash
sdkmanager "platform-tools" "build-tools;36.0.0" "platforms;android-36"
```

**设置环境变量后构建:**

```powershell
$env:JAVA_HOME        = "C:\Program Files\Java\jdk-22"
$env:ANDROID_SDK_ROOT = "C:\Program Files (x86)\Android\android-sdk"

pwsh -File build.ps1
```

脚本会自动挑选版本最高的 `build-tools` 与 `platforms\android-*`,
输出 `build/chainblock.apk`(已 zipalign + 签名)。

首次构建会自动生成 `debug.keystore`(已被 `.gitignore` 排除)。

---

## 安装与使用

```bash
adb install -r build/chainblock.apk
```

> 小米/HyperOS 需要先在「开发者选项 → USB 安装」里放行。
> 另注:`adb install -g` 在 HyperOS 上会报
> `INSTALL_GRANT_RUNTIME_PERMISSIONS`,不要加 `-g`。

1. 打开 App → 点「启用拦截」→ 允许 VPN 授权
2. 状态变绿「● 拦截已启用」

### ⚠️ 唯一必须记住的规则

> **每次打开目标 App 之前,先确认拦截已启用。**

如果拦截关闭时打开了目标 App,广告 SDK 会把解析到的 IP
**持久化到应用私有目录**(`/data/data/`,清外部缓存无效),之后它就绕过 DNS 直连,
任何网络层拦截都会失效。补救办法只有一个:

```
设置 → 应用 → 目标App → 存储 → 清除全部数据
或:  adb shell pm clear <包名>
```

清除后需要重新登录(服务端数据不会丢)。

---

## 已知限制(说清楚的部分)

| 限制 | 原因 |
|---|---|
| **广告仍可能显示** | 广告 SDK 用 HTTPDNS / 预存 IP 直连,绕过系统 DNS;部分广告内容由目标 App 自身服务器下发(与业务数据同域,封了就废功能) |
| **但广告已无法触发安装** | 这是本项目的核心目标,已达成 |
| 商店 / 京东等在拦截开启时不可用 | 主动取舍:推广接口与手动更新共用同一套基础设施,技术上无法区分 |
| 仅处理 IPv4 直连 | IPv6 侧靠 DNS 返回 `::` 阻断 |
| 无法躲避上滑清后台 | HyperOS 的 `SwipeUpClean` 是 `force-stop`,任何 API 都挡不住 |

---

## 踩过的坑

1. **白名单绝不能放笼统顶级域**
   匹配规则是「自身 + 逐级父域」,一条 `xiaomi.com` 会让
   `app.market.xiaomi.com` 的父域匹配上,从而把整片黑名单放行掉。
   这个坑排查了 4 个版本才定位。

2. **DNS 拦截对"缓存过的解析"完全失效**
   必须配合 IP 层;"刷新"本质是重建隧道,令系统 DNS 缓存失效。

3. **HyperOS 封掉了大部分 adb 能力**
   `settings put`(global/secure)被拒、`pm disable-user` 任何组件被拒、
   `cmd appops set` 是唯一还能用的写入通道。
   **Shizuku 也救不了**——它同为 `uid 2000`,没有额外能力。

4. **`zipalign` 必须在签名之前**
   顺序错会导致安装失败。

5. **`classes.dex` 必须 STORE 存放**
   压缩存放会导致部分 ROM 拒绝加载。

---

## 目录结构

```
.
├── AndroidManifest.xml
├── build.ps1                    # 离线构建脚本(无需 Gradle)
├── assets/
│   ├── blocklist.txt            # 拦截域名(147 条)
│   └── ipblock.txt              # IP 黑洞路由(210+ 条)
├── res/values/styles.xml
└── src/com/dsh/chainblock/
    ├── BootReceiver.java        # 开机自启
    ├── DnsCodec.java            # DNS 报文编解码
    ├── DnsServer.java           # 自建 DNS 服务器
    ├── DomainRules.java         # 白名单 / 黑名单判定
    ├── FileLog.java             # 诊断日志
    ├── FilterVpnService.java    # VpnService 主体
    └── MainActivity.java        # 界面(纯代码构建,无 XML 布局)
```

---

## 免责声明

本项目仅用于**在自有设备上保护个人隐私**。

- 不包含任何第三方应用的代码或资源
- 域名清单来自对自有设备网络请求的观察
- 请自行判断在你的设备与地区使用的合法性与风险
- 修改系统或拦截网络可能导致其它应用异常,后果自负

---

## 测试环境

Xiaomi 15 Pro · HyperOS 3.0 · Android 16 (API 36) · 未 root
