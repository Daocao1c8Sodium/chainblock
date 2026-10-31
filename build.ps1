# 离线构建脚本:不依赖 Gradle, 直接用 SDK 自带工具链产出签名 APK
# 用法: pwsh -File build.ps1
$ErrorActionPreference = 'Stop'

function Fail($msg) { Write-Host "!!! $msg" -ForegroundColor Red; exit 1 }

# ---------- 定位 Android SDK ----------
# 优先用环境变量, 否则退回到 Windows 上最常见的两个默认位置。
$SDK = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
       elseif ($env:ANDROID_HOME) { $env:ANDROID_HOME }
       elseif (Test-Path 'C:\Program Files (x86)\Android\android-sdk') { 'C:\Program Files (x86)\Android\android-sdk' }
       elseif (Test-Path "$env:LOCALAPPDATA\Android\Sdk") { "$env:LOCALAPPDATA\Android\Sdk" }
       else { '' }

if (-not $SDK -or -not (Test-Path $SDK)) {
    Fail @'
找不到 Android SDK。请先安装, 然后设置环境变量 ANDROID_SDK_ROOT:
  sdkmanager "platform-tools" "build-tools;36.0.0" "platforms;android-36"
'@
}

# build-tools: 自动挑版本号最高的一个
$btRoot = Join-Path $SDK 'build-tools'
if (-not (Test-Path $btRoot)) { Fail "SDK 里没有 build-tools 目录: $btRoot" }
$BT = Get-ChildItem $btRoot -Directory |
      Sort-Object { try { [version]($_.Name) } catch { [version]'0.0' } } -Descending |
      Select-Object -First 1 -ExpandProperty FullName
if (-not $BT) { Fail 'build-tools 目录为空' }
Write-Host ("  build-tools: " + (Split-Path -Leaf $BT))

# platforms: 自动挑 API 号最高的 android.jar
$platRoot = Join-Path $SDK 'platforms'
if (-not (Test-Path $platRoot)) { Fail "SDK 里没有 platforms 目录: $platRoot" }
$plat = Get-ChildItem $platRoot -Directory |
        Where-Object { $_.Name -match '^android-(\d+)$' } |
        Sort-Object { [int]($_.Name -replace '\D', '') } -Descending |
        Select-Object -First 1
if (-not $plat) { Fail 'platforms 目录里没有 android-XX' }
$ANDROID = Join-Path $plat.FullName 'android.jar'
Write-Host ("  platform  : " + $plat.Name)

# ---------- 定位 JDK ----------
if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\javac.exe'))) {
    $JDK = $env:JAVA_HOME
} else {
    $jdkRoots = @('C:\Program Files\Java', 'C:\Program Files (x86)\Java',
                  'C:\Program Files\Eclipse Adoptium', 'C:\Program Files\Microsoft') | Where-Object { Test-Path $_ }
    $JDK = $null
    foreach ($r in $jdkRoots) {
        $cand = Get-ChildItem $r -Directory -ErrorAction SilentlyContinue |
                Where-Object { Test-Path (Join-Path $_.FullName 'bin\javac.exe') } |
                Sort-Object Name -Descending | Select-Object -First 1
        if ($cand) { $JDK = $cand.FullName; break }
    }
    if (-not $JDK) { Fail '找不到 JDK。请安装 JDK 17+ 并设置 JAVA_HOME。' }
}
Write-Host ("  JDK       : " + $JDK)

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$SRC  = Join-Path $ROOT 'src'
$RES  = Join-Path $ROOT 'res'
$AST  = Join-Path $ROOT 'assets'
$MF   = Join-Path $ROOT 'AndroidManifest.xml'
$OUT  = Join-Path $ROOT 'build'

$JAVAC    = Join-Path $JDK 'bin\javac.exe'
$KEYTOOL  = Join-Path $JDK 'bin\keytool.exe'
$AAPT2    = Join-Path $BT 'aapt2.exe'
$D8JAR    = Join-Path $BT 'lib\d8.jar'
$APKSIG   = Join-Path $BT 'lib\apksigner.jar'
$ZIPALIGN = Join-Path $BT 'zipalign.exe'
$LAMBDA   = Join-Path $BT 'core-lambda-stubs.jar'

$KS       = Join-Path $ROOT 'debug.keystore'
$KS_PASS  = 'chainblock'
$KS_ALIAS = 'cbkey'

function Step($msg) { Write-Host ''; Write-Host "=== $msg" -ForegroundColor Cyan }
function Check($code, $what) {
    if ($code -ne 0) { Fail "$what 失败 (exit $code)" }
}

# ---------------------------------------------------------------- 环境检查
Step '检查工具链'
foreach ($p in @($JAVAC, $KEYTOOL, $AAPT2, $D8JAR, $APKSIG, $ZIPALIGN, $ANDROID, $LAMBDA)) {
    if (-not (Test-Path $p)) { Fail "缺少: $p" }
    Write-Host "  OK  $p"
}

# ---------------------------------------------------------------- 清理
Step '清理 build 目录'
if (Test-Path $OUT) { Remove-Item $OUT -Recurse -Force }
New-Item -ItemType Directory -Force -Path $OUT | Out-Null
$CLS  = Join-Path $OUT 'classes'
$DEXD = Join-Path $OUT 'dex'
$GEN  = Join-Path $OUT 'gen'
$LINK = Join-Path $OUT 'link'
New-Item -ItemType Directory -Force -Path $CLS, $DEXD, $GEN, $LINK | Out-Null

# ---------------------------------------------------------------- 编译 Java
Step 'javac 编译'
$sources = Get-ChildItem -Path $SRC -Recurse -Filter *.java | ForEach-Object { $_.FullName }
Write-Host ("  源文件: " + $sources.Count + " 个")
& $JAVAC -encoding UTF-8 -source 8 -target 8 `
    -bootclasspath $ANDROID `
    -classpath "$ANDROID;$LAMBDA" `
    -d $CLS @sources
Check $LASTEXITCODE 'javac'

$classFiles = Get-ChildItem -Path $CLS -Recurse -Filter *.class
Write-Host ("  产出 class: " + $classFiles.Count + " 个")
if ($classFiles.Count -eq 0) { Fail 'javac 没有产出 class' }

# ---------------------------------------------------------------- aapt2 compile
Step 'aapt2 compile (资源 -> .flat)'
$flat = Join-Path $OUT 'res.zip'
& $AAPT2 compile --dir $RES -o $flat
Check $LASTEXITCODE 'aapt2 compile'
if (-not (Test-Path $flat)) { Fail '未生成 res.zip' }
Write-Host ("  res.zip: " + (Get-Item $flat).Length + " bytes")

# ---------------------------------------------------------------- aapt2 link
Step 'aapt2 link (生成资源表 + 二进制 manifest)'
$unsigned = Join-Path $OUT 'unsigned.apk'
& $AAPT2 link `
    -o $unsigned `
    --manifest $MF `
    -I $ANDROID `
    -A $AST `
    --java $GEN `
    --min-sdk-version 26 `
    --target-sdk-version 34 `
    $flat
Check $LASTEXITCODE 'aapt2 link'
if (-not (Test-Path $unsigned)) { Fail '未生成 unsigned.apk' }
Write-Host ("  unsigned.apk: " + (Get-Item $unsigned).Length + " bytes")

# ---------------------------------------------------------------- d8
Step 'd8 转 dex'
$classArgFile = Join-Path $OUT 'classes.txt'
$classFiles | ForEach-Object { $_.FullName.Replace('\', '/') } |
    Set-Content -Path $classArgFile -Encoding ascii
Write-Host ("  class 条目: " + (Get-Content $classArgFile).Count)

& (Join-Path $JDK 'bin\java.exe') -cp $D8JAR com.android.tools.r8.D8 `
    --min-api 26 `
    --lib $ANDROID `
    --output $DEXD `
    "@$classArgFile"
Check $LASTEXITCODE 'd8'

$dex = Join-Path $DEXD 'classes.dex'
if (-not (Test-Path $dex)) { Fail 'd8 未产出 classes.dex' }
Write-Host ("  classes.dex: " + (Get-Item $dex).Length + " bytes")

# ---------------------------------------------------------------- 组装 APK
Step '把 classes.dex 放入 APK(STORE 模式, Android 要求)'
$unsigned2 = Join-Path $OUT 'unsigned-withdex.apk'
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
Copy-Item $unsigned $unsigned2 -Force
$zip = [System.IO.Compression.ZipFile]::Open($unsigned2, 'Update')
try {
    # NoCompression == ZIP STORE; classes.dex 必须不压缩存放
    $entry = $zip.CreateEntry('classes.dex', [System.IO.Compression.CompressionLevel]::NoCompression)
    $es = $entry.Open()
    $dexBytes = [System.IO.File]::ReadAllBytes($dex)
    $es.Write($dexBytes, 0, $dexBytes.Length)
    $es.Close()
} finally {
    $zip.Dispose()
}
# 复核
$zip2 = [System.IO.Compression.ZipFile]::OpenRead($unsigned2)
try {
    $e = $zip2.GetEntry('classes.dex')
    if (-not $e) { Fail 'classes.dex 没有写进 APK' }
    Write-Host ("  classes.dex in apk: compressed=$($e.CompressedLength) size=$($e.Length) entries=$($zip2.Entries.Count)")
    if ($e.Length -ne (Get-Item $dex).Length) { Fail 'classes.dex 大小不一致' }
} finally {
    $zip2.Dispose()
}
Write-Host ("  unsigned-withdex.apk: " + (Get-Item $unsigned2).Length + " bytes")

# ---------------------------------------------------------------- zipalign
Step 'zipalign'
$aligned = Join-Path $OUT 'aligned.apk'
& $ZIPALIGN -f -p 4 $unsigned2 $aligned
Check $LASTEXITCODE 'zipalign'
Write-Host ("  aligned.apk: " + (Get-Item $aligned).Length + " bytes")

# ---------------------------------------------------------------- 签名
Step '生成 keystore (如不存在)'
if (-not (Test-Path $KS)) {
    & $KEYTOOL -genkeypair -v `
        -keystore $KS `
        -alias $KS_ALIAS `
        -keyalg RSA -keysize 2048 -validity 10000 `
        -storepass $KS_PASS -keypass $KS_PASS `
        -dname "CN=ChainBlock, OU=Local, O=Local, L=Local, S=Local, C=CN"
    Check $LASTEXITCODE 'keytool'
} else {
    Write-Host '  已存在, 跳过'
}

Step 'apksigner 签名'
$final = Join-Path $OUT 'chainblock.apk'
& (Join-Path $JDK 'bin\java.exe') -jar $APKSIG sign `
    --ks $KS `
    --ks-key-alias $KS_ALIAS `
    --ks-pass "pass:$KS_PASS" `
    --key-pass "pass:$KS_PASS" `
    --v1-signing-enabled true `
    --v2-signing-enabled true `
    --out $final `
    $aligned
Check $LASTEXITCODE 'apksigner sign'

Step '校验签名'
& (Join-Path $JDK 'bin\java.exe') -jar $APKSIG verify --print-certs $final
Check $LASTEXITCODE 'apksigner verify'

Step '完成'
$fi = Get-Item $final
Write-Host ("  APK : " + $fi.FullName)
Write-Host ("  大小: " + [math]::Round($fi.Length / 1KB, 1) + " KB")
Write-Host ''
Write-Host '安装: adb install -r "' + $fi.FullName + '"' -ForegroundColor Green
