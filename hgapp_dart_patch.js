/**
 * hgapp_dart_patch.js — 黄果短剧 Flutter Web 客户端补丁
 *
 * 作用（对 p15.udcdftpb.cc 等资源域名生效）：
 *   1. main.dart.js：
 *      - 试看 15 秒硬编码破解：bundle 中 4 处 "15e6" 微秒常量
 *        （e5T 试看结束判定、e5S 试看倒计时、a8z 15 秒定时器、B.lW 默认试看时长）
 *        全部改为 9e15（约 28.5 万年），试看限制实际失效；
 *      - "试看 Xs" 角标函数 e5S 直接返回 null，不再显示倒计时角标。
 *   2. flutter_service_worker.js：返回空脚本 —— 禁用 Service Worker 缓存，
 *      防止应用用缓存的旧 main.dart.js 绕过补丁（也保证 API 清洗器始终能拿到真实请求）。
 *   3. version.json：返回固定新版本号，强制 Flutter SW 走更新流程重新拉取资源。
 */

(function () {
  if (typeof $response === "undefined" || !$response) {
    $done({});
    return;
  }
  var url = (typeof $request !== "undefined" && $request && $request.url) ? String($request.url) : "";

  // 1. 禁用 Service Worker（返回空脚本即可使注册失效）
  if (/flutter_service_worker\.js/i.test(url)) {
    $done({ body: "// service worker disabled by loon adblock" });
    return;
  }

  // 2. version.json 改版本号，促使 SW 判定有更新
  if (/version\.json/i.test(url)) {
    $done({ body: JSON.stringify({ version: "loon-hg-adblock-v6" }) });
    return;
  }

  // 3. main.dart.js 补丁
  if (/main\.dart\.js/i.test(url)) {
    if (!$response.body) { $done({}); return; }
    var b = $response.body;
    var origLen = b.length;

    function count(h, n) { return h.split(n).length - 1; }

    var c1 = count(b, "15e6");
    b = b.split("15e6").join("9e15");

    var trialLabel = 'return"\\u8bd5\\u770b "+B.f.eE(r/1000)+"s"';
    var c2 = count(b, trialLabel);
    // return"\u8bd5..." -> return null&&"\u8bd5..." （null && X 恒为 null，角标不再显示）
    b = b.split(trialLabel).join('return null&&' + trialLabel.slice(6));

    console.log("[hgdart] 15e6替换:" + c1 + " 试看角标替换:" + c2 + " 大小:" + origLen + "->" + b.length);
    $done({ body: b });
    return;
  }

  $done({});
})();
