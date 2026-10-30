// 糖心 Vlog Loon 脚本 (双兼容修复版)
// 优先使用 Loon 原生请求 URL 替换（零内存拷贝、直接复用系统二进制管道与代理策略）；
// 若回退到 $httpClient，也完整保留 binary-mode。
var url = $request.url;
var match = url.match(/^https?:\/\/([^/?#]+)(\/[^?#]*)?(\?.*)?/);

if (match) {
  // 剥离 www. 等子域名，只保留 tx*.com 裸域名，防止公益接口返回 HTTP 530
  var bareHost = match[1].replace(/^[a-z0-9-]+\.(?=tx\w+\.com$)/i, "");
  var targetUrl = "https://txscript.pages.dev/tx/" + bareHost + (match[2] || "") + (match[3] || "");
  var headers = {};
  var orig = $request.headers || {};
  for (var k in orig) {
    var lk = k.toLowerCase();
    if (lk !== "host" && lk !== ":authority") {
      headers[k] = orig[k];
    }
  }
  headers["Host"] = "txscript.pages.dev";

  console.log("[TX-Unlock] Forwarding: " + url + " -> " + targetUrl);

  // 直接让 Loon 核心层将当前请求的目标 URL 和 Host 改写为 txscript.pages.dev
  // 这样请求 Body 和响应 Body 全程走 Loon 底层 TCP/TLS 二进制流，不会被 JS $done({response}) 转换字符串损坏！
  $done({
    url: targetUrl,
    headers: headers
  });
} else {
  $done({});
}
