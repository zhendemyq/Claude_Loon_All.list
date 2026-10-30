// 糖心 Vlog Loon 脚本 (修复版)
// 插件配置: requires-body=true, binary-body-mode=true
// 1. 通过 $httpClient 在 Loon 内部同源转发二进制请求体与响应体（避免 Safari/WebKit 在 307 跨域重定向时丢弃 requestId/sign 等自定义头）
// 2. 彻底过滤 HTTP/2 伪首部 (:authority/:path/:method/:scheme) 及 Host/Origin/Referer，并指定 alpn: "h1" 避免 Cloudflare 报 400/403
// 3. 剥离响应中的 alt-svc 头，防止浏览器升级到 HTTP/3 (QUIC) 绕过 Loon MITM
// 4. 剥离 www. 等子域名防止 txscript.pages.dev 返回 HTTP 530；异常时调用 $done({}) 放行原请求，避免“系统初始化失败”

var url = $request.url;
var method = ($request.method || "POST").toLowerCase();
var match = url.match(/^https?:\/\/([^/?#]+)(\/[^?#]*)?(\?.*)?/);

if (!match || method === "options") {
  $done({});
} else {
  // 剥离 www. 等子域名，只保留 tx*.com 裸域名，防止公益接口返回 HTTP 530
  var bareHost = match[1].replace(/^[a-z0-9-]+\.(?=tx\w+\.com$)/i, "");
  var targetUrl = "https://txscript.pages.dev/tx/" + bareHost + (match[2] || "") + (match[3] || "");

  var headers = {};
  var orig = $request.headers || {};
  for (var k in orig) {
    if (!Object.prototype.hasOwnProperty.call(orig, k)) continue;
    var lk = k.toLowerCase();
    // 过滤所有 HTTP/2 伪头 (:authority, :method, :path, :scheme) 以及会导致冲突的头
    if (
      lk.charAt(0) === ":" ||
      lk === "host" ||
      lk === "content-length" ||
      lk === "accept-encoding" ||
      lk === "origin" ||
      lk === "referer" ||
      lk === "connection"
    ) {
      continue;
    }
    headers[k] = orig[k];
  }

  var options = {
    url: targetUrl,
    headers: headers,
    timeout: 15000,
    alpn: "h1",
    "binary-mode": true
  };

  if ($request.body) {
    options.body = $request.body;
  }

  var fn = $httpClient[method] || $httpClient.post;
  fn.call($httpClient, options, function (error, response, data) {
    if (error || !response || (response.status && response.status >= 500) || !data) {
      console.log("[TX-Unlock] Fallback to origin due to error: " + String(error || (response && response.status)));
      $done({});
      return;
    }

    var code = response.status || 200;
    var outHeaders = {
      "Content-Type": "application/octet-stream",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Expose-Headers": "*",
      "Cache-Control": "no-store"
    };

    $done({
      response: {
        status: code,
        headers: outHeaders,
        body: data
      }
    });
  });
}
