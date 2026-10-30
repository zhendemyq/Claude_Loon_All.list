// 糖心 Vlog Loon 307 重定向脚本
// 为什么用 307 重定向？
// 1. Loon 的 http-request $done({ response: { body: Uint8Array } }) 不支持二进制响应体，会损坏 AES+Gzip 密文；
// 2. Loon 的 Rewrite url.replace 在 POST 请求上不会重新进行 DNS 路由，而是把请求发往原域名 IP (CloudFront)，导致 CloudFront 报 403 -> 客户端显示“系统初始化失败”；
// 3. 返回 HTTP 307 + CORS 头，让客户端（浏览器/App）自己保持 POST 方法和原始二进制加密 Body 直接向 https://txscript.pages.dev/tx/... 发起请求，100% 走正确的 DNS/代理分流且零二进制损坏！

var url = $request.url;
var method = ($request.method || "POST").toUpperCase();

if (method === "OPTIONS") {
  $done({
    response: {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400"
      },
      body: ""
    }
  });
} else {
  var match = url.match(/^https?:\/\/([^/?#]+)(\/[^?#]*)?(\?.*)?/);
  if (match) {
    // 剥离 www. 等子域名，只保留 tx*.com 裸域名，防止公益接口返回 HTTP 530
    var bareHost = match[1].replace(/^[a-z0-9-]+\.(?=tx\w+\.com$)/i, "");
    var targetUrl = "https://txscript.pages.dev/tx/" + bareHost + (match[2] || "") + (match[3] || "");
    $done({
      response: {
        status: 307,
        headers: {
          "Location": targetUrl,
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Cache-Control": "no-store"
        },
        body: ""
      }
    });
  } else {
    $done({});
  }
}
