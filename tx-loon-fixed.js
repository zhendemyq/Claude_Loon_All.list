// 糖心 Vlog Loon 脚本 (修复版)
// 插件配置: requires-body=true, binary-body-mode=true
// $request.body 为 Uint8Array，无 UTF-8 解码问题
var url = $request.url;
var method = ($request.method || "GET").toLowerCase();
var match = url.match(/^https?:\/\/([^/?#]+)(\/[^?#]*)?(\?.*)?/);

if (match) {
  // 去除开头的子域名（如 www.），只保留 tx*.com 裸域名，防止公益接口返回 HTTP 530
  var bareHost = match[1].replace(/^[a-z0-9-]+\.(?=tx\w+\.com$)/i, "");
  var targetUrl = "https://txscript.pages.dev/tx/" + bareHost + (match[2] || "") + (match[3] || "");
  var headers = {};
  var orig = $request.headers || {};
  for (var k in orig) {
    var lk = k.toLowerCase();
    if (lk !== "host" && lk !== "content-length") {
      headers[k] = orig[k];
    }
  }

  var options = {
    url: targetUrl,
    headers: headers,
    timeout: 15000,
    "binary-mode": true,
  };

  // binary-body-mode=true → $request.body 是 Uint8Array
  if ($request.body) options.body = $request.body;

  $httpClient[method](options, function (error, response, data) {
    if (error) {
      $done({ response: { status: 502, body: String(error) } });
      return;
    }
    var resp = response || {};
    var code = resp.status || 200;
    var h = resp.headers || {};
    var out = {};
    for (var k in h) {
      if (!/^(content-encoding|content-length|transfer-encoding)$/i.test(k)) out[k] = h[k];
    }
    // binary-mode=true → data 是 Uint8Array
    $done({ response: { status: code, headers: out, body: data } });
  });
} else {
  $done({});
}
