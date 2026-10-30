// 糖心 Vlog Loon 脚本 (Request 缓存 + Response 二进制替换终极版)
// 为什么必须用 http-request + http-response 配合？
// 1. Loon 官方文档 (Script API 11.4 vs 11.5) 明确规定：
//    - http-request 的 $done({ response: { body } }) 只支持字符串，传入 Uint8Array 会损坏 AES+Gzip 二进制密文；
//    - 只有 http-response 的 $done({ status, headers, body }) 原生支持 Uint8Array 二进制响应体，且由 Loon 自动重算 Content-Length！
// 2. Loon 的 [Rewrite] url.replace 在 HTTPS POST 请求上不会重新进行 DNS 路由，会将 txscript.pages.dev 的 Host 发往原站 CloudFront IP 导致 403（系统初始化失败）。
// 3. iOS Safari/WebKit 在收到 307 跨域重定向时会剥离自定义请求头 (requestId/sign)，导致无法派生 AES 密钥。
// 因此：在 http-request 阶段仅缓存加密请求体并原样放行 ($done({}))，在 http-response 阶段通过 $httpClient 请求公益接口并用原生 Uint8Array 替换响应体！

function bytesToHex(u8) {
  if (!u8 || !u8.length) return "";
  var hex = [];
  for (var i = 0; i < u8.length; i++) {
    var b = u8[i] & 0xff;
    hex.push((b < 16 ? "0" : "") + b.toString(16));
  }
  return hex.join("");
}

function hexToBytes(hex) {
  if (!hex || typeof hex !== "string" || hex.length % 2 !== 0) return null;
  var len = hex.length / 2;
  var u8 = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    u8[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return u8;
}

function getHeader(headers, name) {
  if (!headers) return "";
  var target = name.toLowerCase();
  for (var k in headers) {
    if (String(k).toLowerCase() === target) {
      return String(headers[k] || "");
    }
  }
  return "";
}

var url = $request.url || "";
var match = url.match(/^https?:\/\/([^/?#]+)(\/[^?#]*)?(\?.*)?/);
var reqId = getHeader($request.headers, "requestId") || "default";
var storeKey = "tx_req_" + reqId;

if (!match) {
  $done({});
} else if (typeof $response === "undefined") {
  // 阶段 1：http-request 阶段 —— 缓存二进制请求体，原样放行请求到原站（保证 100% 不报“系统初始化失败”）
  if ($request.body && $request.body.length > 0) {
    $persistentStore.write(bytesToHex($request.body), storeKey);
  }
  $done({});
} else {
  // 阶段 2：http-response 阶段 —— 读取二进制请求体并转发至公益接口，拿到解锁后的 Uint8Array 替换响应体
  var reqBody = null;
  var savedHex = $persistentStore.read(storeKey);
  if (savedHex) {
    $persistentStore.write(undefined, storeKey);
    reqBody = hexToBytes(savedHex);
  }
  if (!reqBody && $request.body && $request.body.length > 0) {
    reqBody = $request.body;
  }

  // 剥离 www. 等子域名，只保留 tx*.com 裸域名，防止公益接口返回 HTTP 530
  var bareHost = match[1].replace(/^[a-z0-9-]+\.(?=tx\w+\.com$)/i, "");
  var targetUrl = "https://txscript.pages.dev/tx/" + bareHost + (match[2] || "") + (match[3] || "");

  var headers = {};
  var orig = $request.headers || {};
  for (var k in orig) {
    var lk = String(k).toLowerCase();
    // 过滤 HTTP/2 伪首部 (:authority, :method, :path, :scheme) 及冲突首部
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

  if (reqBody) {
    options.body = reqBody;
  }

  $httpClient.post(options, function (error, response, data) {
    if (error || !response || response.status !== 200 || !data || !data.length) {
      console.log("[TX-Unlock] Fallback to origin response: " + String(error || (response && response.status)));
      $done({});
      return;
    }

    var respHeaders = {};
    var origRespHeaders = $response.headers || {};
    for (var hk in origRespHeaders) {
      var lhk = String(hk).toLowerCase();
      if (
        lhk.charAt(0) === ":" ||
        lhk === "content-length" ||
        lhk === "content-encoding" ||
        lhk === "transfer-encoding" ||
        lhk === "alt-svc"
      ) {
        continue;
      }
      respHeaders[hk] = origRespHeaders[hk];
    }

    // Loon http-response 原生支持 body: Uint8Array，并自动处理 Content-Length
    $done({
      status: 200,
      headers: respHeaders,
      body: data
    });
  });
}
