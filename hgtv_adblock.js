// hgtv_adblock.js
// 黄果短剧全量去广告与纯净播放脚本
// 支持 Loon / Surge / Quantumult X

const EMPTY_OBJ_CIPHER = "jIY1j26vNjsdMuRZijJHvQ==";

(function () {
  if (typeof $response === "undefined" || !$response || !$response.body) {
    $done({});
    return;
  }

  try {
    const url = (typeof $request !== "undefined" && $request && $request.url) ? $request.url : "";
    const reqBody = (typeof $request !== "undefined" && $request && $request.body) ? $request.body : "";

    // 1. 如果请求体包含 ad/query，无论是否加解密直接命中并返回空密文
    if (reqBody.indexOf("/api/ad/query") !== -1 ||
        reqBody.indexOf("D6BNvw0q8CO5bWGSda8L1IWJ7635jVTpYFkvjKeScIfqNk5KDcau5fywUGI6559C") !== -1 ||
        reqBody.indexOf("D6BNvw0q8CO5bWGSda8L1IA5oRJHrrCF") !== -1) {
      $done({
        body: JSON.stringify({
          code: 0,
          message: "success",
          data: EMPTY_OBJ_CIPHER
        })
      });
      return;
    }

    // 2. 解密响应体做深度清洗
    if (typeof CryptoJS !== "undefined") {
      let resJson = null;
      try {
        resJson = JSON.parse($response.body);
      } catch (e) {}

      if (resJson && typeof resJson.data === "string" && resJson.data.length > 0) {
        const key = CryptoJS.enc.Utf8.parse("35c54740fbb6c4ae2f8ef636cad562da");
        const iv = CryptoJS.enc.Utf8.parse("17eaad145654932c");

        const decrypted = CryptoJS.AES.decrypt(resJson.data, key, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }).toString(CryptoJS.enc.Utf8);

        if (decrypted) {
          // A. 如果是 /api/ad/query 返回的广告位数据（特征：包含数字键值数组如 {"1":[...]}）
          if (/^\{\s*"[0-9]+"\s*:\s*\[/.test(decrypted) || decrypted.indexOf('"position"') !== -1) {
            resJson.data = EMPTY_OBJ_CIPHER;
            $done({ body: JSON.stringify(resJson) });
            return;
          }

          // B. 清除 /api/app/config 中的系统公告、新用户广告
          if (decrypted.indexOf('"sys_notice"') !== -1 || decrypted.indexOf('"temp_new_user_vip_ad"') !== -1) {
            try {
              const cfg = JSON.parse(decrypted);
              if (cfg && cfg.extra) {
                cfg.extra.sys_notice = "";
                cfg.extra.temp_new_user_vip_ad = "off";
                cfg.extra.official_post_text = "";
              }
              resJson.data = CryptoJS.AES.encrypt(JSON.stringify(cfg), key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
              }).toString();
              $done({ body: JSON.stringify(resJson) });
              return;
            } catch (err) {}
          }
        }
      }
    }
  } catch (globalErr) {}

  $done({});
})();
