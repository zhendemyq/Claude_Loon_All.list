// hgtv_adblock.js
// 黄果短剧去广告与公告脚本（仅清理全站9类广告位与系统公告弹窗，不影响免费视频正常播放）

const EMPTY_OBJ_CIPHER = "jIY1j26vNjsdMuRZijJHvQ==";
// {"route":"/api/ad/query","request":{}} 的固定 AES-256-CBC 密文
const AD_QUERY_REQ_CIPHER = "D6BNvw0q8CO5bWGSda8L1IWJ7635jVTpYFkvjKeScIfqNk5KDcau5fywUGI6559C";
// {"route":"/api/ad/event",...} 的固定密文前缀
const AD_EVENT_REQ_PREFIX = "D6BNvw0q8CO5bWGSda8L1IA5oRJHrrCF";

(function () {
  if (typeof $response === "undefined" || !$response || !$response.body) {
    $done({});
    return;
  }

  try {
    const reqBody = (typeof $request !== "undefined" && $request && $request.body) ? $request.body : "";

    // 1. 匹配 /api/ad/query 或 /api/ad/event，直接返回空对象 {} 的密文
    if (reqBody.indexOf(AD_QUERY_REQ_CIPHER) !== -1 || reqBody.indexOf(AD_EVENT_REQ_PREFIX) !== -1) {
      $done({
        body: JSON.stringify({
          code: 0,
          message: "success",
          data: EMPTY_OBJ_CIPHER
        })
      });
      return;
    }

    // 2. 利用 Loon 内置 CryptoJS 解密响应，清空 /api/ad/query 与 /api/app/config 中的公告弹窗
    if (typeof CryptoJS !== "undefined") {
      const resJson = JSON.parse($response.body);
      if (resJson && typeof resJson.data === "string" && resJson.data.length > 0) {
        const key = CryptoJS.enc.Utf8.parse("35c54740fbb6c4ae2f8ef636cad562da");
        const iv = CryptoJS.enc.Utf8.parse("17eaad145654932c");

        const decrypted = CryptoJS.AES.decrypt(resJson.data, key, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }).toString(CryptoJS.enc.Utf8);

        if (decrypted) {
          // 兜底识别 /api/ad/query 响应结构 {"1":[...],"2":[...]}
          if (/^\{\s*"[0-9]+"\s*:\s*\[/.test(decrypted)) {
            resJson.data = EMPTY_OBJ_CIPHER;
            $done({ body: JSON.stringify(resJson) });
            return;
          }

          // 识别 /api/app/config 响应并清空系统公告弹窗与新客弹窗
          if (decrypted.indexOf('"sys_notice"') !== -1) {
            const cfg = JSON.parse(decrypted);
            if (cfg && cfg.extra) {
              cfg.extra.sys_notice = "";
              cfg.extra.temp_new_user_vip_ad = "off";
            }
            resJson.data = CryptoJS.AES.encrypt(JSON.stringify(cfg), key, {
              iv: iv,
              mode: CryptoJS.mode.CBC,
              padding: CryptoJS.pad.Pkcs7
            }).toString();
            $done({ body: JSON.stringify(resJson) });
            return;
          }
        }
      }
    }
  } catch (e) {}

  $done({});
})();
