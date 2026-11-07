/**
 * hgweb_adblock.js
 * huangguoai.com 网页版去广告（服务端渲染站点）
 *
 * 站点广告结构（实测自线上页面与抓包）：
 *   1. 页面里散布 10 个空广告位：<aside class="hg-ssp-slot" data-ssp-slot-key="..." aria-label="推广"></aside>
 *      槽位名：icon_player_top_main_001 / icon_player_overlay_pause_001 /
 *              icon_video_detail_overlay_card_001 / icon_video_detail_inline_main_001 /
 *              banner_home_center_card_001 / banner_video_detail_overlay_card_001 /
 *              feed_feed_top_main_001
 *   2. 由 /static/web/js/lib/ssp-core-v0.0.4-*.js + /static/web/js/ssp-mount.js 动态填充
 *   3. 广告素材/配置来自第三方网络 api-ad3/4/5.adsdk*.cc，且 SDK 会把配置缓存到本地
 *      （ssp-cache-scope.js，cacheScope 形如 v1-xxxx）
 *
 * 本脚本做两件事（配合规则层封锁 SDK 脚本与广告网络）：
 *   A. 注入 CSS 把广告位彻底折叠（槽位行内写了 min-height，必须 !important 才压得住）
 *   B. 移除 data-ssp-slot-key 属性（ssp-mount 靠它找挂载点），并清理 SDK 的本地缓存
 */

(function () {
  var url = (typeof $request !== "undefined" && $request && $request.url) ? String($request.url) : "";
  var body = (typeof $response !== "undefined" && $response && $response.body) ? String($response.body) : "";

  // ---- 非 HTML 或非目标站点：直接放行 ----
  if (!body || !/huangguoai\.(com|cc|app)/i.test(url)) { $done({}); return; }
  // 已经处理过（幂等）：避免重复注入
  if (body.indexOf('id="hg-adkill"') !== -1) { $done({}); return; }
  if (body.indexOf("hg-ssp-slot") === -1 && body.indexOf("data-ssp-slot-key") === -1) {
    $done({});
    return;
  }

  try {
    var out = body;

    // ---- A. 折叠广告位（含 SDK 可能创建的悬浮/暂停容器）----
    var CSS = '<style id="hg-adkill">' +
      '.hg-ssp-slot,[data-ssp-slot-key],[data-ssp-floating-container],[data-ssp-pause],' +
      '[data-ssp-grid-item],.hg-ssp-floating,.hg-ssp-pause__card{' +
      'display:none!important;min-height:0!important;height:0!important;' +
      'margin:0!important;padding:0!important;overflow:hidden!important}' +
      '</style>';

    var INJECT = CSS +
      '<script>(function(){try{' +
      // 清理 SDK 缓存的广告配置（只匹配明确的广告键，避免误删用户数据）
      'var pat=/ssp|adsdk|dx-150|ad_?cache|advert|\\u5e7f\\u544a/i;' +
      'var purge=function(st){try{Object.keys(st).forEach(function(k){if(pat.test(k))st.removeItem(k)})}catch(e){}};' +
      'purge(window.localStorage);purge(window.sessionStorage);' +
      // 若 SDK 已在运行，清掉可能存在的定时重挂
      'if(window.__hgSsp){window.__hgSsp=null}' +
      '}catch(e){}})();</script>';

    // 注入到 </head> 之前；没有 head 则插到 <body> 之后
    if (out.indexOf("</head>") !== -1) {
      out = out.replace("</head>", INJECT + "</head>");
    } else {
      out = out.replace(/<body([^>]*)>/i, "<body$1>" + INJECT);
    }

    // ---- B. 移除广告位挂载属性，让 ssp-mount 找不到挂载点 ----
    out = out.replace(/\s*data-ssp-slot-key="[^"]*"/g, "");
    // 悬浮/暂停容器保留节点但去掉标记，CSS 已折叠
    out = out.replace(/\s*data-ssp-floating(-container)?(="[^"]*")?/g, "");
    out = out.replace(/\s*data-ssp-pause(-target)?(="[^"]*")?/g, "");

    $done({ body: out });
  } catch (e) {
    $done({});
  }
})();
