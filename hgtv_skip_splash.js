// hgtv_skip_splash.js
// 秒过 5 秒开屏倒计时，自动进入首页
(function () {
  if (typeof $response === "undefined" || !$response || !$response.body) {
    $done({});
    return;
  }
  const body = $response.body.replace(
    "P.value=5,j.value=!0,oe()",
    "P.value=0,j.value=!0,oe(),pe()"
  );
  $done({ body });
})();
