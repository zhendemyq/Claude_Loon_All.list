// hgtv_skip_splash.js
// 前端路由层双重加固：秒过 5 秒开屏倒计时 + 前端层直接短路广告拉取与系统公告弹窗
(function () {
  if (typeof $response === "undefined" || !$response || !$response.body) {
    $done({});
    return;
  }
  var body = $response.body;
  // 1. 将 SplashView 中的 5 秒倒计时改为 0 秒并自动执行跳过进入首页
  body = body.replace(
    "P.value=5,j.value=!0,oe()",
    "P.value=0,j.value=!0,oe(),setTimeout(pe,30)"
  );
  // 2. 前端层直接将 /api/ad/query 缓存置为空对象
  body = body.replace(
    "function Ut(){return Bt?Promise.resolve(Bt):",
    "function Ut(){return Promise.resolve({});"
  );
  // 3. 前端层禁用 sys_notice 系统公告弹窗读取
  body = body.replace(
    'He("sys_notice",',
    'He("__disabled_notice__",'
  );
  $done({ body: body });
})();
