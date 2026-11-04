/**
 * 黄豆短剧 (NP7架构) Loon 专用解锁脚本 (100% 纯 JS 本地 AES-192-CBC 引擎 + 跨接口正片流缓存)
 * 逆向实测参数：
 *   - 响应体加密: AES-192-CBC (PKCS7 Padding)
 *   - Key: "KivItun6MHYOU55hlQECIa==" (24字节)
 *   - IV : "efa3s7w8fbe3jae2" (16字节)
 * 核心机制：
 *   1. 拦截动态 MD5 混淆路径的响应体，纯 JS 解密 AES-192-CBC Base64 密文。
 *   2. 注入永久 VIP 身份与全部 vipPerks[0..20] 权限码 (含 VIP_SHORT_VIDEO=11, SHORT_DRAMA=16, VIP_VIDEO=3, DARK_NET=6)。
 *   3. 自动提取 /video/shortList/v2 与 /video/shortDrama/list/v2 中泄露的完整版正片 M3U8 (videoLink)，
 *      覆盖 previewVideoLink 并写入 $persistentStore 缓存；当单集详情接口 /video/detail 抹空 videoLink 时自动从缓存回填正片流。
 */

var SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);
// Fix SBOX length check (0xbc at index 120)
SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);
var INV_SBOX = new Uint8Array(256);
for (var _i = 0; _i < 256; _i++) INV_SBOX[SBOX[_i]] = _i;
var RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function xtime(a) { return ((a << 1) ^ (((a >> 7) & 1) * 0x1b)) & 0xff; }
function mul(a, b) {
  var res = 0;
  for (var i = 0; i < 8; i++) {
    if (b & 1) res ^= a;
    a = xtime(a);
    b >>= 1;
  }
  return res;
}

function expandKey(keyBytes) {
  var Nk = keyBytes.length / 4;
  var Nr = Nk + 6;
  var Nb = 4;
  var w = new Array(Nb * (Nr + 1));
  for (var i = 0; i < Nk; i++) {
    w[i] = [keyBytes[4*i], keyBytes[4*i+1], keyBytes[4*i+2], keyBytes[4*i+3]];
  }
  for (var j = Nk; j < Nb * (Nr + 1); j++) {
    var temp = w[j - 1].slice();
    if (j % Nk === 0) {
      temp = [SBOX[temp[1]] ^ RCON[j / Nk], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]];
    } else if (Nk > 6 && j % Nk === 4) {
      temp = [SBOX[temp[0]], SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]]];
    }
    w[j] = [w[j-Nk][0]^temp[0], w[j-Nk][1]^temp[1], w[j-Nk][2]^temp[2], w[j-Nk][3]^temp[3]];
  }
  return { w: w, Nr: Nr };
}

function addRoundKey(s, w, round) {
  for (var c = 0; c < 4; c++) {
    for (var r = 0; r < 4; r++) s[r + 4*c] ^= w[round*4 + c][r];
  }
}

function encryptBlock(block, w, Nr) {
  var s = new Uint8Array(block);
  addRoundKey(s, w, 0);
  for (var round = 1; round < Nr; round++) {
    for (var i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    var t = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
    for (var c = 0; c < 4; c++) {
      var idx = 4*c;
      var a0=s[idx], a1=s[idx+1], a2=s[idx+2], a3=s[idx+3];
      s[idx]   = mul(a0,2)^mul(a1,3)^a2^a3;
      s[idx+1] = a0^mul(a1,2)^mul(a2,3)^a3;
      s[idx+2] = a0^a1^mul(a2,2)^mul(a3,3);
      s[idx+3] = mul(a0,3)^a1^a2^mul(a3,2);
    }
    addRoundKey(s, w, round);
  }
  for (var k = 0; k < 16; k++) s[k] = SBOX[s[k]];
  var t2 = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t2;
  t2=s[2]; s[2]=s[10]; s[10]=t2; t2=s[6]; s[6]=s[14]; s[14]=t2;
  t2=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t2;
  addRoundKey(s, w, Nr);
  return s;
}

function decryptBlock(block, w, Nr) {
  var s = new Uint8Array(block);
  addRoundKey(s, w, Nr);
  for (var round = Nr - 1; round >= 1; round--) {
    var t = s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
    for (var i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
    addRoundKey(s, w, round);
    for (var c = 0; c < 4; c++) {
      var idx = 4*c;
      var a0=s[idx], a1=s[idx+1], a2=s[idx+2], a3=s[idx+3];
      s[idx]   = mul(a0,0x0e)^mul(a1,0x0b)^mul(a2,0x0d)^mul(a3,0x09);
      s[idx+1] = mul(a0,0x09)^mul(a1,0x0e)^mul(a2,0x0b)^mul(a3,0x0d);
      s[idx+2] = mul(a0,0x0d)^mul(a1,0x09)^mul(a2,0x0e)^mul(a3,0x0b);
      s[idx+3] = mul(a0,0x0b)^mul(a1,0x0d)^mul(a2,0x09)^mul(a3,0x0e);
    }
  }
  var t2 = s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t2;
  t2=s[2]; s[2]=s[10]; s[10]=t2; t2=s[6]; s[6]=s[14]; s[14]=t2;
  t2=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t2;
  for (var k = 0; k < 16; k++) s[k] = INV_SBOX[s[k]];
  addRoundKey(s, w, 0);
  return s;
}

function strToUtf8Bytes(str) {
  var utf8 = unescape(encodeURIComponent(str));
  var arr = new Uint8Array(utf8.length);
  for (var i = 0; i < utf8.length; i++) arr[i] = utf8.charCodeAt(i);
  return arr;
}

function utf8BytesToStr(bytes) {
  var chunk = 8192;
  var bin = "";
  for (var i = 0; i < bytes.length; i += chunk) {
    var sub = bytes.subarray(i, Math.min(i + chunk, bytes.length));
    for (var j = 0; j < sub.length; j++) bin += String.fromCharCode(sub[j]);
  }
  return decodeURIComponent(escape(bin));
}

var B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64ToBytes(b64) {
  b64 = b64.replace(/[^A-Za-z0-9+/]/g, "");
  var len = b64.length;
  var out = new Uint8Array(Math.floor(len * 3 / 4));
  var p = 0;
  for (var i = 0; i < len; i += 4) {
    var c1 = B64_CHARS.indexOf(b64[i]);
    var c2 = B64_CHARS.indexOf(b64[i+1]);
    var c3 = i + 2 < len ? B64_CHARS.indexOf(b64[i+2]) : -1;
    var c4 = i + 3 < len ? B64_CHARS.indexOf(b64[i+3]) : -1;
    out[p++] = (c1 << 2) | (c2 >> 4);
    if (c3 !== -1) out[p++] = ((c2 & 15) << 4) | (c3 >> 2);
    if (c4 !== -1) out[p++] = ((c3 & 3) << 6) | c4;
  }
  return out.subarray(0, p);
}

function bytesToB64(bytes) {
  var res = "";
  for (var i = 0; i < bytes.length; i += 3) {
    var b1 = bytes[i];
    var b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    var b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    res += B64_CHARS[b1 >> 2];
    res += B64_CHARS[((b1 & 3) << 4) | (b2 >> 4)];
    res += i + 1 < bytes.length ? B64_CHARS[((b2 & 15) << 2) | (b3 >> 6)] : "=";
    res += i + 2 < bytes.length ? B64_CHARS[b3 & 63] : "=";
  }
  return res;
}

var KEY_BYTES = strToUtf8Bytes("KivItun6MHYOU55hlQECIa==");
var IV_BYTES = strToUtf8Bytes("efa3s7w8fbe3jae2");
var EXP = expandKey(KEY_BYTES);
var EXP_KEY = EXP.w;
var NR = EXP.Nr;

function decryptAES(b64) {
  var data = b64ToBytes(b64.trim());
  if (!data.length || data.length % 16 !== 0) return null;
  var out = new Uint8Array(data.length);
  var prev = IV_BYTES;
  for (var i = 0; i < data.length; i += 16) {
    var chunk = data.subarray(i, i + 16);
    var dec = decryptBlock(chunk, EXP_KEY, NR);
    for (var j = 0; j < 16; j++) out[i + j] = dec[j] ^ prev[j];
    prev = chunk;
  }
  var pad = out[out.length - 1];
  if (pad < 1 || pad > 16) return null;
  return utf8BytesToStr(out.subarray(0, out.length - pad));
}

function encryptAES(str) {
  var raw = strToUtf8Bytes(str);
  var pad = 16 - (raw.length % 16);
  var padded = new Uint8Array(raw.length + pad);
  padded.set(raw);
  for (var p = raw.length; p < padded.length; p++) padded[p] = pad;
  var out = new Uint8Array(padded.length);
  var prev = IV_BYTES;
  for (var i = 0; i < padded.length; i += 16) {
    var block = new Uint8Array(16);
    for (var j = 0; j < 16; j++) block[j] = padded[i + j] ^ prev[j];
    var enc = encryptBlock(block, EXP_KEY, NR);
    out.set(enc, i);
    prev = enc;
  }
  return bytesToB64(out);
}

var STORE_KEY = "hd_drama_url_cache_v1";
function loadUrlCache() {
  try {
    if (typeof $persistentStore !== "undefined") {
      var raw = $persistentStore.read(STORE_KEY);
      if (raw) return JSON.parse(raw);
    }
  } catch (e) {}
  return {};
}

function saveUrlCache(cache) {
  try {
    if (typeof $persistentStore !== "undefined") {
      var keys = Object.keys(cache);
      if (keys.length > 300) {
        var trimmed = {};
        for (var i = keys.length - 200; i < keys.length; i++) {
          trimmed[keys[i]] = cache[keys[i]];
        }
        cache = trimmed;
      }
      $persistentStore.write(JSON.stringify(cache), STORE_KEY);
    }
  } catch (e) {}
}

function patchVideoItem(item, cache, state) {
  if (!item || typeof item !== "object") return;
  item.buyFlag = 1;
  item.isFree = 1;
  item.chargeAmount = 0;
  item.lastVerify = false;
  var vid = item.id ? String(item.id) : "";
  if (item.playInfo && Array.isArray(item.playInfo.playUrl)) {
    for (var i = 0; i < item.playInfo.playUrl.length; i++) {
      var u = item.playInfo.playUrl[i];
      if (u.videoLink && u.videoLink !== "") {
        u.previewVideoLink = u.videoLink;
        if (vid && i === 0) {
          cache[vid] = u.videoLink;
          state.dirty = true;
        }
      } else if (vid && cache[vid]) {
        u.videoLink = cache[vid];
        u.previewVideoLink = cache[vid];
      } else if (u.previewVideoLink && !u.videoLink) {
        u.videoLink = u.previewVideoLink;
      }
    }
  }
}

var body = $response.body;
if (body && typeof body === "string" && body.length > 20 && body.trim().charAt(0) !== "{") {
  try {
    var decStr = decryptAES(body);
    if (decStr) {
      var obj = JSON.parse(decStr);
      if (obj && obj.data) {
        var d = obj.data;
        var cache = loadUrlCache();
        var state = { dirty: false };

        // 1. 用户信息接口 (/user/userInfo, /user/userInfo/new, /user/guest/register)
        if ("isVip" in d || "vipLevel" in d || "vipPerks" in d) {
          d.isVip = true;
          d.vipLevel = 4;
          d.vipId = 4;
          d.vipName = "永久一卡通";
          d.validityDate = "2099-12-31 23:59:59";
          d.validityDays = 9999;
          d.remainDownloadCount = 9999;
          d.totalCoin = "999999";
          d.vipPerks = d.vipPerks || {};
          for (var code = 0; code <= 20; code++) {
            d.vipPerks[code] = { permissions: true, code: code };
          }
        }

        // 2. 短剧/视频列表与详情接口
        if (Array.isArray(d.list)) {
          for (var i = 0; i < d.list.length; i++) {
            var item = d.list[i];
            patchVideoItem(item, cache, state);
            if (Array.isArray(item.videoList)) {
              for (var j = 0; j < item.videoList.length; j++) {
                patchVideoItem(item.videoList[j], cache, state);
              }
            }
          }
        } else if (d.playInfo) {
          patchVideoItem(d, cache, state);
        }

        if (state.dirty) saveUrlCache(cache);
        body = encryptAES(JSON.stringify(obj));
      }
    }
  } catch (e) {
    console.log("[HuangDou Unlock] Error: " + e.message);
  }
}

$done({ body: body });
