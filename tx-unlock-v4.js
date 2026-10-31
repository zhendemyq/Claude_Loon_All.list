// 糖心 Vlog Loon 脚本 (100% 纯 JS 本地 AES+Gzip 引擎 + 公益接口双引擎 v4)
// 修复点：
// 1. 彻底移除对原生 $crypto.aes / $utils.ungzip 的 TypedArray 桥接依赖（避免 JavaScriptCore 中 subarray byteOffset 非零或 PKCS7 尾部字节导致解压失败返回 null）。
// 2. 全程使用 100% 纯 JS 实现 SHA-256 / HMAC-SHA256 / AES-256-CBC / RFC1952 Gunzip / Gzip，任何 Loon 版本均零报错运行。
// 3. 在 http-request 阶段将 { reqId, devType, headers, bodyHex } 同时存入 tx_ctx_<reqId> 与 tx_ctx_latest，防止 http-response 阶段拿不到 requestId 请求头。

// ==================== 1. 基础字节与 UTF-8 / Hex 工具 ====================
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
  if (!hex || typeof hex !== "string") return null;
  hex = hex.replace(/[^0-9a-fA-F]/g, "");
  if (hex.length % 2 !== 0) return null;
  var len = hex.length / 2;
  var u8 = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    u8[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return u8;
}

function sliceBytes(u8, start, end) {
  var s = start || 0;
  var e = typeof end === "number" ? end : u8.length;
  if (e < s) e = s;
  var out = new Uint8Array(e - s);
  for (var i = 0; i < e - s; i++) {
    out[i] = u8[s + i];
  }
  return out;
}

function utf8ToBytes(str) {
  var utf8 = unescape(encodeURIComponent(str));
  var u8 = new Uint8Array(utf8.length);
  for (var i = 0; i < utf8.length; i++) {
    u8[i] = utf8.charCodeAt(i) & 0xff;
  }
  return u8;
}

function bytesToUtf8(u8) {
  var bin = "";
  for (var i = 0; i < u8.length; i++) {
    bin += String.fromCharCode(u8[i] & 0xff);
  }
  return decodeURIComponent(escape(bin));
}

function toUint8Array(val) {
  if (!val) return null;
  if (val instanceof Uint8Array) return sliceBytes(val, 0, val.length);
  if (typeof ArrayBuffer !== "undefined" && val instanceof ArrayBuffer) return new Uint8Array(val);
  if (val.buffer instanceof ArrayBuffer) {
    var v = new Uint8Array(val.buffer, val.byteOffset || 0, val.byteLength || val.length || 0);
    return sliceBytes(v, 0, v.length);
  }
  return null;
}

// ==================== 2. 纯 JS SHA-256 & HMAC-SHA256 ====================
var K256 = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

function rotr(n, x) { return (x >>> n) | (x << (32 - n)); }

function sha256(msg) {
  var l = msg.length;
  var bitLen = l * 8;
  var padLen = (l + 9 + 63) & ~63;
  var buf = new Uint8Array(padLen);
  buf.set(msg);
  buf[l] = 0x80;
  var dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 4, bitLen >>> 0, false);
  dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  var H0=0x6a09e667,H1=0xbb67ae85,H2=0x3c6ef372,H3=0xa54ff53a,H4=0x510e527f,H5=0x9b05688c,H6=0x1f83d9ab,H7=0x5be0cd19;
  var W = new Uint32Array(64);
  for (var i = 0; i < padLen; i += 64) {
    for (var t = 0; t < 16; t++) W[t] = dv.getUint32(i + t * 4, false);
    for (var t = 16; t < 64; t++) {
      var s0 = rotr(7, W[t-15]) ^ rotr(18, W[t-15]) ^ (W[t-15] >>> 3);
      var s1 = rotr(17, W[t-2]) ^ rotr(19, W[t-2]) ^ (W[t-2] >>> 10);
      W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
    }
    var a=H0,b=H1,c=H2,d=H3,e=H4,f=H5,g=H6,h=H7;
    for (var t = 0; t < 64; t++) {
      var S1 = rotr(6,e) ^ rotr(11,e) ^ rotr(25,e);
      var ch = (e & f) ^ (~e & g);
      var T1 = (h + S1 + ch + K256[t] + W[t]) >>> 0;
      var S0 = rotr(2,a) ^ rotr(13,a) ^ rotr(22,a);
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var T2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d + T1) >>> 0; d=c; c=b; b=a; a=(T1 + T2) >>> 0;
    }
    H0=(H0+a)>>>0; H1=(H1+b)>>>0; H2=(H2+c)>>>0; H3=(H3+d)>>>0;
    H4=(H4+e)>>>0; H5=(H5+f)>>>0; H6=(H6+g)>>>0; H7=(H7+h)>>>0;
  }
  var out = new Uint8Array(32);
  var odv = new DataView(out.buffer);
  var hs = [H0,H1,H2,H3,H4,H5,H6,H7];
  for (var idx = 0; idx < 8; idx++) odv.setUint32(idx * 4, hs[idx], false);
  return out;
}

function hmacSha256(keyBytes, dataBytes) {
  var block = 64;
  var k = keyBytes.length > block ? sha256(keyBytes) : keyBytes;
  var ipad = new Uint8Array(block + dataBytes.length);
  var opad = new Uint8Array(block + 32);
  for (var i = 0; i < block; i++) {
    var kb = i < k.length ? k[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  ipad.set(dataBytes, block);
  opad.set(sha256(ipad), block);
  return sha256(opad);
}

// ==================== 3. 纯 JS AES-256-CBC (PKCS7) ====================
var SBOX = new Uint8Array(256), INV_SBOX = new Uint8Array(256), RCON = new Uint32Array(11);
(function initAES() {
  var p = new Uint8Array(256), l = new Uint8Array(256);
  var x = 1;
  for (var i = 0; i < 256; i++) {
    p[i] = x; l[x] = i;
    x ^= (x << 1) ^ ((x & 0x80) ? 0x11b : 0);
  }
  SBOX[0] = 0x63; INV_SBOX[0x63] = 0;
  for (var i = 1; i < 256; i++) {
    var y = p[255 - l[i]];
    y ^= ((y << 1) | (y >>> 7)) ^ ((y << 2) | (y >>> 6)) ^ ((y << 3) | (y >>> 5)) ^ ((y << 4) | (y >>> 4)) ^ 0x63;
    SBOX[i] = y & 0xff;
    INV_SBOX[y & 0xff] = i;
  }
  var r = 1;
  for (var i = 1; i <= 10; i++) { RCON[i] = (r << 24) >>> 0; r = (r << 1) ^ ((r & 0x80) ? 0x11b : 0); }
})();

function gmul(a, b) {
  var p = 0;
  for (var i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function expandKey256(key) {
  var w = new Uint32Array(60);
  var dv = new DataView(key.buffer, key.byteOffset, 32);
  for (var i = 0; i < 8; i++) w[i] = dv.getUint32(i * 4, false);
  for (var i = 8; i < 60; i++) {
    var t = w[i - 1];
    if (i % 8 === 0) {
      t = (((SBOX[(t >>> 16) & 0xff] << 24) | (SBOX[(t >>> 8) & 0xff] << 16) | (SBOX[t & 0xff] << 8) | SBOX[(t >>> 24) & 0xff]) ^ RCON[i / 8]) >>> 0;
    } else if (i % 8 === 4) {
      t = ((SBOX[(t >>> 24) & 0xff] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff]) >>> 0;
    }
    w[i] = (w[i - 8] ^ t) >>> 0;
  }
  var rk = new Uint8Array(240);
  var rdv = new DataView(rk.buffer);
  for (var i = 0; i < 60; i++) rdv.setUint32(i * 4, w[i], false);
  return rk;
}

function aesEncryptBlock(s, rk) {
  var b = new Uint8Array(16), t = new Uint8Array(16);
  for (var i = 0; i < 16; i++) b[i] = s[i] ^ rk[i];
  for (var r = 1; r <= 14; r++) {
    for (var i = 0; i < 16; i++) t[i] = SBOX[b[(i + (i & 3) * 4) & 15]];
    if (r < 14) {
      for (var c = 0; c < 16; c += 4) {
        var a0=t[c], a1=t[c+1], a2=t[c+2], a3=t[c+3];
        b[c]   = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3 ^ rk[r*16+c];
        b[c+1] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3 ^ rk[r*16+c+1];
        b[c+2] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3) ^ rk[r*16+c+2];
        b[c+3] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2) ^ rk[r*16+c+3];
      }
    } else {
      for (var i = 0; i < 16; i++) b[i] = t[i] ^ rk[224 + i];
    }
  }
  return b;
}

function aesDecryptBlock(s, rk) {
  var b = new Uint8Array(16), t = new Uint8Array(16);
  for (var i = 0; i < 16; i++) b[i] = s[i] ^ rk[224 + i];
  for (var r = 13; r >= 0; r--) {
    for (var i = 0; i < 16; i++) t[i] = INV_SBOX[b[(i + (16 - (i & 3) * 4)) & 15]];
    for (var i = 0; i < 16; i++) t[i] ^= rk[r * 16 + i];
    if (r > 0) {
      for (var c = 0; c < 16; c += 4) {
        var a0=t[c], a1=t[c+1], a2=t[c+2], a3=t[c+3];
        b[c]   = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
        b[c+1] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
        b[c+2] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11);
        b[c+3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14);
      }
    } else {
      for (var i = 0; i < 16; i++) b[i] = t[i];
    }
  }
  return b;
}

function aes256CbcEncrypt(plain, key, iv) {
  var rk = expandKey256(key);
  var pad = 16 - (plain.length % 16);
  var out = new Uint8Array(plain.length + pad);
  var prev = iv;
  for (var off = 0; off < out.length; off += 16) {
    var blk = new Uint8Array(16);
    for (var i = 0; i < 16; i++) blk[i] = (off + i < plain.length ? plain[off + i] : pad) ^ prev[i];
    prev = aesEncryptBlock(blk, rk);
    out.set(prev, off);
  }
  return out;
}

function aes256CbcDecrypt(cipher, key, iv) {
  var rk = expandKey256(key);
  var out = new Uint8Array(cipher.length);
  var prev = iv;
  for (var off = 0; off < cipher.length; off += 16) {
    var cur = sliceBytes(cipher, off, off + 16);
    var dec = aesDecryptBlock(cur, rk);
    for (var i = 0; i < 16; i++) out[off + i] = dec[i] ^ prev[i];
    prev = cur;
  }
  var pad = out[out.length - 1];
  if (pad < 1 || pad > 16) pad = 0;
  return sliceBytes(out, 0, out.length - pad);
}

// ==================== 4. 100% 纯 JS Gunzip (RFC 1952/1951) & Gzip ====================
function jsGunzip(u8) {
  if (u8[0] !== 0x1f || u8[1] !== 0x8b || u8[2] !== 8) throw new Error("Invalid gzip header");
  var flg = u8[3];
  var pos = 10;
  if (flg & 4) { var xlen = u8[pos] | (u8[pos + 1] << 8); pos += 2 + xlen; }
  if (flg & 8) { while (pos < u8.length && u8[pos++] !== 0); }
  if (flg & 16) { while (pos < u8.length && u8[pos++] !== 0); }
  if (flg & 2) pos += 2;

  var bitBuf = 0, bitCnt = 0;
  function bits(n) {
    while (bitCnt < n) { bitBuf |= (u8[pos++] || 0) << bitCnt; bitCnt += 8; }
    var v = bitBuf & ((1 << n) - 1);
    bitBuf >>>= n; bitCnt -= n;
    return v;
  }
  function buildTree(lengths, count) {
    var counts = new Uint16Array(16), offsets = new Uint16Array(16);
    for (var i = 0; i < count; i++) if (lengths[i]) counts[lengths[i]]++;
    var code = 0;
    for (var i = 1; i <= 15; i++) { offsets[i] = code; code = (code + counts[i]) << 1; }
    var map = {};
    for (var i = 0; i < count; i++) {
      var len = lengths[i];
      if (len) { map[(len << 16) | offsets[len]] = i; offsets[len]++; }
    }
    return map;
  }
  function decodeSym(tree) {
    var code = 0;
    for (var len = 1; len <= 15; len++) {
      code = (code << 1) | bits(1);
      var sym = tree[(len << 16) | code];
      if (sym !== undefined) return sym;
    }
    throw new Error("Invalid huffman code");
  }

  var fixedLitLens = new Uint8Array(288), fixedDistLens = new Uint8Array(32);
  for (var i = 0; i <= 143; i++) fixedLitLens[i] = 8;
  for (var i = 144; i <= 255; i++) fixedLitLens[i] = 9;
  for (var i = 256; i <= 279; i++) fixedLitLens[i] = 7;
  for (var i = 280; i <= 287; i++) fixedLitLens[i] = 8;
  for (var i = 0; i < 32; i++) fixedDistLens[i] = 5;
  var fixedLitTree = buildTree(fixedLitLens, 288), fixedDistTree = buildTree(fixedDistLens, 32);

  var lenBase = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
  var lenExtra = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
  var distBase = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
  var distExtra = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
  var clOrder = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];

  var out = [];
  var bfinal = 0;
  while (!bfinal) {
    bfinal = bits(1);
    var btype = bits(2);
    if (btype === 0) {
      bitBuf = 0; bitCnt = 0;
      var len = u8[pos] | (u8[pos + 1] << 8); pos += 4;
      for (var i = 0; i < len; i++) out.push(u8[pos++]);
    } else if (btype === 1 || btype === 2) {
      var litTree = fixedLitTree, distTree = fixedDistTree;
      if (btype === 2) {
        var hlit = bits(5) + 257, hdist = bits(5) + 1, hclen = bits(4) + 4;
        var clLens = new Uint8Array(19);
        for (var i = 0; i < hclen; i++) clLens[clOrder[i]] = bits(3);
        var clTree = buildTree(clLens, 19);
        var allLens = new Uint8Array(hlit + hdist);
        var idx = 0;
        while (idx < hlit + hdist) {
          var s = decodeSym(clTree);
          if (s < 16) allLens[idx++] = s;
          else if (s === 16) { var rep = bits(2) + 3, prev = allLens[idx - 1]; for (var r = 0; r < rep; r++) allLens[idx++] = prev; }
          else if (s === 17) { var rep = bits(3) + 3; for (var r = 0; r < rep; r++) allLens[idx++] = 0; }
          else { var rep = bits(7) + 11; for (var r = 0; r < rep; r++) allLens[idx++] = 0; }
        }
        litTree = buildTree(sliceBytes(allLens, 0, hlit), hlit);
        distTree = buildTree(sliceBytes(allLens, hlit, hlit + hdist), hdist);
      }
      while (true) {
        var sym = decodeSym(litTree);
        if (sym === 256) break;
        if (sym < 256) out.push(sym);
        else {
          var lIdx = sym - 257;
          var length = lenBase[lIdx] + bits(lenExtra[lIdx]);
          var dSym = decodeSym(distTree);
          var dist = distBase[dSym] + bits(distExtra[dSym]);
          var start = out.length - dist;
          for (var i = 0; i < length; i++) out.push(out[start + i]);
        }
      }
    } else throw new Error("Invalid deflate block");
  }
  return new Uint8Array(out);
}

function gzipCompress(u8) {
  var crc = 0xffffffff;
  for (var i = 0; i < u8.length; i++) {
    crc ^= u8[i];
    for (var j = 0; j < 8; j++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  var blocks = [];
  var offset = 0;
  while (offset < u8.length || blocks.length === 0) {
    var chunkLen = Math.min(65535, u8.length - offset);
    var isLast = (offset + chunkLen >= u8.length) ? 1 : 0;
    var nlen = (~chunkLen) & 0xffff;
    var header = new Uint8Array([isLast, chunkLen & 0xff, (chunkLen >>> 8) & 0xff, nlen & 0xff, (nlen >>> 8) & 0xff]);
    blocks.push(header, sliceBytes(u8, offset, offset + chunkLen));
    offset += chunkLen;
    if (offset >= u8.length) break;
  }
  var deflateLen = 0;
  for (var b = 0; b < blocks.length; b++) deflateLen += blocks[b].length;
  var out = new Uint8Array(10 + deflateLen + 8);
  out.set([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff], 0);
  var pos = 10;
  for (var b = 0; b < blocks.length; b++) { out.set(blocks[b], pos); pos += blocks[b].length; }
  var len = u8.length >>> 0;
  out.set([crc & 0xff, (crc >>> 8) & 0xff, (crc >>> 16) & 0xff, (crc >>> 24) & 0xff, len & 0xff, (len >>> 8) & 0xff, (len >>> 16) & 0xff, (len >>> 24) & 0xff], pos);
  return out;
}

// ==================== 5. 糖心业务加解密与本地修改器 ====================
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

function deriveTxAesKey(reqId, devType) {
  var secret = "45f6af497734161d";
  var dt = String(devType || "web").toLowerCase();
  if (dt === "web") secret = "e0202eee7ef7807f";
  else if (dt === "ios") secret = "cf5a727569cdc1e0";
  var reqBytes = hexToBytes(String(reqId).replace(/-/g, ""));
  if (!reqBytes || reqBytes.length !== 16) return null;
  return hmacSha256(utf8ToBytes(secret), reqBytes);
}

function localUnlockResponse(respBytes, reqId, devType, apiPath) {
  try {
    var u8 = toUint8Array(respBytes);
    if (!u8 || u8.length <= 16) return null;
    var aesKey = deriveTxAesKey(reqId, devType);
    if (!aesKey) return null;
    var iv = sliceBytes(u8, 0, 16);
    var cipher = sliceBytes(u8, 16, u8.length);
    var gzBytes = aes256CbcDecrypt(cipher, aesKey, iv);
    var jsonBytes = jsGunzip(gzBytes);
    var obj = JSON.parse(bytesToUtf8(jsonBytes));
    if (!obj || typeof obj !== "object") return null;

    if (apiPath.indexOf("user/info") !== -1 && obj.data) {
      obj.data.is_vip = "y";
      obj.data.is_dark_vip = "y";
      obj.data.is_up = "y";
      obj.data.is_mer = "y";
      obj.data.exp_level = 99;
      obj.data.balance = "999999";
      obj.data.group_name = "永久VIP会员";
      obj.data.group_end_time = "2099-09-09";
      obj.data.group_dark_name = "暗网永久VIP";
      obj.data.group_dark_end_time = "2099-09-09";
    } else if (apiPath.indexOf("system/info") !== -1 && obj.data) {
      if (Array.isArray(obj.data.splash_ads)) obj.data.splash_ads = [];
      if (Array.isArray(obj.data.pop_ads)) obj.data.pop_ads = [];
      if (Array.isArray(obj.data.ads)) obj.data.ads = [];
      if (Array.isArray(obj.data.index_ads)) obj.data.index_ads = [];
      if (Array.isArray(obj.data.startup_adv)) obj.data.startup_adv = [];
    } else if (apiPath.indexOf("movie/detail") !== -1 && obj.data) {
      obj.data.money = "0";
      obj.data.old_money = "0";
      obj.data.layer_type = "";
      obj.data.pay_type = "free";
      if (Array.isArray(obj.data.play_ads)) obj.data.play_ads = [];
      if (Array.isArray(obj.data.apps)) obj.data.apps = [];
      if (obj.data.user) {
        obj.data.user.is_vip = "y";
        obj.data.user.balance = "999999";
      }
    }

    var newPlain = utf8ToBytes(JSON.stringify(obj));
    var newGz = gzipCompress(newPlain);
    var newCipher = aes256CbcEncrypt(newGz, aesKey, iv);
    var finalOut = new Uint8Array(16 + newCipher.length);
    finalOut.set(iv, 0);
    finalOut.set(newCipher, 16);
    return finalOut;
  } catch (e) {
    console.log("[TX-Unlock] Local decrypt/encrypt error: " + String(e));
    return null;
  }
}

function buildCleanRespHeaders(origRespHeaders) {
  var respHeaders = {};
  var h = origRespHeaders || {};
  for (var hk in h) {
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
    respHeaders[hk] = h[hk];
  }
  return respHeaders;
}

function notifyOnce(title, sub) {
  try {
    if (typeof $notification !== "undefined" && $notification.post) {
      var lastTs = Number($persistentStore.read("tx_notify_ts") || "0");
      var now = Date.now();
      if (now - lastTs > 60000) {
        $persistentStore.write(String(now), "tx_notify_ts");
        $notification.post(title, sub, "");
      }
    }
  } catch (_) {}
}

function stripTxSiteSubdomain(host) {
  return String(host || "").replace(/^[a-z0-9-]+\.(?=tx[a-z0-9]+\.com$)/i, "");
}

function hostFromReferer(headers) {
  var referer = getHeader(headers, "Referer") || getHeader(headers, "Origin") || "";
  var m = referer.match(/^https?:\/\/([^/?#]+)/i);
  return m ? m[1] : "";
}

function resolveWorkerHost(reqHost, pageHost) {
  var req = String(reqHost || "").toLowerCase();
  var page = stripTxSiteSubdomain(pageHost || reqHost);
  if (/^dapi\.[a-z0-9]+\.icu$/i.test(req)) {
    if (/^tx[a-z0-9]+\.com$/i.test(page)) return page;
  }
  if (/^tx[a-z0-9]+\.com$/i.test(req) || /^[a-z0-9-]+\.tx[a-z0-9]+\.com$/i.test(req)) {
    return stripTxSiteSubdomain(req);
  }
  if (/^api\./i.test(req)) return reqHost;
  if (/^tx[a-z0-9]+\.com$/i.test(page)) return page;
  return reqHost;
}

// ==================== 6. 主流程 (http-request & http-response) ====================
var url = $request.url || "";
var match = url.match(/^https?:\/\/([^/?#]+)(\/[^?#]*)?(\?.*)?/);

if (!match) {
  $done({});
} else if (typeof $response === "undefined") {
  // 阶段 1：http-request 阶段 —— 保存完整请求上下文 (reqId, devType, headers, bodyHex) 并原样放行
  var reqId = getHeader($request.headers, "requestId") || "";
  var devType = getHeader($request.headers, "deviceType") || "web";
  var cleanHeaders = {};
  var origH = $request.headers || {};
  for (var k in origH) {
    var lk = String(k).toLowerCase();
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
    cleanHeaders[k] = origH[k];
  }
  var reqHost = match[1];
  var pageHost = hostFromReferer($request.headers) || reqHost;
  var reqU8 = toUint8Array($request.body);
  var ctxStr = JSON.stringify({
    reqId: reqId,
    devType: devType,
    reqHost: reqHost,
    pageHost: pageHost,
    headers: cleanHeaders,
    bodyHex: reqU8 && reqU8.length > 0 ? bytesToHex(reqU8) : ""
  });
  if (reqId) {
    $persistentStore.write(ctxStr, "tx_ctx_" + reqId);
  }
  $persistentStore.write(ctxStr, "tx_ctx_latest");
  $done({});
} else {
  // 阶段 2：http-response 阶段
  var apiPath = (match[2] || "") + (match[3] || "");
  var reqId = getHeader($request.headers, "requestId") || "";
  var devType = getHeader($request.headers, "deviceType") || "";
  var savedCtx = null;

  if (reqId) {
    var s1 = $persistentStore.read("tx_ctx_" + reqId);
    if (s1) {
      $persistentStore.write(undefined, "tx_ctx_" + reqId);
      try { savedCtx = JSON.parse(s1); } catch (_) {}
    }
  }
  if (!savedCtx) {
    var s2 = $persistentStore.read("tx_ctx_latest");
    if (s2) {
      try { savedCtx = JSON.parse(s2); } catch (_) {}
    }
  }

  if (savedCtx) {
    if (!reqId) reqId = savedCtx.reqId || "";
    if (!devType) devType = savedCtx.devType || "web";
  }
  if (!devType) devType = "web";

  // 只要进入 http-response 阶段即触发一次系统通知，方便确认脚本已执行
  notifyOnce("糖心Vlog 解锁脚本已触发", "正在处理: " + apiPath);

  if (apiPath.indexOf("user/info") !== -1 || apiPath.indexOf("system/info") !== -1) {
    var unlockedLocal = localUnlockResponse($response.body, reqId, devType, apiPath);
    if (unlockedLocal) {
      $done({
        status: 200,
        headers: buildCleanRespHeaders($response.headers),
        body: unlockedLocal
      });
    } else {
      $done({});
    }
  } else {
    var reqHost = (savedCtx && savedCtx.reqHost) ? savedCtx.reqHost : match[1];
    var pageHost = (savedCtx && savedCtx.pageHost) ? savedCtx.pageHost : hostFromReferer($request.headers) || reqHost;
    var bareHost = resolveWorkerHost(reqHost, pageHost);
    var targetUrl = "https://txscript.pages.dev/tx/" + bareHost + apiPath;

    var headers = (savedCtx && savedCtx.headers) ? savedCtx.headers : {};
    if (Object.keys(headers).length === 0) {
      var orig = $request.headers || {};
      for (var k in orig) {
        var lk = String(k).toLowerCase();
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
    }

    var reqBody = (savedCtx && savedCtx.bodyHex) ? hexToBytes(savedCtx.bodyHex) : toUint8Array($request.body);
    var options = {
      url: targetUrl,
      headers: headers,
      timeout: 12000,
      "binary-mode": true
    };
    if (reqBody) options.body = reqBody;

    $httpClient.post(options, function (error, response, data) {
      var outU8 = toUint8Array(data);
      if (!error && response && response.status === 200 && outU8 && outU8.length > 16) {
        $done({
          status: 200,
          headers: buildCleanRespHeaders($response.headers),
          body: outU8
        });
        return;
      }

      var proxyGroup = null;
      try {
        if (typeof $config !== "undefined" && $config.getConfig) {
          var cfg = JSON.parse($config.getConfig() || "{}");
          if (cfg.all_policy_groups && cfg.all_policy_groups.length > 0) {
            proxyGroup = cfg.all_policy_groups[0];
          }
        }
      } catch (_) {}

      if (proxyGroup) {
        options.node = proxyGroup;
        options.timeout = 8000;
        $httpClient.post(options, function (err2, resp2, data2) {
          var outU8_2 = toUint8Array(data2);
          if (!err2 && resp2 && resp2.status === 200 && outU8_2 && outU8_2.length > 16) {
            $done({
              status: 200,
              headers: buildCleanRespHeaders($response.headers),
              body: outU8_2
            });
            return;
          }
          var fallbackLocal = localUnlockResponse($response.body, reqId, devType, apiPath);
          if (fallbackLocal) {
            $done({ status: 200, headers: buildCleanRespHeaders($response.headers), body: fallbackLocal });
          } else {
            $done({});
          }
        });
      } else {
        var fallbackLocal = localUnlockResponse($response.body, reqId, devType, apiPath);
        if (fallbackLocal) {
          $done({ status: 200, headers: buildCleanRespHeaders($response.headers), body: fallbackLocal });
        } else {
          $done({});
        }
      }
    });
  }
}
