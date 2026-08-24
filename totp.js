/**
 * TOTP (RFC 6238) 纯JavaScript实现
 * 兼容 Google Authenticator、Authy 等主流2FA应用
 * 无外部依赖，可在浏览器扩展和Node.js中运行
 */

(function (global) {
  'use strict';

  // Base32 解码表
  const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  /**
   * 清理密钥字符串：移除空格、连字符、下划线等，转为大写
   */
  function normalizeSecret(secret) {
    if (!secret) return '';
    return String(secret).replace(/[\s\-_.]+/g, '').toUpperCase();
  }

  /**
   * Base32 解码为字节数组
   */
  function base32Decode(secret) {
    secret = normalizeSecret(secret);
    if (!secret) throw new Error('密钥不能为空');

    // 验证字符
    for (let i = 0; i < secret.length; i++) {
      if (BASE32_CHARS.indexOf(secret[i]) === -1) {
        throw new Error('密钥包含非法Base32字符: ' + secret[i]);
      }
    }

    const bits = secret.split('').map(c => BASE32_CHARS.indexOf(c).toString(2).padStart(5, '0')).join('');
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.substr(i, 8), 2));
    }
    return new Uint8Array(bytes);
  }

  /**
   * HMAC-SHA1 实现（使用 Web Crypto API）
   */
  async function hmacSha1(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
  }

  /**
   * HMAC-SHA256
   */
  async function hmacSha256(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
  }

  /**
   * HMAC-SHA512
   */
  async function hmacSha512(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
  }

  /**
   * 将数字转为8字节大端数组
   */
  function counterToBytes(counter) {
    const bytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
      bytes[i] = counter & 0xff;
      counter = Math.floor(counter / 256);
    }
    return bytes;
  }

  /**
   * 动态截断 (Dynamic Truncation)
   */
  function dynamicTruncate(hmacResult, digits) {
    const offset = hmacResult[hmacResult.length - 1] & 0x0f;
    const binary =
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff);
    const otp = binary % Math.pow(10, digits);
    return String(otp).padStart(digits, '0');
  }

  /**
   * 生成 TOTP 验证码（异步，使用 Web Crypto）
   * @param {string} secret - Base32密钥
   * @param {object} options - { digits, period, algorithm, timestamp }
   * @returns {Promise<string>} 验证码
   */
  async function totp(secret, options = {}) {
    const digits = options.digits || 6;
    const period = options.period || 30;
    const algorithm = (options.algorithm || 'sha1').toLowerCase();
    const timestamp = options.timestamp || Date.now() / 1000;

    const key = base32Decode(secret);
    const counter = Math.floor(timestamp / period);
    const message = counterToBytes(counter);

    let hmacResult;
    switch (algorithm) {
      case 'sha256':
        hmacResult = await hmacSha256(key, message);
        break;
      case 'sha512':
        hmacResult = await hmacSha512(key, message);
        break;
      default:
        hmacResult = await hmacSha1(key, message);
    }

    return dynamicTruncate(hmacResult, digits);
  }

  /**
   * 计算剩余有效秒数
   */
  function timeRemaining(period = 30, timestamp = null) {
    const ts = timestamp || Date.now() / 1000;
    return period - (Math.floor(ts) % period);
  }

  /**
   * 计算进度 (0.0 ~ 1.0)
   */
  function progress(period = 30, timestamp = null) {
    const ts = timestamp || Date.now() / 1000;
    return (Math.floor(ts) % period) / period;
  }

  /**
   * 解析 otpauth:// URI
   * 格式: otpauth://totp/Issuer:Account?secret=XXX&issuer=YYY&digits=6&period=30
   */
  function parseOTPAuth(uri) {
    if (!uri || typeof uri !== 'string') return null;
    uri = uri.trim();
    if (!uri.toLowerCase().startsWith('otpauth://')) return null;

    try {
      const url = new URL(uri);
      const type = url.host; // totp or hotp
      const path = decodeURIComponent(url.pathname.replace(/^\//, ''));
      const params = Object.fromEntries(url.searchParams);

      let issuer = params.issuer || '';
      let account = path;

      // 路径可能是 "Issuer:Account" 格式
      if (path.includes(':')) {
        const parts = path.split(':');
        if (!issuer) issuer = parts[0];
        account = parts.slice(1).join(':');
      }

      return {
        type: type,
        issuer: issuer,
        account: account,
        secret: params.secret || '',
        digits: parseInt(params.digits) || 6,
        period: parseInt(params.period) || 30,
        algorithm: (params.algorithm || 'sha1').toLowerCase(),
        rawUri: uri
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * 验证 TOTP 验证码
   */
  async function verifyTOTP(secret, code, options = {}) {
    const period = options.period || 30;
    const window = options.window || 1;
    const now = Date.now() / 1000;

    for (let offset = -window; offset <= window; offset++) {
      const expected = await totp(secret, { ...options, timestamp: now + offset * period });
      if (expected === code) return true;
    }
    return false;
  }

  // 导出
  const TOTP = {
    normalizeSecret,
    base32Decode,
    totp,
    timeRemaining,
    progress,
    parseOTPAuth,
    verifyTOTP
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = TOTP;
  } else {
    global.TOTP = TOTP;
  }

})(typeof window !== 'undefined' ? window : this);
