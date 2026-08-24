/**
 * 2FA 扩展 - 内容脚本 (Content Script)
 * 负责：2FA页面检测、二维码扫描、自动生成验证码、UI注入
 */

(function () {
  'use strict';

  // 防止重复注入
  if (window.__2FA_EXTENSION_INJECTED__) return;
  window.__2FA_EXTENSION_INJECTED__ = true;

  const hostname = window.location.hostname;
  let settings = null;
  let pageEntries = [];
  let detectedOTPAuths = [];
  let uiContainer = null;
  let refreshTimer = null;

  // 2FA相关关键词
  const TWO_FA_KEYWORDS = [
    '2fa', '2-factor', 'two factor', 'two-factor', 'two step', 'two-step',
    'authenticator', 'google authenticator', 'microsoft authenticator', 'authy',
    'otp', 'totp', 'hotp', 'one-time password', 'one time password',
    'verification code', 'security code', '6-digit code',
    '两步验证', '双因素', '双因子', '二次验证', '验证码', '安全验证',
    '身份验证器', '动态口令', '一次性密码', '安全密钥'
  ];

  /**
   * 发送消息到后台
   */
  function sendMessage(action, data = {}) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action, ...data }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(response);
        }
      });
    });
  }

  /**
   * 检测页面是否疑似2FA页面
   */
  function detect2FAPage() {
    const signals = [];
    const pageText = document.body ? document.body.innerText.toLowerCase() : '';
    const pageTitle = document.title.toLowerCase();
    const pageURL = window.location.href.toLowerCase();

    // 1. 检测 otpauth:// URI
    const otpLinks = document.querySelectorAll('a[href^="otpauth://"]');
    if (otpLinks.length > 0) {
      signals.push({ type: 'otpauth_link', count: otpLinks.length, elements: Array.from(otpLinks) });
    }

    // 检测文本中的 otpauth://
    const otpTextMatch = pageText.match(/otpauth:\/\/[^\s]+/gi);
    if (otpTextMatch) {
      signals.push({ type: 'otpauth_text', count: otpTextMatch.length, uris: otpTextMatch });
    }

    // 2. 检测二维码图片
    const qrImages = detectQRImages();
    if (qrImages.length > 0) {
      signals.push({ type: 'qr_image', count: qrImages.length, images: qrImages });
    }

    // 3. 检测6位数字输入框
    const codeInputs = detectCodeInputs();
    if (codeInputs.length > 0) {
      signals.push({ type: 'code_input', count: codeInputs.length, inputs: codeInputs });
    }

    // 4. 关键词匹配
    const matchedKeywords = [];
    for (const kw of TWO_FA_KEYWORDS) {
      if (pageText.includes(kw) || pageTitle.includes(kw) || pageURL.includes(kw)) {
        matchedKeywords.push(kw);
      }
    }
    if (matchedKeywords.length > 0) {
      signals.push({ type: 'keyword', keywords: matchedKeywords });
    }

    // 评分
    let score = 0;
    for (const s of signals) {
      switch (s.type) {
        case 'otpauth_link':
        case 'otpauth_text':
          score += 50;
          break;
        case 'qr_image':
          score += 30;
          break;
        case 'code_input':
          score += 25;
          break;
        case 'keyword':
          score += Math.min(s.keywords.length * 10, 30);
          break;
      }
    }

    return { is2FA: score >= 40, score, signals };
  }

  /**
   * 检测页面中的二维码图片
   */
  function detectQRImages() {
    const candidates = [];

    // 1. 检测所有 img 元素
    const images = document.querySelectorAll('img');
    for (const img of images) {
      const src = img.src || '';
      if (!src) continue;

      const alt = (img.alt || '').toLowerCase();
      const className = (img.className || '').toLowerCase();
      const id = (img.id || '').toLowerCase();
      const width = img.naturalWidth || img.width;
      const height = img.naturalHeight || img.height;

      // 二维码通常是正方形
      const isSquareish = width > 40 && height > 40 && Math.abs(width - height) < width * 0.35;

      // 检查alt/class/id/src是否包含二维码相关词
      const hasQRKeyword = /qr|code|barcode|2fa|otp|authenticator|totp|verify|验证|二维码|条码|安全验证|两步验证/.test(
        alt + ' ' + className + ' ' + id + ' ' + src
      );

      // 检查src是否包含二维码生成API
      const isQRApi = /chart\.googleapis|api\.qrcode|qrcode\.|qr-server|qr-code|qr_code|generate.*qr/.test(src);

      // 评分：有关键词+正方形 = 高置信度；纯正方形大图片 = 中置信度
      let score = 0;
      if (isSquareish) score += 2;
      if (hasQRKeyword) score += 3;
      if (isQRApi) score += 4;
      if (width >= 100 && height >= 100 && isSquareish) score += 1;

      if (score >= 2) {
        candidates.push({ element: img, score, type: 'img' });
      }
    }

    // 2. 检测 canvas 元素（有些网站用canvas绘制二维码）
    const canvases = document.querySelectorAll('canvas');
    for (const canvas of canvases) {
      const width = canvas.width;
      const height = canvas.height;
      const className = (canvas.className || '').toLowerCase();
      const id = (canvas.id || '').toLowerCase();

      const isSquareish = width > 40 && height > 40 && Math.abs(width - height) < width * 0.35;
      const hasQRKeyword = /qr|code|barcode|2fa|otp/.test(className + ' ' + id);

      if (isSquareish && (hasQRKeyword || width >= 100)) {
        candidates.push({ element: canvas, score: hasQRKeyword ? 5 : 2, type: 'canvas' });
      }
    }

    // 3. 检测背景图中可能的二维码（CSS background-image）
    const allElements = document.querySelectorAll('*');
    for (const el of allElements) {
      try {
        const bgImage = window.getComputedStyle(el).backgroundImage;
        if (bgImage && bgImage !== 'none' && /url\(/.test(bgImage)) {
          const urlMatch = bgImage.match(/url\(["']?([^"')]+)["']?\)/);
          if (urlMatch) {
            const bgUrl = urlMatch[1];
            const width = el.offsetWidth;
            const height = el.offsetHeight;
            const isSquareish = width > 40 && height > 40 && Math.abs(width - height) < width * 0.35;
            if (isSquareish && /qr|code|2fa|otp/i.test(bgUrl + el.className + el.id)) {
              // 创建临时img来扫描
              const tempImg = new Image();
              tempImg.src = bgUrl;
              tempImg.crossOrigin = 'anonymous';
              candidates.push({ element: tempImg, score: 3, type: 'bg-image', originalEl: el });
            }
          }
        }
      } catch (e) {
        // 忽略
      }
    }

    // 按分数排序，高置信度优先
    candidates.sort((a, b) => b.score - a.score);

    // 返回元素列表（最多10个，避免扫描过多）
    return candidates.slice(0, 10).map(c => c.element);
  }

  /**
   * 检测6位验证码输入框
   */
  function detectCodeInputs() {
    const inputs = document.querySelectorAll('input');
    const codeInputs = [];

    for (const input of inputs) {
      const type = input.type;
      const maxLength = input.maxLength;
      const placeholder = (input.placeholder || '').toLowerCase();
      const name = (input.name || '').toLowerCase();
      const id = (input.id || '').toLowerCase();
      const autoComplete = (input.autocomplete || '').toLowerCase();

      const isNumeric = type === 'tel' || type === 'number' || type === 'text' || type === 'password';
      const hasCodeLength = maxLength >= 4 && maxLength <= 8;
      const hasCodeKeyword = /code|otp|totp|2fa|verify|verification|token|pin|验证|验证码|动态码/.test(
        placeholder + ' ' + name + ' ' + id + ' ' + autoComplete
      );
      const isOneTimeCode = autoComplete === 'one-time-code';

      if (isNumeric && (hasCodeKeyword || isOneTimeCode || (hasCodeLength && hasCodeKeyword))) {
        codeInputs.push(input);
      }
    }

    return codeInputs;
  }

  /**
   * 尝试用 BarcodeDetector 扫描二维码图片
   */
  async function scanQRImage(img) {
    try {
      // 如果是 canvas 元素，直接获取 ImageData
      if (img.tagName && img.tagName.toLowerCase() === 'canvas') {
        const ctx = img.getContext('2d', { willReadFrequently: true });
        if (ctx) {
          const imageData = ctx.getImageData(0, 0, img.width, img.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'attemptBoth'
          });
          if (code && code.data) return code.data;
        }
        return null;
      }

      // 确保图片已加载
      if (!img.complete || img.naturalWidth === 0) {
        await new Promise((resolve) => {
          if (img.complete) { resolve(); return; }
          const onLoad = () => { img.removeEventListener('load', onLoad); resolve(); };
          const onError = () => { img.removeEventListener('error', onError); resolve(); };
          img.addEventListener('load', onLoad);
          img.addEventListener('error', onError);
          setTimeout(resolve, 3000);
        });
      }

      const width = img.naturalWidth || img.width;
      const height = img.naturalHeight || img.height;
      if (width === 0 || height === 0) return null;

      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });

      // 第一次尝试：直接绘制（同源图片）
      try {
        ctx.drawImage(img, 0, 0, width, height);
        const imageData = ctx.getImageData(0, 0, width, height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'attemptBoth'
        });
        if (code && code.data) return code.data;
      } catch (e) {
        // canvas被污染（跨域图片），继续用fetch方案
      }

      // 第二次尝试：通过fetch获取图片blob（扩展有host权限），转为同源
      try {
        const response = await fetch(img.src, { mode: 'cors', credentials: 'omit' });
        if (!response.ok) return null;
        const blob = await response.blob();
        const objectURL = URL.createObjectURL(blob);
        const img2 = new Image();
        await new Promise((resolve, reject) => {
          img2.onload = resolve;
          img2.onerror = reject;
          img2.src = objectURL;
        });
        ctx.clearRect(0, 0, width, height);
        ctx.drawImage(img2, 0, 0, width, height);
        URL.revokeObjectURL(objectURL);
        const imageData = ctx.getImageData(0, 0, width, height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'attemptBoth'
        });
        if (code && code.data) return code.data;
      } catch (e) {
        console.warn('fetch图片扫描失败:', e);
      }

      return null;
    } catch (e) {
      console.warn('二维码扫描异常:', e);
      return null;
    }
  }

  /**
   * 扫描页面中所有二维码和otpauth链接
   */
  async function scanPageForSecrets() {
    const results = [];

    // 1. 提取 otpauth:// 链接
    const links = document.querySelectorAll('a[href^="otpauth://"]');
    for (const link of links) {
      const parsed = TOTP.parseOTPAuth(link.href);
      if (parsed && parsed.secret) {
        results.push({ ...parsed, source: 'link', element: link });
      }
    }

    // 2. 提取文本中的 otpauth://
    const bodyText = document.body ? document.body.innerText : '';
    const textMatches = bodyText.match(/otpauth:\/\/[^\s\]"'>]+/gi);
    if (textMatches) {
      for (const uri of textMatches) {
        const parsed = TOTP.parseOTPAuth(uri);
        if (parsed && parsed.secret && !results.find(r => r.rawUri === uri)) {
          results.push({ ...parsed, source: 'text' });
        }
      }
    }

    // 3. 扫描二维码图片
    const qrImages = detectQRImages();
    for (const img of qrImages) {
      try {
        const decoded = await scanQRImage(img);
        if (decoded) {
          const parsed = TOTP.parseOTPAuth(decoded);
          if (parsed && parsed.secret) {
            results.push({ ...parsed, source: 'qr_image', element: img });
          }
        }
      } catch (e) {
        console.warn('二维码扫描失败:', e);
      }
    }

    return results;
  }

  /**
   * 创建UI容器
   */
  function createUIContainer() {
    if (uiContainer) return uiContainer;

    uiContainer = document.createElement('div');
    uiContainer.id = '2fa-extension-container';
    uiContainer.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    document.body.appendChild(uiContainer);
    return uiContainer;
  }

  /**
   * 显示检测到2FA页面的提示
   */
  function showDetectPrompt(detection, onScan, onDismiss) {
    const container = createUIContainer();
    container.innerHTML = '';

    const card = document.createElement('div');
    card.className = 'fa2-card fa2-detect-prompt';
    card.innerHTML = `
      <div class="fa2-header">
        <span class="fa2-icon">🔐</span>
        <span class="fa2-title">检测到 2FA 页面</span>
        <button class="fa2-close" title="关闭">×</button>
      </div>
      <div class="fa2-body">
        <p>当前页面疑似两步验证页面，是否自动扫描二维码并保存密钥？</p>
        <div class="fa2-signals">
          ${detection.signals.map(s => {
            let label = '';
            switch (s.type) {
              case 'otpauth_link': label = `发现 ${s.count} 个OTP链接`; break;
              case 'otpauth_text': label = `发现 ${s.count} 个OTP地址`; break;
              case 'qr_image': label = `发现 ${s.count} 个二维码`; break;
              case 'code_input': label = `发现 ${s.count} 个验证码输入框`; break;
              case 'keyword': label = `匹配关键词: ${s.keywords.slice(0,3).join(', ')}`; break;
            }
            return `<span class="fa2-tag">${label}</span>`;
          }).join('')}
        </div>
      </div>
      <div class="fa2-actions">
        <button class="fa2-btn fa2-btn-primary" data-action="scan">扫描并保存</button>
        <button class="fa2-btn fa2-btn-secondary" data-action="manual">手动输入</button>
        <button class="fa2-btn fa2-btn-ghost" data-action="dismiss">忽略</button>
      </div>
    `;

    container.appendChild(card);

    card.querySelector('.fa2-close').addEventListener('click', () => {
      container.remove();
      uiContainer = null;
      if (onDismiss) onDismiss();
    });

    const scanBtn = card.querySelector('[data-action="scan"]');
    scanBtn.addEventListener('click', () => {
      // 显示扫描中状态
      scanBtn.disabled = true;
      scanBtn.textContent = '⏳ 扫描中...';
      scanBtn.style.opacity = '0.7';
      if (onScan) onScan('auto');
    });

    card.querySelector('[data-action="manual"]').addEventListener('click', () => {
      if (onScan) onScan('manual');
    });

    card.querySelector('[data-action="dismiss"]').addEventListener('click', () => {
      container.remove();
      uiContainer = null;
      if (onDismiss) onDismiss();
    });
  }

  /**
   * 显示已扫描到的密钥列表，让用户确认保存
   */
  function showScanResults(secrets, onSave, onCancel) {
    const container = createUIContainer();
    container.innerHTML = '';

    const card = document.createElement('div');
    card.className = 'fa2-card fa2-scan-results';
    card.innerHTML = `
      <div class="fa2-header">
        <span class="fa2-icon">📱</span>
        <span class="fa2-title">发现 ${secrets.length} 个2FA密钥</span>
        <button class="fa2-close" title="关闭">×</button>
      </div>
      <div class="fa2-body">
        <div class="fa2-secret-list">
          ${secrets.map((s, i) => `
            <div class="fa2-secret-item" data-index="${i}">
              <label class="fa2-checkbox">
                <input type="checkbox" checked data-secret-index="${i}">
              </label>
              <div class="fa2-secret-info">
                <div class="fa2-secret-issuer">${s.issuer || '未知服务'}</div>
                <div class="fa2-secret-account">${s.account || ''}</div>
                <div class="fa2-secret-preview">${s.secret.substring(0, 8)}...${s.secret.substring(s.secret.length - 4)}</div>
              </div>
              <span class="fa2-source-tag">${s.source === 'qr_image' ? '二维码' : s.source === 'link' ? '链接' : '文本'}</span>
            </div>
          `).join('')}
        </div>
        <div class="fa2-domain-config">
          <label>
            <input type="checkbox" id="fa2-keep-path" ${settings && settings.customDomains && settings.customDomains[hostname] ? 'checked' : ''}>
            保持完整地址（不只是一级域名）
          </label>
        </div>
      </div>
      <div class="fa2-actions">
        <button class="fa2-btn fa2-btn-primary" data-action="save">保存选中</button>
        <button class="fa2-btn fa2-btn-ghost" data-action="cancel">取消</button>
      </div>
    `;

    container.appendChild(card);

    card.querySelector('.fa2-close').addEventListener('click', () => {
      container.remove();
      uiContainer = null;
      if (onCancel) onCancel();
    });

    card.querySelector('[data-action="cancel"]').addEventListener('click', () => {
      container.remove();
      uiContainer = null;
      if (onCancel) onCancel();
    });

    card.querySelector('[data-action="save"]').addEventListener('click', async () => {
      const checked = card.querySelectorAll('input[data-secret-index]:checked');
      const keepPath = card.querySelector('#fa2-keep-path').checked;
      const selected = [];
      for (const cb of checked) {
        selected.push(secrets[parseInt(cb.dataset.secretIndex)]);
      }
      if (onSave) onSave(selected, keepPath);
    });
  }

  /**
   * 显示手动输入密钥的表单
   */
  function showManualInput(onSave, onCancel) {
    const container = createUIContainer();
    container.innerHTML = '';

    const card = document.createElement('div');
    card.className = 'fa2-card fa2-manual-input';
    card.innerHTML = `
      <div class="fa2-header">
        <span class="fa2-icon">⌨️</span>
        <span class="fa2-title">手动输入2FA密钥</span>
        <button class="fa2-close" title="关闭">×</button>
      </div>
      <div class="fa2-body">
        <div class="fa2-form-group">
          <label>服务名称（可选）</label>
          <input type="text" id="fa2-issuer" placeholder="例如：GitHub">
        </div>
        <div class="fa2-form-group">
          <label>账户名（可选）</label>
          <input type="text" id="fa2-account" placeholder="例如：user@example.com">
        </div>
        <div class="fa2-form-group">
          <label>密钥（Base32） *</label>
          <input type="text" id="fa2-secret" placeholder="例如：JBSWY3DPEHPK3PXP" style="font-family: monospace;">
        </div>
        <div class="fa2-form-row">
          <div class="fa2-form-group">
            <label>位数</label>
            <select id="fa2-digits">
              <option value="6" selected>6位</option>
              <option value="7">7位</option>
              <option value="8">8位</option>
            </select>
          </div>
          <div class="fa2-form-group">
            <label>周期(秒)</label>
            <select id="fa2-period">
              <option value="30" selected>30</option>
              <option value="60">60</option>
            </select>
          </div>
          <div class="fa2-form-group">
            <label>算法</label>
            <select id="fa2-algorithm">
              <option value="sha1" selected>SHA1</option>
              <option value="sha256">SHA256</option>
              <option value="sha512">SHA512</option>
            </select>
          </div>
        </div>
        <div class="fa2-form-group">
          <label>
            <input type="checkbox" id="fa2-keep-path-manual">
            保持完整地址（不只是一级域名）
          </label>
        </div>
        <div id="fa2-preview" class="fa2-preview" style="display:none;">
          <span class="fa2-preview-label">预览：</span>
          <span class="fa2-preview-code">------</span>
        </div>
      </div>
      <div class="fa2-actions">
        <button class="fa2-btn fa2-btn-primary" data-action="save">保存</button>
        <button class="fa2-btn fa2-btn-ghost" data-action="cancel">取消</button>
      </div>
    `;

    container.appendChild(card);

    const secretInput = card.querySelector('#fa2-secret');
    const preview = card.querySelector('#fa2-preview');
    const previewCode = card.querySelector('.fa2-preview-code');

    // 实时预览
    let previewTimer = null;
    secretInput.addEventListener('input', () => {
      const secret = secretInput.value.trim();
      if (secret && secret.length >= 4) {
        preview.style.display = 'block';
        clearTimeout(previewTimer);
        previewTimer = setTimeout(async () => {
          try {
            const code = await TOTP.totp(secret);
            previewCode.textContent = code;
            previewCode.style.color = '#10b981';
          } catch (e) {
            previewCode.textContent = '密钥无效';
            previewCode.style.color = '#ef4444';
          }
        }, 300);
      } else {
        preview.style.display = 'none';
      }
    });

    card.querySelector('.fa2-close').addEventListener('click', () => {
      container.remove();
      uiContainer = null;
      if (onCancel) onCancel();
    });

    card.querySelector('[data-action="cancel"]').addEventListener('click', () => {
      container.remove();
      uiContainer = null;
      if (onCancel) onCancel();
    });

    card.querySelector('[data-action="save"]').addEventListener('click', () => {
      const secret = secretInput.value.trim();
      if (!secret) {
        secretInput.style.borderColor = '#ef4444';
        return;
      }
      const entry = {
        issuer: card.querySelector('#fa2-issuer').value.trim(),
        account: card.querySelector('#fa2-account').value.trim(),
        secret: secret,
        digits: parseInt(card.querySelector('#fa2-digits').value),
        period: parseInt(card.querySelector('#fa2-period').value),
        algorithm: card.querySelector('#fa2-algorithm').value,
        domain: hostname
      };
      const keepPath = card.querySelector('#fa2-keep-path-manual').checked;
      if (onSave) onSave([entry], keepPath);
    });
  }

  /**
   * 显示自动生成的验证码面板
   */
  async function showCodePanel(entries) {
    const container = createUIContainer();
    container.innerHTML = '';

    const card = document.createElement('div');
    card.className = 'fa2-card fa2-code-panel fa2-code-panel-minimal';

    // 生成验证码
    const codes = [];
    for (const entry of entries) {
      try {
        const code = await TOTP.totp(entry.secret, {
          digits: entry.digits,
          period: entry.period,
          algorithm: entry.algorithm
        });
        codes.push({ entry, code });
      } catch (e) {
        codes.push({ entry, code: '错误', error: e.message });
      }
    }

    // 简洁格式：服务名 + 验证码，无用户名，无底部按钮
    card.innerHTML = `
      <button class="fa2-minimal-close" title="关闭 (Esc)">×</button>
      <div class="fa2-minimal-body">
        ${codes.map((c, i) => `
          <div class="fa2-minimal-item" data-index="${i}">
            <span class="fa2-minimal-issuer">${c.entry.issuer || c.entry.domain || '2FA'}</span>
            <span class="fa2-minimal-code ${c.error ? 'fa2-code-error' : ''}" data-code-index="${i}">${c.code}</span>
          </div>
        `).join('')}
        <div class="fa2-minimal-countdown">
          <div class="fa2-minimal-countdown-bar">
            <div class="fa2-minimal-countdown-fill" id="fa2-countdown-fill"></div>
          </div>
          <span class="fa2-minimal-countdown-text" id="fa2-countdown-text">30s</span>
        </div>
        <div class="fa2-minimal-hint">无选中时按 Ctrl+C 复制验证码</div>
      </div>
    `;

    container.appendChild(card);

    // 点击验证码复制
    card.querySelectorAll('.fa2-minimal-code').forEach(el => {
      el.addEventListener('click', () => {
        const code = el.textContent;
        if (code === '错误') return;
        navigator.clipboard.writeText(code).then(() => {
          const original = code;
          el.textContent = '✓';
          el.style.color = '#10b981';
          setTimeout(() => {
            el.textContent = original;
            el.style.color = '';
          }, 1000);
        });
        const idx = parseInt(el.dataset.codeIndex);
        if (codes[idx] && codes[idx].entry && codes[idx].entry.id) {
          sendMessage('markUsed', { id: codes[idx].entry.id });
        }
      });
    });

    // 关闭面板
    function closePanel() {
      container.remove();
      uiContainer = null;
      if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
      }
      document.removeEventListener('keydown', onGlobalKeyDown);
    }

    card.querySelector('.fa2-minimal-close').addEventListener('click', closePanel);

    // 全局快捷键：无选中文本时 Ctrl+C / Cmd+C 复制验证码，Esc 关闭
    function onGlobalKeyDown(e) {
      // Esc 关闭
      if (e.key === 'Escape') {
        closePanel();
        return;
      }

      // Ctrl+C 或 Cmd+C
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c') {
        const selection = window.getSelection().toString();
        // 如果没有选中文本，复制插件验证码
        if (!selection || selection.trim() === '') {
          e.preventDefault();
          e.stopPropagation();
          // 复制第一个有效验证码；多个则全部复制（服务名 验证码 每行）
          const validCodes = codes.filter(c => !c.error);
          if (validCodes.length === 1) {
            navigator.clipboard.writeText(validCodes[0].code);
          } else if (validCodes.length > 1) {
            const text = validCodes.map(c =>
              `${c.entry.issuer || c.entry.domain || '2FA'} ${c.code}`
            ).join('\n');
            navigator.clipboard.writeText(text);
          }
          // 视觉反馈
          const firstCodeEl = card.querySelector('[data-code-index="0"]');
          if (firstCodeEl && firstCodeEl.textContent !== '错误') {
            const original = firstCodeEl.textContent;
            firstCodeEl.textContent = '✓';
            firstCodeEl.style.color = '#10b981';
            setTimeout(() => {
              firstCodeEl.textContent = original;
              firstCodeEl.style.color = '';
            }, 800);
          }
        }
      }
    }

    document.addEventListener('keydown', onGlobalKeyDown, true);

    // 自动刷新验证码
    const updateCodes = async () => {
      for (let i = 0; i < codes.length; i++) {
        if (codes[i].error) continue;
        try {
          const code = await TOTP.totp(codes[i].entry.secret, {
            digits: codes[i].entry.digits,
            period: codes[i].entry.period,
            algorithm: codes[i].entry.algorithm
          });
          const el = card.querySelector(`[data-code-index="${i}"]`);
          if (el && el.textContent !== code && el.textContent !== '✓') {
            el.textContent = code;
            el.style.animation = 'fa2-flash 0.5s ease';
            setTimeout(() => { el.style.animation = ''; }, 500);
          }
        } catch (e) {
          // 忽略刷新错误
        }
      }

      // 更新倒计时
      const remaining = TOTP.timeRemaining();
      const p = TOTP.progress();
      const fill = card.querySelector('#fa2-countdown-fill');
      const text = card.querySelector('#fa2-countdown-text');
      if (fill) fill.style.width = (p * 100) + '%';
      if (text) text.textContent = remaining + 's';
    };

    updateCodes();
    refreshTimer = setInterval(updateCodes, 1000);
  }

  /**
   * 显示保存成功提示
   */
  function showSuccess(message) {
    const container = createUIContainer();
    container.innerHTML = '';

    const toast = document.createElement('div');
    toast.className = 'fa2-toast fa2-toast-success';
    toast.innerHTML = `
      <span class="fa2-toast-icon">✅</span>
      <span class="fa2-toast-text">${message}</span>
    `;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => {
        container.remove();
        uiContainer = null;
      }, 300);
    }, 2500);
  }

  /**
   * 主流程：检测页面并处理
   */
  async function init() {
    // 获取设置
    const settingsResp = await sendMessage('getSettings');
    if (settingsResp.success) {
      settings = settingsResp.data;
    }

    if (!settings || !settings.autoDetect) return;

    // 检查当前域名是否已有存储的条目
    const entriesResp = await sendMessage('getEntriesForDomain', { hostname });
    if (entriesResp.success && entriesResp.data && entriesResp.data.length > 0) {
      pageEntries = entriesResp.data;
      // 已登记页面：询问是否自动生成
      if (settings.autoGenerate) {
        setTimeout(() => {
          showCodePanel(pageEntries);
        }, 500);
      }
      return;
    }

    // 新页面：检测是否为2FA页面
    const detection = detect2FAPage();
    if (detection.is2FA) {
      setTimeout(() => {
        showDetectPrompt(detection, async (mode) => {
          if (mode === 'auto') {
            // 自动扫描
            const secrets = await scanPageForSecrets();
            if (secrets.length > 0) {
              showScanResults(secrets, async (selected, keepPath) => {
                await saveEntries(selected, keepPath);
              });
            } else {
              // 没扫描到，提示手动输入
              showManualInput(async (entries, keepPath) => {
                await saveEntries(entries, keepPath);
              });
            }
          } else if (mode === 'manual') {
            showManualInput(async (entries, keepPath) => {
              await saveEntries(entries, keepPath);
            });
          }
        });
      }, 800);
    }
  }

  /**
   * 保存条目到存储
   */
  async function saveEntries(entries, keepPath) {
    let savedCount = 0;
    for (const entry of entries) {
      const domainToSave = keepPath ? hostname : (await sendMessage('getRootDomain', { hostname })).data;
      const result = await sendMessage('addEntry', {
        entry: {
          ...entry,
          domain: domainToSave
        }
      });
      if (result.success) savedCount++;
    }

    // 如果配置了保持完整地址，添加自定义域名配置
    if (keepPath) {
      await sendMessage('addCustomDomain', {
        domain: hostname,
        config: { keepPath: true, addedAt: Date.now() }
      });
    }

    // 关闭UI并显示成功
    if (uiContainer) {
      uiContainer.remove();
      uiContainer = null;
    }
    showSuccess(`已保存 ${savedCount} 个2FA密钥`);

    // 重新获取条目并显示验证码
    setTimeout(async () => {
      const resp = await sendMessage('getEntriesForDomain', { hostname });
      if (resp.success && resp.data.length > 0) {
        showCodePanel(resp.data);
      }
    }, 1000);
  }

  // 监听来自popup的消息
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getContentStatus') {
      sendResponse({
        hostname,
        hasEntries: pageEntries.length > 0,
        entriesCount: pageEntries.length,
        isInjected: true
      });
      return true;
    }
    if (request.action === 'showCodePanel') {
      if (pageEntries.length > 0) {
        showCodePanel(pageEntries);
      }
      sendResponse({ success: true });
      return true;
    }
    if (request.action === 'showManualInput') {
      showManualInput(async (entries, keepPath) => {
        await saveEntries(entries, keepPath);
      });
      sendResponse({ success: true });
      return true;
    }
    if (request.action === 'rescanPage') {
      (async () => {
        const secrets = await scanPageForSecrets();
        if (secrets.length > 0) {
          showScanResults(secrets, async (selected, keepPath) => {
            await saveEntries(selected, keepPath);
          });
        } else {
          showManualInput(async (entries, keepPath) => {
            await saveEntries(entries, keepPath);
          });
        }
      })();
      sendResponse({ success: true });
      return true;
    }
  });

  // 启动
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
