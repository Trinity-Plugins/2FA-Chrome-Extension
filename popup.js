/**
 * 2FA 扩展 - Popup 弹窗逻辑
 */

(function () {
  'use strict';

  let currentTab = null;
  let currentHostname = '';
  let allEntries = {};
  let refreshTimer = null;

  // DOM 元素
  const domainEl = document.getElementById('current-domain');
  const statusEl = document.getElementById('current-page-status');
  const actionsEl = document.getElementById('current-page-actions');
  const btnShowCodes = document.getElementById('btn-show-codes');
  const btnRescan = document.getElementById('btn-rescan');
  const btnManual = document.getElementById('btn-manual');
  const btnOptions = document.getElementById('btn-options');
  const entriesListEl = document.getElementById('entries-list');
  const totalCountEl = document.getElementById('total-count');

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
   * 发送消息到内容脚本
   */
  function sendToContent(tabId, action, data = {}) {
    return new Promise((resolve) => {
      chrome.tabs.sendMessage(tabId, { action, ...data }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(response);
        }
      });
    });
  }

  /**
   * 获取当前标签页
   */
  async function getCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab;
  }

  /**
   * 从URL提取hostname
   */
  function getHostname(url) {
    try {
      return new URL(url).hostname;
    } catch (e) {
      return '';
    }
  }

  /**
   * 加载所有条目
   */
  async function loadEntries() {
    const resp = await sendMessage('getAllEntries');
    if (resp.success) {
      allEntries = resp.data || {};
    }
    totalCountEl.textContent = Object.keys(allEntries).length;
    renderEntriesList();
  }

  /**
   * 渲染所有条目列表
   */
  async function renderEntriesList() {
    const entries = Object.values(allEntries);

    if (entries.length === 0) {
      entriesListEl.innerHTML = '<div class="empty-state">暂无保存的密钥<br>访问2FA页面时会自动提示添加</div>';
      return;
    }

    // 按最后使用时间排序
    entries.sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0));

    entriesListEl.innerHTML = '';
    for (const entry of entries) {
      const item = document.createElement('div');
      item.className = 'entry-item';

      let codeHtml = '<span class="entry-code">------</span>';
      try {
        const code = await TOTP.totp(entry.secret, {
          digits: entry.digits,
          period: entry.period,
          algorithm: entry.algorithm
        });
        codeHtml = `<span class="entry-code" title="点击复制">${code}</span>`;
      } catch (e) {
        codeHtml = '<span class="entry-code" style="color:#ef4444;font-size:10px;">无效</span>';
      }

      item.innerHTML = `
        <div class="entry-info">
          <div class="entry-issuer">${entry.issuer || entry.domain || '未命名'}</div>
          ${entry.account ? `<div class="entry-account">${entry.account}</div>` : ''}
          <div class="entry-domain">${entry.domain || ''}</div>
        </div>
        ${codeHtml}
        <div class="entry-actions">
          <button class="entry-action-btn" data-action="delete" data-id="${entry.id}" title="删除">🗑️</button>
        </div>
      `;

      // 复制验证码
      const codeEl = item.querySelector('.entry-code');
      if (codeEl && !codeEl.textContent.includes('无效')) {
        codeEl.addEventListener('click', () => {
          navigator.clipboard.writeText(codeEl.textContent).then(() => {
            const original = codeEl.textContent;
            codeEl.textContent = '✓';
            setTimeout(() => { codeEl.textContent = original; }, 1000);
          });
          sendMessage('markUsed', { id: entry.id });
        });
      }

      // 删除
      item.querySelector('[data-action="delete"]').addEventListener('click', async (e) => {
        e.stopPropagation();
        if (confirm('确定要删除这个密钥吗？')) {
          await sendMessage('deleteEntry', { id: entry.id });
          await loadEntries();
          await checkCurrentPage();
        }
      });

      entriesListEl.appendChild(item);
    }
  }

  /**
   * 检查当前页面状态
   */
  async function checkCurrentPage() {
    if (!currentTab || !currentHostname) {
      statusEl.innerHTML = '<span class="status-no-entries">无法获取当前页面信息</span>';
      return;
    }

    domainEl.textContent = currentHostname;

    // 查询当前域名的条目
    const resp = await sendMessage('getEntriesForDomain', { hostname: currentHostname });
    const pageEntries = resp.success ? (resp.data || []) : [];

    actionsEl.style.display = 'flex';

    if (pageEntries.length > 0) {
      statusEl.innerHTML = `<span class="status-has-entries">✓ 已保存 ${pageEntries.length} 个密钥</span>`;
      btnShowCodes.style.display = 'inline-block';

      // 尝试通知内容脚本显示验证码面板
      if (currentTab.id) {
        sendToContent(currentTab.id, 'showCodePanel');
      }
    } else {
      statusEl.innerHTML = '<span class="status-no-entries">当前页面未保存密钥</span>';
      btnShowCodes.style.display = 'none';
    }
  }

  // 事件绑定
  btnShowCodes.addEventListener('click', () => {
    if (currentTab && currentTab.id) {
      sendToContent(currentTab.id, 'showCodePanel');
      window.close();
    }
  });

  btnRescan.addEventListener('click', () => {
    if (currentTab && currentTab.id) {
      sendToContent(currentTab.id, 'rescanPage');
      window.close();
    }
  });

  btnManual.addEventListener('click', () => {
    if (currentTab && currentTab.id) {
      sendToContent(currentTab.id, 'showManualInput');
      window.close();
    }
  });

  btnOptions.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  // 自动刷新验证码
  function startAutoRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
      renderEntriesList();
    }, 5000);
  }

  // 初始化
  async function init() {
    try {
      currentTab = await getCurrentTab();
      if (currentTab && currentTab.url) {
        currentHostname = getHostname(currentTab.url);
      }
    } catch (e) {
      console.warn('获取标签页失败:', e);
    }

    await loadEntries();
    await checkCurrentPage();
    startAutoRefresh();
  }

  init();
})();
