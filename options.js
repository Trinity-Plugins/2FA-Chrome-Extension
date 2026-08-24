/**
 * 2FA 扩展 - 选项/管理页面逻辑
 */

(function () {
  'use strict';

  let allEntries = {};
  let settings = {};
  let refreshTimer = null;

  // DOM 元素
  const settingsInputs = {
    autoDetect: document.getElementById('setting-autoDetect'),
    autoGenerate: document.getElementById('setting-autoGenerate'),
    autoScanQR: document.getElementById('setting-autoScanQR'),
    notifyOnDetect: document.getElementById('setting-notifyOnDetect'),
    domainLevel: document.getElementById('setting-domainLevel')
  };

  const btnSaveSettings = document.getElementById('btn-save-settings');
  const saveStatus = document.getElementById('save-status');
  const entriesTbody = document.getElementById('entries-tbody');
  const btnAddManual = document.getElementById('btn-add-manual');
  const btnExport = document.getElementById('btn-export');
  const btnImport = document.getElementById('btn-import');
  const importFile = document.getElementById('import-file');
  const customDomainsList = document.getElementById('custom-domains-list');
  const newDomainInput = document.getElementById('new-domain-input');
  const btnAddDomain = document.getElementById('btn-add-domain');

  // 模态框
  const addModal = document.getElementById('add-modal');
  const modalClose = document.getElementById('modal-close');
  const modalCancel = document.getElementById('modal-cancel');
  const modalSave = document.getElementById('modal-save');
  const modalSecret = document.getElementById('modal-secret');
  const modalPreview = document.getElementById('modal-preview');
  const modalPreviewCode = document.getElementById('modal-preview-code');

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
   * 加载设置
   */
  async function loadSettings() {
    const resp = await sendMessage('getSettings');
    if (resp.success) {
      settings = resp.data;
      settingsInputs.autoDetect.checked = settings.autoDetect;
      settingsInputs.autoGenerate.checked = settings.autoGenerate;
      settingsInputs.autoScanQR.checked = settings.autoScanQR;
      settingsInputs.notifyOnDetect.checked = settings.notifyOnDetect;
      settingsInputs.domainLevel.value = settings.domainLevel;
    }
  }

  /**
   * 保存设置
   */
  async function saveSettings() {
    const newSettings = {
      ...settings,
      autoDetect: settingsInputs.autoDetect.checked,
      autoGenerate: settingsInputs.autoGenerate.checked,
      autoScanQR: settingsInputs.autoScanQR.checked,
      notifyOnDetect: settingsInputs.notifyOnDetect.checked,
      domainLevel: settingsInputs.domainLevel.value
    };

    const resp = await sendMessage('saveSettings', { settings: newSettings });
    if (resp.success) {
      settings = newSettings;
      showSaveStatus('设置已保存 ✓');
    } else {
      showSaveStatus('保存失败', true);
    }
  }

  function showSaveStatus(text, isError = false) {
    saveStatus.textContent = text;
    saveStatus.style.color = isError ? '#ef4444' : '#10b981';
    saveStatus.classList.add('show');
    setTimeout(() => saveStatus.classList.remove('show'), 2000);
  }

  /**
   * 加载所有条目
   */
  async function loadEntries() {
    const resp = await sendMessage('getAllEntries');
    if (resp.success) {
      allEntries = resp.data || {};
    }
    renderEntriesTable();
  }

  /**
   * 渲染条目表格
   */
  async function renderEntriesTable() {
    const entries = Object.values(allEntries);

    if (entries.length === 0) {
      entriesTbody.innerHTML = '<tr><td colspan="7" class="empty-cell">暂无保存的密钥，点击"手动添加"或访问2FA页面自动添加</td></tr>';
      return;
    }

    entries.sort((a, b) => (b.lastUsed || b.createdAt || 0) - (a.lastUsed || a.createdAt || 0));

    entriesTbody.innerHTML = '';
    for (const entry of entries) {
      const tr = document.createElement('tr');

      let codeHtml = '<span class="code-cell">------</span>';
      try {
        const code = await TOTP.totp(entry.secret, {
          digits: entry.digits,
          period: entry.period,
          algorithm: entry.algorithm
        });
        codeHtml = `<span class="code-cell" title="点击复制">${code}</span>`;
      } catch (e) {
        codeHtml = '<span style="color:#ef4444;font-size:11px;">无效密钥</span>';
      }

      const lastUsed = entry.lastUsed
        ? new Date(entry.lastUsed).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
        : '从未';

      tr.innerHTML = `
        <td><strong>${entry.issuer || '未命名'}</strong></td>
        <td>${entry.account || '-'}</td>
        <td style="font-family:monospace;font-size:12px;">${entry.domain || '-'}</td>
        <td>${codeHtml}</td>
        <td style="font-size:12px;text-transform:uppercase;">${entry.algorithm || 'sha1'} / ${entry.digits || 6}位 / ${entry.period || 30}s</td>
        <td style="font-size:12px;color:#6b7280;">${lastUsed}</td>
        <td>
          <button class="btn btn-danger-ghost" data-action="delete" data-id="${entry.id}" style="padding:4px 10px;font-size:12px;">删除</button>
        </td>
      `;

      // 复制验证码
      const codeEl = tr.querySelector('.code-cell');
      if (codeEl) {
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
      tr.querySelector('[data-action="delete"]').addEventListener('click', async () => {
        if (confirm(`确定要删除 "${entry.issuer || entry.domain || '未命名'}" 的密钥吗？`)) {
          await sendMessage('deleteEntry', { id: entry.id });
          await loadEntries();
        }
      });

      entriesTbody.appendChild(tr);
    }
  }

  /**
   * 渲染自定义域名列表
   */
  function renderCustomDomains() {
    const customDomains = settings.customDomains || {};
    const domains = Object.keys(customDomains);

    if (domains.length === 0) {
      customDomainsList.innerHTML = '<div class="empty-cell" style="padding:16px;text-align:center;color:#9ca3af;font-size:13px;">暂无自定义配置</div>';
      return;
    }

    customDomainsList.innerHTML = '';
    for (const domain of domains) {
      const config = customDomains[domain];
      const item = document.createElement('div');
      item.className = 'domain-item';
      item.innerHTML = `
        <span class="domain-name">${domain}</span>
        <button class="btn btn-danger-ghost" data-domain="${domain}" style="padding:4px 10px;font-size:12px;">移除</button>
      `;
      item.querySelector('button').addEventListener('click', async () => {
        await sendMessage('removeCustomDomain', { domain });
        settings.customDomains = { ...settings.customDomains };
        delete settings.customDomains[domain];
        renderCustomDomains();
      });
      customDomainsList.appendChild(item);
    }
  }

  /**
   * 添加自定义域名
   */
  async function addCustomDomain() {
    const domain = newDomainInput.value.trim().toLowerCase();
    if (!domain) return;

    try {
      // 简单验证域名格式
      if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
        alert('请输入有效的域名');
        return;
      }

      await sendMessage('addCustomDomain', {
        domain,
        config: { keepPath: true, addedAt: Date.now(), manual: true }
      });

      settings.customDomains = { ...settings.customDomains, [domain]: { keepPath: true } };
      newDomainInput.value = '';
      renderCustomDomains();
    } catch (e) {
      alert('添加失败: ' + e.message);
    }
  }

  /**
   * 导出密钥
   */
  function exportEntries() {
    const data = {
      version: '1.0',
      exportedAt: new Date().toISOString(),
      entries: Object.values(allEntries),
      settings: settings
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `2fa-export-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  /**
   * 导入密钥
   */
  async function importEntries(file) {
    try {
      const text = await file.text();
      const data = JSON.parse(text);

      if (!data.entries || !Array.isArray(data.entries)) {
        alert('无效的导入文件格式');
        return;
      }

      if (!confirm(`确定要导入 ${data.entries.length} 个密钥吗？这将合并到现有密钥中。`)) {
        return;
      }

      let imported = 0;
      for (const entry of data.entries) {
        // 移除旧ID，让系统生成新ID
        const { id, ...entryData } = entry;
        const resp = await sendMessage('addEntry', { entry: entryData });
        if (resp.success) imported++;
      }

      alert(`成功导入 ${imported} 个密钥`);
      await loadEntries();
    } catch (e) {
      alert('导入失败: ' + e.message);
    }
  }

  // 模态框操作
  function openModal() {
    addModal.style.display = 'flex';
    document.getElementById('modal-issuer').focus();
  }

  function closeModal() {
    addModal.style.display = 'none';
    // 清空表单
    document.getElementById('modal-issuer').value = '';
    document.getElementById('modal-account').value = '';
    document.getElementById('modal-domain').value = '';
    document.getElementById('modal-secret').value = '';
    document.getElementById('modal-note').value = '';
    modalPreview.style.display = 'none';
  }

  // 实时预览
  let previewTimer = null;
  modalSecret.addEventListener('input', () => {
    const secret = modalSecret.value.trim();
    if (secret && secret.length >= 4) {
      modalPreview.style.display = 'flex';
      clearTimeout(previewTimer);
      previewTimer = setTimeout(async () => {
        try {
          const code = await TOTP.totp(secret);
          modalPreviewCode.textContent = code;
          modalPreviewCode.style.color = '#059669';
        } catch (e) {
          modalPreviewCode.textContent = '密钥无效';
          modalPreviewCode.style.color = '#dc2626';
        }
      }, 300);
    } else {
      modalPreview.style.display = 'none';
    }
  });

  // 保存手动添加
  modalSave.addEventListener('click', async () => {
    const secret = document.getElementById('modal-secret').value.trim();
    if (!secret) {
      alert('请输入密钥');
      return;
    }

    const entry = {
      issuer: document.getElementById('modal-issuer').value.trim(),
      account: document.getElementById('modal-account').value.trim(),
      domain: document.getElementById('modal-domain').value.trim().toLowerCase(),
      secret: secret,
      digits: parseInt(document.getElementById('modal-digits').value),
      period: parseInt(document.getElementById('modal-period').value),
      algorithm: document.getElementById('modal-algorithm').value,
      note: document.getElementById('modal-note').value.trim()
    };

    const resp = await sendMessage('addEntry', { entry });
    if (resp.success) {
      closeModal();
      await loadEntries();
    } else {
      alert('保存失败: ' + (resp.error || '未知错误'));
    }
  });

  // 事件绑定
  btnSaveSettings.addEventListener('click', saveSettings);
  btnAddManual.addEventListener('click', openModal);
  modalClose.addEventListener('click', closeModal);
  modalCancel.addEventListener('click', closeModal);
  btnExport.addEventListener('click', exportEntries);
  btnImport.addEventListener('click', () => importFile.click());
  importFile.addEventListener('change', (e) => {
    if (e.target.files[0]) {
      importEntries(e.target.files[0]);
      e.target.value = '';
    }
  });
  btnAddDomain.addEventListener('click', addCustomDomain);
  newDomainInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') addCustomDomain();
  });

  // 点击模态框外部关闭
  addModal.addEventListener('click', (e) => {
    if (e.target === addModal) closeModal();
  });

  // 自动刷新验证码
  function startAutoRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
      renderEntriesTable();
    }, 5000);
  }

  // 初始化
  async function init() {
    await loadSettings();
    await loadEntries();
    renderCustomDomains();
    startAutoRefresh();
  }

  init();
})();
