/**
 * 2FA 扩展 - 后台服务脚本 (Service Worker)
 * 负责：存储管理、消息传递、域名登记、通知
 */

// 存储键名
const STORAGE_KEY = '2fa_entries';
const SETTINGS_KEY = '2fa_settings';

// 默认设置
const DEFAULT_SETTINGS = {
  autoDetect: true,           // 自动检测2FA页面
  autoGenerate: true,         // 已登记页面自动生成
  autoScanQR: true,           // 自动扫描二维码
  notifyOnDetect: true,       // 检测到2FA页面时通知
  storageMethod: 'local',     // local (chrome.storage.local)
  domainLevel: 'eTLD+1',      // 一级域名登记
  customDomains: {}           // 手动配置的域名映射 { domain: { keepPath: bool, path: string } }
};

/**
 * 获取一级域名 (eTLD+1)
 * 简单实现：取最后两段，但需要处理 co.uk 等情况
 * 实际使用中可以用 chrome.storage 维护一个公共后缀列表
 */
function getRootDomain(hostname) {
  if (!hostname) return '';
  hostname = hostname.toLowerCase();

  // IP地址直接返回
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname;

  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;

  // 常见二级域名后缀（简化版）
  const secondLevelTLDs = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.cn', 'org.cn', 'net.cn', 'gov.cn', 'com.au', 'co.jp', 'co.kr', 'com.br', 'com.tw', 'com.hk', 'com.sg', 'com.mx'];

  const lastTwo = parts.slice(-2).join('.');
  if (secondLevelTLDs.includes(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

/**
 * 获取所有存储的2FA条目
 */
async function getAllEntries() {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return result[STORAGE_KEY] || {};
}

/**
 * 保存所有条目
 */
async function saveAllEntries(entries) {
  await chrome.storage.local.set({ [STORAGE_KEY]: entries });
}

/**
 * 获取设置
 */
async function getSettings() {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS, ...(result[SETTINGS_KEY] || {}) };
}

/**
 * 保存设置
 */
async function saveSettings(settings) {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

/**
 * 根据域名查找2FA条目
 */
async function getEntriesForDomain(hostname) {
  const entries = await getAllEntries();
  const rootDomain = getRootDomain(hostname);
  const settings = await getSettings();

  // 检查是否有自定义域名配置
  const customConfig = settings.customDomains[hostname] || settings.customDomains[rootDomain];

  const results = [];
  for (const [id, entry] of Object.entries(entries)) {
    // 匹配域名：精确匹配或一级域名匹配
    if (entry.domain === hostname || entry.domain === rootDomain || entry.rootDomain === rootDomain) {
      results.push({ id, ...entry });
    }
  }
  return results;
}

/**
 * 添加2FA条目
 */
async function addEntry(entry) {
  const entries = await getAllEntries();
  const id = 'entry_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);

  const rootDomain = getRootDomain(entry.domain || '');

  const newEntry = {
    id,
    domain: entry.domain || '',
    rootDomain: rootDomain,
    issuer: entry.issuer || '',
    account: entry.account || '',
    secret: entry.secret || '',
    digits: entry.digits || 6,
    period: entry.period || 30,
    algorithm: entry.algorithm || 'sha1',
    createdAt: Date.now(),
    lastUsed: null,
    note: entry.note || ''
  };

  entries[id] = newEntry;
  await saveAllEntries(entries);
  return newEntry;
}

/**
 * 更新条目
 */
async function updateEntry(id, updates) {
  const entries = await getAllEntries();
  if (!entries[id]) return null;
  entries[id] = { ...entries[id], ...updates, id };
  await saveAllEntries(entries);
  return entries[id];
}

/**
 * 删除条目
 */
async function deleteEntry(id) {
  const entries = await getAllEntries();
  if (entries[id]) {
    delete entries[id];
    await saveAllEntries(entries);
    return true;
  }
  return false;
}

/**
 * 标记条目为已使用
 */
async function markUsed(id) {
  return updateEntry(id, { lastUsed: Date.now() });
}

/**
 * 发送桌面通知
 */
function sendNotification(title, message, iconUrl = 'icons/icon128.png') {
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: iconUrl,
      title: title,
      message: message,
      priority: 2
    });
  } catch (e) {
    console.warn('通知发送失败:', e);
  }
}

// 消息监听
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  (async () => {
    try {
      switch (request.action) {
        case 'getSettings':
          sendResponse({ success: true, data: await getSettings() });
          break;

        case 'saveSettings':
          await saveSettings(request.settings);
          sendResponse({ success: true });
          break;

        case 'getAllEntries':
          sendResponse({ success: true, data: await getAllEntries() });
          break;

        case 'getEntriesForDomain':
          sendResponse({ success: true, data: await getEntriesForDomain(request.hostname) });
          break;

        case 'addEntry':
          const newEntry = await addEntry(request.entry);
          sendResponse({ success: true, data: newEntry });
          break;

        case 'updateEntry':
          const updated = await updateEntry(request.id, request.updates);
          sendResponse({ success: true, data: updated });
          break;

        case 'deleteEntry':
          const deleted = await deleteEntry(request.id);
          sendResponse({ success: deleted });
          break;

        case 'markUsed':
          await markUsed(request.id);
          sendResponse({ success: true });
          break;

        case 'getRootDomain':
          sendResponse({ success: true, data: getRootDomain(request.hostname) });
          break;

        case 'notify':
          sendNotification(request.title, request.message);
          sendResponse({ success: true });
          break;

        case 'addCustomDomain':
          const settings = await getSettings();
          settings.customDomains[request.domain] = request.config;
          await saveSettings(settings);
          sendResponse({ success: true });
          break;

        case 'removeCustomDomain':
          const s = await getSettings();
          delete s.customDomains[request.domain];
          await saveSettings(s);
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ success: false, error: '未知操作: ' + request.action });
      }
    } catch (e) {
      console.error('后台处理错误:', e);
      sendResponse({ success: false, error: e.message });
    }
  })();
  return true; // 保持消息通道开放以支持异步响应
});

// 安装时初始化
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    await saveSettings(DEFAULT_SETTINGS);
    console.log('2FA 扩展已安装，默认设置已初始化');
  }
});

// 导出供测试（在service worker中全局可用）
self.getRootDomain = getRootDomain;
self.getAllEntries = getAllEntries;
