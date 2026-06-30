import express from 'express';
import axios from 'axios';
import net from 'net';
import cron from 'node-cron';
import dotenv from 'dotenv';
import geoip from 'geoip-lite';
import base64 from 'base-64';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIG (с поддержкой env) ====================
const CONFIG = {
  // === Основные настройки сервиса ===
  name: process.env.SERVICE_NAME || "Zapretka",
  version: process.env.SERVICE_VERSION || "2.1.0",

  // === Источники подписок ===
  subscriptionUrls: (process.env.SUBSCRIPTION_URLS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean),

  // === Настройки обновления ===
  updateIntervalMinutes: parseInt(process.env.UPDATE_INTERVAL_MINUTES || '45'),
  maxNodesPerSub: parseInt(process.env.MAX_NODES_PER_SUB || '200'),

  // === Лимиты подписок ===
  topLimit: parseInt(process.env.TOP_LIMIT || '20'),

  // === Формат имени ноды ===
  nodeNameFormat: process.env.NODE_NAME_FORMAT || "[flag] [country] #[number]"
};

// ==================== COUNTRY NAMES ====================
const countryNames = {
  'RU': 'Russia', 'US': 'United States', 'DE': 'Germany', 'FR': 'France', 'GB': 'United Kingdom',
  'NL': 'Netherlands', 'CA': 'Canada', 'JP': 'Japan', 'KR': 'South Korea', 'CN': 'China',
  'HK': 'Hong Kong', 'SG': 'Singapore', 'TW': 'Taiwan', 'AU': 'Australia', 'BR': 'Brazil',
  'IN': 'India', 'IT': 'Italy', 'ES': 'Spain', 'SE': 'Sweden', 'CH': 'Switzerland',
  'AT': 'Austria', 'BE': 'Belgium', 'DK': 'Denmark', 'NO': 'Norway', 'FI': 'Finland',
  'PL': 'Poland', 'CZ': 'Czech Republic', 'HU': 'Hungary', 'RO': 'Romania', 'UA': 'Ukraine',
  'TR': 'Turkey', 'IL': 'Israel', 'AE': 'UAE', 'SA': 'Saudi Arabia', 'ZA': 'South Africa',
  'MX': 'Mexico', 'AR': 'Argentina', 'CL': 'Chile', 'CO': 'Colombia', 'PE': 'Peru',
  'TH': 'Thailand', 'VN': 'Vietnam', 'ID': 'Indonesia', 'MY': 'Malaysia', 'PH': 'Philippines',
  'XX': 'Unknown'
};

function getCountryName(code) {
  return countryNames[code] || code;
}

// ==================== NODE RENAMING ====================
function renameNode(node, index) {
  const flag = Object.keys(flagToCountry).find(f => flagToCountry[f] === node.country) || '';
  const countryName = getCountryName(node.country);
  const number = (index + 1).toString().padStart(2, '0');
  
  return `${flag} ${countryName} #${number}`;
}

// ==================== STATE ====================
let nodes = [];
let lastUpdated = null;
let updateInProgress = false;

// ==================== PARSERS ====================

function decodeBase64(str) {
  try {
    return Buffer.from(str, 'base64').toString('utf8');
  } catch {
    try { return base64.decode(str); } catch { return str; }
  }
}

function parseVmess(link) {
  try {
    const data = JSON.parse(decodeBase64(link.replace('vmess://', '')));
    return {
      protocol: 'vmess',
      name: data.ps || data.add || 'vmess',
      server: data.add,
      port: parseInt(data.port),
      uuid: data.id,
      alterId: parseInt(data.aid) || 0,
      net: data.net || 'tcp',
      path: data.path || '/',
      host: data.host || data.add,
      tls: data.tls === 'tls',
      raw: link,
      config: data
    };
  } catch { return null; }
}

function parseVless(link) {
  try {
    const url = new URL(link);
    const params = new URLSearchParams(url.search);
    return {
      protocol: 'vless',
      name: decodeURIComponent(params.get('remarks') || url.hash.replace('#', '') || url.hostname),
      server: url.hostname,
      port: parseInt(url.port) || 443,
      uuid: url.username,
      flow: params.get('flow') || '',
      net: params.get('type') || 'tcp',
      path: params.get('path') || '/',
      host: params.get('host') || '',
      tls: params.get('security') === 'tls' || params.get('security') === 'reality',
      sni: params.get('sni') || params.get('host') || url.hostname,
      raw: link
    };
  } catch { return null; }
}

function parseTrojan(link) {
  try {
    const url = new URL(link);
    const params = new URLSearchParams(url.search);
    return {
      protocol: 'trojan',
      name: decodeURIComponent(params.get('remarks') || url.hash.replace('#', '') || url.hostname),
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password: url.username,
      flow: params.get('flow') || '',
      net: params.get('type') || 'tcp',
      path: params.get('path') || '/',
      host: params.get('host') || '',
      tls: true,
      sni: params.get('sni') || params.get('host') || url.hostname,
      raw: link
    };
  } catch { return null; }
}

function parseShadowsocks(link) {
  try {
    let content = link.replace('ss://', '');
    let methodPass, serverInfo;
    if (content.includes('@')) {
      [methodPass, serverInfo] = content.split('@');
    } else {
      content = decodeBase64(content);
      [methodPass, serverInfo] = content.split('@');
    }
    const [method, password] = methodPass.split(':');
    const [server, port] = serverInfo.split(':');
    return {
      protocol: 'ss',
      name: server,
      server: server,
      port: parseInt(port),
      method: method,
      password: password,
      raw: link
    };
  } catch { return null; }
}

// ==================== HYSTERIA2 PARSER ====================
function parseHysteria2(link) {
  try {
    let urlStr = link;
    if (link.startsWith('hy2://')) {
      urlStr = link.replace('hy2://', 'hysteria2://');
    }

    const url = new URL(urlStr);
    const params = new URLSearchParams(url.search);

    return {
      protocol: 'hysteria2',
      name: decodeURIComponent(params.get('remarks') || url.hash.replace('#', '') || url.hostname),
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password: url.username,
      obfs: params.get('obfs') || '',
      obfsPassword: params.get('obfs-password') || '',
      sni: params.get('sni') || params.get('peer') || url.hostname,
      insecure: params.get('insecure') === '1' || params.get('allowInsecure') === '1',
      upMbps: params.get('upmbps') || params.get('up') || '',
      downMbps: params.get('downmbps') || params.get('down') || '',
      alpn: params.get('alpn') || '',
      raw: link
    };
  } catch {
    return null;
  }
}

function parseSubscription(rawText) {
  const lines = rawText.trim().split(/\r?\n/);
  const nodes = [];
  for (let line of lines) {
    line = line.trim();
    if (!line) continue;
    let node = null;
    if (line.startsWith('vmess://')) node = parseVmess(line);
    else if (line.startsWith('vless://')) node = parseVless(line);
    else if (line.startsWith('trojan://')) node = parseTrojan(line);
    else if (line.startsWith('ss://')) node = parseShadowsocks(line);
    else if (line.startsWith('hysteria2://') || line.startsWith('hy2://')) node = parseHysteria2(line);
    if (node && node.server && node.port) nodes.push(node);
  }
  return nodes;
}

// ==================== TESTING ====================

async function testTCP(node, timeout = 5500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const start = Date.now();
    socket.setTimeout(timeout);
    socket.connect(node.port, node.server, () => {
      const latency = Date.now() - start;
      socket.destroy();
      resolve({ success: true, latency });
    });
    socket.on('error', () => { socket.destroy(); resolve({ success: false, latency: null }); });
    socket.on('timeout', () => { socket.destroy(); resolve({ success: false, latency: null }); });
  });
}

async function testNode(node) {
  try {
    if (node.protocol === 'hysteria2') {
      const urlOk = await testURLQuick(node);
      return {
        ...node,
        latency: 50,
        alive: urlOk,
        testedAt: new Date()
      };
    }

    const tcp = await testTCP(node);
    if (!tcp.success) return { ...node, latency: null, alive: false };
    
    const urlOk = await testURLQuick(node);
    
    return {
      ...node,
      latency: tcp.latency,
      alive: tcp.success && urlOk,
      testedAt: new Date()
    };
  } catch {
    return { ...node, latency: null, alive: false };
  }
}

async function testURLQuick(node) {
  try {
    const res = await axios.get('https://www.google.com', {
      timeout: 7000,
      validateStatus: () => true
    });
    return res.status < 500;
  } catch {
    return false;
  }
}

// ==================== COUNTRY DETECTION ====================

const flagToCountry = {
  '🇷🇺': 'RU', '🇺🇸': 'US', '🇩🇪': 'DE', '🇫🇷': 'FR', '🇬🇧': 'GB',
  '🇳🇱': 'NL', '🇨🇦': 'CA', '🇯🇵': 'JP', '🇰🇷': 'KR', '🇨🇳': 'CN',
  '🇭🇰': 'HK', '🇸🇬': 'SG', '🇹🇼': 'TW', '🇦🇺': 'AU', '🇧🇷': 'BR',
  '🇮🇳': 'IN', '🇮🇹': 'IT', '🇪🇸': 'ES', '🇸🇪': 'SE', '🇨🇭': 'CH',
  '🇦🇹': 'AT', '🇧🇪': 'BE', '🇩🇰': 'DK', '🇳🇴': 'NO', '🇫🇮': 'FI',
  '🇵🇱': 'PL', '🇨🇿': 'CZ', '🇭🇺': 'HU', '🇷🇴': 'RO', '🇺🇦': 'UA',
  '🇹🇷': 'TR', '🇮🇱': 'IL', '🇦🇪': 'AE', '🇸🇦': 'SA', '🇿🇦': 'ZA',
  '🇲🇽': 'MX', '🇦🇷': 'AR', '🇨🇱': 'CL', '🇨🇴': 'CO', '🇵🇪': 'PE',
  '🇹🇭': 'TH', '🇻🇳': 'VN', '🇮🇩': 'ID', '🇲🇾': 'MY', '🇵🇭': 'PH',
};

function extractCountryFromName(name) {
  if (!name) return null;
  for (const [flag, code] of Object.entries(flagToCountry)) {
    if (name.includes(flag)) return code;
  }
  return null;
}

function getCountry(node) {
  const fromName = extractCountryFromName(node.name);
  if (fromName) return fromName;

  try {
    const geo = geoip.lookup(node.server);
    return geo?.country || 'XX';
  } catch {
    return 'XX';
  }
}

// ==================== HELPERS ====================

function generateSubscription(nodesList) {
  if (!nodesList.length) return '';
  
  return nodesList
    .map((node, index) => {
      const newNode = { ...node };
      newNode.name = renameNode(node, index);
      
      let newRaw = node.raw;
      
      if (newRaw.includes('#')) {
        newRaw = newRaw.split('#')[0] + '#' + encodeURIComponent(newNode.name);
      } else if (newRaw.includes('remarks=')) {
        newRaw = newRaw.replace(/remarks=[^&]+/, `remarks=${encodeURIComponent(newNode.name)}`);
      }
      
      return newRaw;
    })
    .join('\n');
}

function deduplicateNodes(nodeList) {
  const seen = new Set();
  return nodeList.filter(node => {
    const key = `${node.server}:${node.port}:${node.protocol}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ==================== UPDATE LOGIC ====================

async function fetchSubscription(url) {
  try {
    const res = await axios.get(url, {
      timeout: 15000,
      headers: { 'User-Agent': 'v2rayNG/1.8.0' }
    });
    return parseSubscription(res.data);
  } catch (err) {
    console.error(`Fetch failed: ${url} - ${err.message}`);
    return [];
  }
}

async function updateNodes() {
  if (updateInProgress || CONFIG.subscriptionUrls.length === 0) return;
  updateInProgress = true;
  console.log('🔄 Updating nodes...');

  try {
    let allNodes = [];
    for (const url of CONFIG.subscriptionUrls) {
      const fetched = await fetchSubscription(url);
      allNodes.push(...fetched);
    }

    const seen = new Set();
    const unique = [];
    for (const node of allNodes) {
      const key = `${node.server}:${node.port}:${node.protocol}`;
      if (!seen.has(key)) {
        seen.add(key);
        node.country = getCountry(node);
        unique.push(node);
      }
    }

    console.log(`Unique nodes: ${unique.length}`);

    const tested = [];
    const batchSize = 25;
    for (let i = 0; i < unique.length; i += batchSize) {
      const batch = unique.slice(i, i + batchSize);
      const results = await Promise.all(batch.map(testNode));
      tested.push(...results);
    }

    let alive = tested.filter(n => n.alive && n.latency !== null);
    alive.sort((a, b) => a.latency - b.latency);

    nodes = alive;
    lastUpdated = new Date();

    console.log(`✅ Done. Alive nodes: ${nodes.length}`);
  } catch (err) {
    console.error('Update error:', err.message);
  } finally {
    updateInProgress = false;
  }
}

// ==================== SUBSCRIPTION GENERATORS ====================

function getBest() {
  return deduplicateNodes(nodes).slice(0, CONFIG.topLimit);
}

function getGood() {
  const deduped = deduplicateNodes(nodes);
  return deduped.slice(CONFIG.topLimit, CONFIG.topLimit * 2);
}

function getDiverseCountries() {
  const countryMap = new Map();
  
  for (const node of nodes) {
    if (!countryMap.has(node.country)) {
      countryMap.set(node.country, node);
    }
  }

  let diverse = Array.from(countryMap.values());
  diverse.sort((a, b) => a.latency - b.latency);
  return diverse.slice(0, CONFIG.topLimit);
}

function getMultiProtocol() {
  const deduped = deduplicateNodes(nodes);

  const vless   = deduped.filter(n => n.protocol === 'vless').slice(0, 8);
  const trojan  = deduped.filter(n => n.protocol === 'trojan').slice(0, 4);
  const ss      = deduped.filter(n => n.protocol === 'ss').slice(0, 4);
  const hysteria = deduped.filter(n => n.protocol === 'hysteria2').slice(0, 4);

  const mixed = [...vless, ...trojan, ...ss, ...hysteria];
  return deduplicateNodes(mixed).slice(0, CONFIG.topLimit);
}

function getFull() {
  return deduplicateNodes(nodes).slice(0, CONFIG.maxNodesPerSub);
}

// ==================== ROUTES ====================

app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: `${CONFIG.name} v${CONFIG.version}`,
    nodes: nodes.length,
    lastUpdated,
    endpoints: ['/best', '/good', '/diverse', '/multi', '/full', '/status']
  });
});

app.get('/health', (req, res) => res.json({ status: 'healthy' }));

app.get('/status', (req, res) => {
  res.json({
    name: CONFIG.name,
    version: CONFIG.version,
    total: nodes.length,
    lastUpdated,
    updateInProgress,
    urls: CONFIG.subscriptionUrls.length,
    interval: CONFIG.updateIntervalMinutes
  });
});

// ==================== SUBSCRIPTION ENDPOINTS ====================

app.get('/best', (req, res) => {
  const list = getBest();
  const sub = generateSubscription(list);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(Buffer.from(sub).toString('base64'));
});

app.get('/good', (req, res) => {
  const list = getGood();
  const sub = generateSubscription(list);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(Buffer.from(sub).toString('base64'));
});

app.get('/diverse', (req, res) => {
  const list = getDiverseCountries();
  const sub = generateSubscription(list);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(Buffer.from(sub).toString('base64'));
});

app.get('/multi', (req, res) => {
  const list = getMultiProtocol();
  const sub = generateSubscription(list);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(Buffer.from(sub).toString('base64'));
});

app.get('/full', (req, res) => {
  const list = getFull();
  const sub = generateSubscription(list);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(Buffer.from(sub).toString('base64'));
});

// ==================== CRON ====================

if (CONFIG.subscriptionUrls.length > 0) {
  const cronExpr = `*/${CONFIG.updateIntervalMinutes} * * * *`;
  cron.schedule(cronExpr, () => {
    console.log('⏰ Scheduled update');
    updateNodes();
  });

  setTimeout(updateNodes, 4000);
} else {
  console.log('⚠️ SUBSCRIPTION_URLS is empty. Add them in environment variables.');
}

// ==================== START ====================

app.listen(PORT, () => {
  console.log(`🚀 ${CONFIG.name} v${CONFIG.version} running on port ${PORT}`);
  console.log(`📡 Subscriptions: ${CONFIG.subscriptionUrls.length}`);
  console.log(`🔄 Update every ${CONFIG.updateIntervalMinutes} minutes`);
  console.log(`📍 Endpoints: /best | /good | /diverse | /multi | /full | /status`);
});
