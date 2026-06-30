import express from 'express';
import axios from 'axios';
import net from 'net';
import tls from 'tls';
import cron from 'node-cron';
import dotenv from 'dotenv';
import geoip from 'geoip-lite';
import base64 from 'base-64';
import TelegramBot from 'node-telegram-bot-api';
import QRCode from 'qrcode';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIG (с поддержкой env) ====================
const CONFIG = {
  // === Основные настройки сервиса ===
  name: process.env.SERVICE_NAME || "Zapretka",
  version: process.env.SERVICE_VERSION || "3.3.0",

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
  nodeNameFormat: process.env.NODE_NAME_FORMAT || "[flag] [country] #[number]",

  // === User-Agent для запросов подписок ===
  userAgent: process.env.USER_AGENT || "HiddifyNext/2.0.5",

  // === Telegram-бот ===
  botToken: process.env.BOT_TOKEN || '',
  // Публичный URL сервиса, из которого бот строит ссылки-подписки.
  // На Render это, например, https://zapretka.onrender.com
  baseUrl: process.env.BASE_URL || ''
};

// ==================== COUNTRY NAMES ====================
const countryNames = {
  // === Европа ===
  'RU': 'Россия', 'UA': 'Украина', 'BY': 'Беларусь', 'MD': 'Молдова',
  'DE': 'Германия', 'FR': 'Франция', 'GB': 'Великобритания', 'IE': 'Ирландия',
  'NL': 'Нидерланды', 'BE': 'Бельгия', 'LU': 'Люксембург',
  'IT': 'Италия', 'ES': 'Испания', 'PT': 'Португалия', 'AD': 'Андорра',
  'MT': 'Мальта', 'MC': 'Монако', 'SM': 'Сан-Марино', 'VA': 'Ватикан', 'GI': 'Гибралтар',
  'CH': 'Швейцария', 'AT': 'Австрия', 'LI': 'Лихтенштейн',
  'SE': 'Швеция', 'NO': 'Норвегия', 'FI': 'Финляндия', 'DK': 'Дания', 'IS': 'Исландия',
  'EE': 'Эстония', 'LV': 'Латвия', 'LT': 'Литва',
  'PL': 'Польша', 'CZ': 'Чехия', 'SK': 'Словакия', 'HU': 'Венгрия',
  'RO': 'Румыния', 'BG': 'Болгария', 'GR': 'Греция', 'CY': 'Кипр',
  'SI': 'Словения', 'HR': 'Хорватия', 'BA': 'Босния и Герцеговина',
  'RS': 'Сербия', 'ME': 'Черногория', 'MK': 'Северная Македония',
  'AL': 'Албания', 'XK': 'Косово',

  // === Кавказ / Закавказье ===
  'GE': 'Грузия', 'AM': 'Армения', 'AZ': 'Азербайджан',

  // === Северная Америка ===
  'US': 'США', 'CA': 'Канада', 'MX': 'Мексика',

  // === Южная Америка ===
  'BR': 'Бразилия', 'AR': 'Аргентина', 'CL': 'Чили', 'CO': 'Колумбия',
  'PE': 'Перу', 'VE': 'Венесуэла', 'UY': 'Уругвай', 'EC': 'Эквадор', 'BO': 'Боливия',

  // === Азия ===
  'CN': 'Китай', 'HK': 'Гонконг', 'TW': 'Тайвань', 'MO': 'Макао',
  'JP': 'Япония', 'KR': 'Южная Корея', 'KP': 'Северная Корея',
  'SG': 'Сингапур', 'MY': 'Малайзия', 'TH': 'Таиланд', 'VN': 'Вьетнам',
  'ID': 'Индонезия', 'PH': 'Филиппины', 'IN': 'Индия', 'PK': 'Пакистан',
  'BD': 'Бангладеш', 'LK': 'Шри-Ланка', 'NP': 'Непал',
  'KZ': 'Казахстан', 'UZ': 'Узбекистан', 'KG': 'Киргизия',
  'TJ': 'Таджикистан', 'TM': 'Туркменистан', 'MN': 'Монголия',

  // === Ближний Восток ===
  'TR': 'Турция', 'IL': 'Израиль', 'AE': 'ОАЭ', 'SA': 'Саудовская Аравия',
  'QA': 'Катар', 'KW': 'Кувейт', 'BH': 'Бахрейн', 'OM': 'Оман',
  'IR': 'Иран', 'IQ': 'Ирак', 'JO': 'Иордания', 'LB': 'Ливан', 'SY': 'Сирия',

  // === Африка ===
  'ZA': 'ЮАР', 'EG': 'Египет', 'MA': 'Марокко', 'NG': 'Нигерия',
  'KE': 'Кения', 'TN': 'Тунис', 'DZ': 'Алжир', 'GH': 'Гана', 'ET': 'Эфиопия',

  // === Океания ===
  'AU': 'Австралия', 'NZ': 'Новая Зеландия',

  'XX': 'Неизвестно'
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
  let text = rawText.trim();

  // Проверяем, есть ли протоколы в тексте
  const hasProtocol = text.includes('vless://') || 
                      text.includes('vmess://') || 
                      text.includes('trojan://') || 
                      text.includes('ss://') ||
                      text.includes('hysteria2://');

  // Если протоколов нет — всегда пробуем декодировать как base64
  if (!hasProtocol) {
    // Убираем все пробелы и переносы строк
    const clean = text.replace(/[\s\r\n]/g, '');

    try {
      // Пробуем декодировать base64
      const decoded = Buffer.from(clean, 'base64').toString('utf8');

      // Если после декодирования появились протоколы — используем
      if (decoded.includes('vless://') || 
          decoded.includes('vmess://') || 
          decoded.includes('trojan://') || 
          decoded.includes('ss://') ||
          decoded.includes('hysteria2://') ||
          decoded.includes('hy2://')) {
        
        console.log('📦 Обнаружен base64 — успешно декодировано');
        text = decoded;
      } else {
        // Показываем диагностику
        console.log('⚠️ Не удалось распознать формат подписки');
        console.log('Первые 500 символов:', text.substring(0, 500));
      }
    } catch (e) {
      console.log('⚠️ Ошибка декодирования base64');
    }
  }

  const lines = text.split(/\r?\n/);
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

    if (node && node.server && node.port) {
      nodes.push(node);
    }
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

// Проверка TLS-хендшейка к САМОМУ серверу ноды (а не к google.com).
// Для reality/tls нод сервер должен ответить корректным TLS на нужном SNI.
// latency считаем по времени до установления соединения (TCP+TLS).
async function testTLS(node, timeout = 6000) {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch {}
      resolve(result);
    };

    const socket = tls.connect({
      host: node.server,
      port: node.port,
      servername: node.sni || node.host || node.server,
      // Сертификат у reality/самоподписанных нод почти всегда «невалидный»
      // с точки зрения CA — нам важен сам факт ответа TLS, а не доверие.
      rejectUnauthorized: false,
      ALPNProtocols: ['h2', 'http/1.1']
    }, () => {
      done({ success: true, latency: Date.now() - start });
    });

    socket.setTimeout(timeout);
    socket.on('timeout', () => done({ success: false, latency: null }));
    socket.on('error', () => done({ success: false, latency: null }));
  });
}

async function testNode(node) {
  try {
    // hysteria2 работает поверх QUIC/UDP — TCP/TLS-проба к нему неприменима.
    // Не имея способа проверить UDP-датаграммы здесь, считаем такие ноды
    // потенциально живыми (TCP-проба часто не сработает, а отбрасывать жалко).
    if (node.protocol === 'hysteria2') {
      return {
        ...node,
        latency: 100,
        alive: true,
        testedAt: new Date()
      };
    }

    // 1) Базовая TCP-проба — открыт ли порт.
    const tcp = await testTCP(node);
    if (!tcp.success) {
      return { ...node, latency: null, alive: false };
    }

    // 2) Для tls/reality дополнительно проверяем TLS-хендшейк к самому серверу.
    //    Это отсеет ноды, где порт открыт, но TLS не отвечает.
    if (node.tls) {
      const tlsRes = await testTLS(node);
      return {
        ...node,
        latency: tlsRes.success ? tlsRes.latency : tcp.latency,
        alive: tlsRes.success,
        testedAt: new Date()
      };
    }

    // 3) Нешифрованные ноды — достаточно открытого TCP-порта.
    return {
      ...node,
      latency: tcp.latency,
      alive: true,
      testedAt: new Date()
    };
  } catch {
    return { ...node, latency: null, alive: false };
  }
}

// ==================== COUNTRY DETECTION ====================

const flagToCountry = {
  // Европа
  '🇷🇺': 'RU', '🇺🇦': 'UA', '🇧🇾': 'BY', '🇲🇩': 'MD',
  '🇩🇪': 'DE', '🇫🇷': 'FR', '🇬🇧': 'GB', '🇮🇪': 'IE',
  '🇳🇱': 'NL', '🇧🇪': 'BE', '🇱🇺': 'LU',
  '🇮🇹': 'IT', '🇪🇸': 'ES', '🇵🇹': 'PT', '🇦🇩': 'AD',
  '🇲🇹': 'MT', '🇲🇨': 'MC', '🇸🇲': 'SM', '🇻🇦': 'VA', '🇬🇮': 'GI',
  '🇨🇭': 'CH', '🇦🇹': 'AT', '🇱🇮': 'LI',
  '🇸🇪': 'SE', '🇳🇴': 'NO', '🇫🇮': 'FI', '🇩🇰': 'DK', '🇮🇸': 'IS',
  '🇪🇪': 'EE', '🇱🇻': 'LV', '🇱🇹': 'LT',
  '🇵🇱': 'PL', '🇨🇿': 'CZ', '🇸🇰': 'SK', '🇭🇺': 'HU',
  '🇷🇴': 'RO', '🇧🇬': 'BG', '🇬🇷': 'GR', '🇨🇾': 'CY',
  '🇸🇮': 'SI', '🇭🇷': 'HR', '🇧🇦': 'BA',
  '🇷🇸': 'RS', '🇲🇪': 'ME', '🇲🇰': 'MK',
  '🇦🇱': 'AL', '🇽🇰': 'XK',
  // Кавказ
  '🇬🇪': 'GE', '🇦🇲': 'AM', '🇦🇿': 'AZ',
  // Северная Америка
  '🇺🇸': 'US', '🇨🇦': 'CA', '🇲🇽': 'MX',
  // Южная Америка
  '🇧🇷': 'BR', '🇦🇷': 'AR', '🇨🇱': 'CL', '🇨🇴': 'CO',
  '🇵🇪': 'PE', '🇻🇪': 'VE', '🇺🇾': 'UY', '🇪🇨': 'EC', '🇧🇴': 'BO',
  // Азия
  '🇨🇳': 'CN', '🇭🇰': 'HK', '🇹🇼': 'TW', '🇲🇴': 'MO',
  '🇯🇵': 'JP', '🇰🇷': 'KR', '🇰🇵': 'KP',
  '🇸🇬': 'SG', '🇲🇾': 'MY', '🇹🇭': 'TH', '🇻🇳': 'VN',
  '🇮🇩': 'ID', '🇵🇭': 'PH', '🇮🇳': 'IN', '🇵🇰': 'PK',
  '🇧🇩': 'BD', '🇱🇰': 'LK', '🇳🇵': 'NP',
  '🇰🇿': 'KZ', '🇺🇿': 'UZ', '🇰🇬': 'KG',
  '🇹🇯': 'TJ', '🇹🇲': 'TM', '🇲🇳': 'MN',
  // Ближний Восток
  '🇹🇷': 'TR', '🇮🇱': 'IL', '🇦🇪': 'AE', '🇸🇦': 'SA',
  '🇶🇦': 'QA', '🇰🇼': 'KW', '🇧🇭': 'BH', '🇴🇲': 'OM',
  '🇮🇷': 'IR', '🇮🇶': 'IQ', '🇯🇴': 'JO', '🇱🇧': 'LB', '🇸🇾': 'SY',
  // Африка
  '🇿🇦': 'ZA', '🇪🇬': 'EG', '🇲🇦': 'MA', '🇳🇬': 'NG',
  '🇰🇪': 'KE', '🇹🇳': 'TN', '🇩🇿': 'DZ', '🇬🇭': 'GH', '🇪🇹': 'ET',
  // Океания
  '🇦🇺': 'AU', '🇳🇿': 'NZ',
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

async function fetchSubscription(url, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await axios.get(url, {
        timeout: 18000,
        headers: {
          // ВАЖНО: 'Accept: */*', а НЕ 'text/html'.
          // Многие панели подписок (в т.ч. AccarVPN) при Accept: text/html
          // считают, что зашёл браузер, и отдают HTML-страницу вместо конфигов.
          'User-Agent': CONFIG.userAgent,
          'Accept': '*/*'
        },
        maxRedirects: 5,
        // Не даём axios преобразовывать тело — нам нужна сырая строка с подпиской.
        responseType: 'text',
        transformResponse: [(data) => data]
      });

      // ---- Диагностика ответа ----
      const body = typeof res.data === 'string' ? res.data : String(res.data ?? '');
      const ct = res.headers?.['content-type'] || 'unknown';
      const looksHtml = body.trimStart().toLowerCase().startsWith('<!doctype') ||
                        body.trimStart().toLowerCase().startsWith('<html');
      console.log(`  ↳ status=${res.status} content-type=${ct} bytes=${body.length}${looksHtml ? ' ⚠️ ПОХОЖЕ НА HTML-СТРАНИЦУ' : ''}`);

      const parsed = parseSubscription(body);
      console.log(`✓ Fetched from ${url} → ${parsed.length} nodes`);
      return parsed;

    } catch (err) {
      const isLastAttempt = attempt === retries;
      
      if (isLastAttempt) {
        console.error(`✗ Fetch failed after ${retries + 1} attempts: ${url} - ${err.message}`);
        return [];
      } else {
        console.warn(`⚠️ Attempt ${attempt + 1} failed for ${url}, retrying...`);
        await new Promise(resolve => setTimeout(resolve, 1200));
      }
    }
  }
  
  return [];
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

// ==================== CUSTOM FILTERING ====================

// Нормализует параметр: 'all'/'any'/'' → null (без фильтра),
// иначе массив значений в нижнем регистре (поддержка списка через запятую).
function parseFilterParam(value) {
  if (value === undefined || value === null) return null;
  const v = String(value).trim().toLowerCase();
  if (v === '' || v === 'all' || v === 'any' || v === '*') return null;
  return v.split(',').map(s => s.trim()).filter(Boolean);
}

// Алиасы протоколов, чтобы /sub/hy2/... и /sub/hysteria/... тоже работали.
const protocolAliases = {
  'hy2': 'hysteria2',
  'hysteria': 'hysteria2',
  'shadowsocks': 'ss',
  'v2ray': 'vmess'
};

function normalizeProtocol(p) {
  return protocolAliases[p] || p;
}

// Главный фильтр: protocol + country + count.
// protocolFilter / countryFilter: null = любой, либо массив допустимых значений.
function filterNodes({ protocol, country, count }) {
  const protoFilter = parseFilterParam(protocol)?.map(normalizeProtocol) || null;
  const countryFilter = parseFilterParam(country)?.map(c => c.toUpperCase()) || null;

  let list = deduplicateNodes(nodes);

  if (protoFilter) {
    list = list.filter(n => protoFilter.includes(n.protocol));
  }
  if (countryFilter) {
    list = list.filter(n => countryFilter.includes((n.country || 'XX').toUpperCase()));
  }

  // Уже отсортировано по latency в updateNodes(), но пересортируем на всякий случай.
  list = [...list].sort((a, b) => (a.latency ?? Infinity) - (b.latency ?? Infinity));

  // count: целое > 0, либо без лимита.
  const n = parseInt(count, 10);
  if (Number.isFinite(n) && n > 0) {
    list = list.slice(0, n);
  } else {
    list = list.slice(0, CONFIG.maxNodesPerSub);
  }

  return list;
}

// Отдаём подписку в base64 (как ожидают клиенты).
function sendSubscription(res, list) {
  const sub = generateSubscription(list);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Profile-Update-Interval', String(CONFIG.updateIntervalMinutes));
  res.send(Buffer.from(sub).toString('base64'));
}


// Сводка по живым нодам: total + разбивка по протоколам и странам.
// Используется и эндпоинтом /status, и Telegram-ботом.
function computeStats() {
  const byProtocol = {};
  const byCountry = {};
  for (const n of nodes) {
    byProtocol[n.protocol] = (byProtocol[n.protocol] || 0) + 1;
    const c = (n.country || 'XX').toUpperCase();
    byCountry[c] = (byCountry[c] || 0) + 1;
  }
  return { total: nodes.length, byProtocol, byCountry };
}

// ==================== ROUTES ====================

app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: `${CONFIG.name} v${CONFIG.version}`,
    nodes: nodes.length,
    lastUpdated,
    usage: {
      custom: '/sub/:protocol/:country/:count',
      examples: [
        '/sub/vless/RU/10        → 10 быстрейших vless-нод из России',
        '/sub/all/all/20         → 20 любых нод (любой протокол, любая страна)',
        '/sub/vless/all/0        → все vless-ноды (count=0 = без лимита)',
        '/sub/vless,trojan/RU,DE/15 → vless+trojan из RU и DE, до 15 шт',
        '/sub/all/DE/5           → 5 нод из Германии'
      ],
      notes: [
        "protocol: vless | vmess | trojan | ss | hysteria2 | all (можно списком через запятую)",
        "country: ISO-код (RU, DE, US...) | all (можно списком через запятую)",
        "count: число > 0, либо 0/all для всех нод"
      ]
    },
    endpoints: ['/sub/:protocol/:country/:count', '/status', '/health']
  });
});

app.get('/health', (req, res) => res.json({ status: 'healthy' }));

app.get('/status', (req, res) => {
  const stats = computeStats();
  res.json({
    name: CONFIG.name,
    version: CONFIG.version,
    total: stats.total,
    byProtocol: stats.byProtocol,
    byCountry: stats.byCountry,
    lastUpdated,
    updateInProgress,
    urls: CONFIG.subscriptionUrls.length,
    interval: CONFIG.updateIntervalMinutes
  });
});

// ==================== CUSTOM SUBSCRIPTION ENDPOINT ====================
// /sub/:protocol/:country/:count
//   protocol — vless | vmess | trojan | ss | hysteria2 | all | список через запятую
//   country  — RU | DE | US ... | all | список через запятую
//   count    — число (>0); 0 или all = без лимита
//
// Параметры country и count необязательны:
//   /sub/vless            → все vless, любая страна
//   /sub/vless/RU         → vless из RU, без лимита по количеству
//   /sub/vless/RU/10      → 10 быстрейших vless из RU

app.get('/sub/:protocol/:country/:count', (req, res) => {
  const { protocol, country, count } = req.params;
  sendSubscription(res, filterNodes({ protocol, country, count }));
});

app.get('/sub/:protocol/:country', (req, res) => {
  const { protocol, country } = req.params;
  sendSubscription(res, filterNodes({ protocol, country, count: 0 }));
});

app.get('/sub/:protocol', (req, res) => {
  const { protocol } = req.params;
  sendSubscription(res, filterNodes({ protocol, country: 'all', count: 0 }));
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

// ==================== TELEGRAM BOT: конструктор подписок ====================
// Бот-конструктор ссылок: пользователь через inline-кнопки выбирает
// протокол → страну → количество и получает готовую ссылку вида
//   https://<BASE_URL>/sub/vless/RU/10
// плюс QR-код для быстрого импорта в клиент (Happ / v2rayNG / Hiddify и т.п.).
// Работает в long-polling режиме, в том же процессе, что и веб-сервер.

// Русские названия протоколов для кнопок.
const PROTOCOL_LABELS = {
  all: 'Любой протокол',
  vless: 'VLESS',
  vmess: 'VMess',
  trojan: 'Trojan',
  ss: 'Shadowsocks',
  hysteria2: 'Hysteria2'
};

// Варианты количества для кнопок.
const COUNT_OPTIONS = [5, 10, 20, 50, 0]; // 0 = все

// Безопасное экранирование для HTML-разметки Telegram.
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * startBot — поднимает Telegram-бота.
 * @param {object} deps
 * @param {string} deps.token        — токен бота (BOT_TOKEN)
 * @param {string} deps.baseUrl      — базовый публичный URL сервиса (BASE_URL)
 * @param {object} deps.countryNames — словарь { 'RU': 'Россия', ... }
 * @param {function} deps.getStats   — () => { byProtocol:{}, byCountry:{}, total:number }
 */
function startBot({ token, baseUrl, countryNames, getStats }) {
  if (!token) {
    console.log('⚠️ BOT_TOKEN не задан — Telegram-бот не запущен.');
    return null;
  }
  if (!baseUrl) {
    console.log('⚠️ BASE_URL не задан — бот не сможет строить ссылки. Укажи BASE_URL в env.');
    return null;
  }

  const base = baseUrl.replace(/\/+$/, ''); // без хвостового слэша
  const bot = new TelegramBot(token, { polling: true });

  // Хранилище незавершённых выборов: chatId -> { protocol, country }
  const sessions = new Map();

  const codeToName = (code) =>
    (countryNames && countryNames[code]) ? countryNames[code] : code;

  // ---------- Клавиатуры ----------

  function protocolKeyboard() {
    const stats = getStats();
    const available = stats.byProtocol || {};
    const rows = [];
    let row = [];

    // 'all' всегда доступен.
    row.push({ text: PROTOCOL_LABELS.all, callback_data: 'p:all' });

    for (const proto of ['vless', 'vmess', 'trojan', 'ss', 'hysteria2']) {
      const cnt = available[proto] || 0;
      if (cnt === 0) continue; // не показываем протоколы, которых нет
      row.push({ text: `${PROTOCOL_LABELS[proto]} (${cnt})`, callback_data: `p:${proto}` });
      if (row.length === 2) { rows.push(row); row = []; }
    }
    if (row.length) rows.push(row);

    return { inline_keyboard: rows };
  }

  function countryKeyboard(protocol) {
    const stats = getStats();
    const byCountry = stats.byCountry || {};

    // Список стран, отсортированный по числу нод (по убыванию).
    const entries = Object.entries(byCountry)
      .filter(([, n]) => n > 0)
      .sort((a, b) => b[1] - a[1]);

    const rows = [[{ text: '🌍 Любая страна', callback_data: 'c:all' }]];
    let row = [];
    for (const [code, n] of entries) {
      row.push({ text: `${codeToName(code)} (${n})`, callback_data: `c:${code}` });
      if (row.length === 2) { rows.push(row); row = []; }
    }
    if (row.length) rows.push(row);

    rows.push([{ text: '« Назад к протоколу', callback_data: 'back:protocol' }]);
    return { inline_keyboard: rows };
  }

  function countKeyboard() {
    const rows = [];
    let row = [];
    for (const c of COUNT_OPTIONS) {
      row.push({ text: c === 0 ? 'Все' : String(c), callback_data: `n:${c}` });
      if (row.length === 3) { rows.push(row); row = []; }
    }
    if (row.length) rows.push(row);
    rows.push([{ text: '« Назад к стране', callback_data: 'back:country' }]);
    return { inline_keyboard: rows };
  }

  // ---------- Формирование итоговой ссылки ----------

  function buildSubUrl({ protocol, country, count }) {
    const p = protocol || 'all';
    const c = country || 'all';
    const n = (count === undefined || count === null) ? 0 : count;
    return `${base}/sub/${p}/${c}/${n}`;
  }

  async function sendResult(chatId, sel) {
    const url = buildSubUrl(sel);
    const protoLabel = PROTOCOL_LABELS[sel.protocol] || sel.protocol;
    const countryLabel = sel.country === 'all' ? 'Любая страна' : codeToName(sel.country);
    const countLabel = (!sel.count || sel.count === 0) ? 'Все' : String(sel.count);

    const caption =
      `✅ <b>Ваша подписка готова</b>\n\n` +
      `🔌 Протокол: <b>${escapeHtml(protoLabel)}</b>\n` +
      `📍 Страна: <b>${escapeHtml(countryLabel)}</b>\n` +
      `🔢 Количество: <b>${escapeHtml(countLabel)}</b>\n\n` +
      `🔗 <code>${escapeHtml(url)}</code>\n\n` +
      `Скопируйте ссылку или отсканируйте QR-код в вашем VPN-клиенте.`;

    try {
      const png = await QRCode.toBuffer(url, { width: 512, margin: 2 });
      await bot.sendPhoto(chatId, png, {
        caption,
        parse_mode: 'HTML',
        reply_markup: {
          inline_keyboard: [[{ text: '🔄 Создать ещё', callback_data: 'restart' }]]
        }
      }, { filename: 'subscription.png', contentType: 'image/png' });
    } catch (e) {
      // Если QR не сгенерировался — хотя бы отправим ссылку текстом.
      await bot.sendMessage(chatId, caption, {
        parse_mode: 'HTML',
        reply_markup: {
          inline_keyboard: [[{ text: '🔄 Создать ещё', callback_data: 'restart' }]]
        }
      });
    }
  }

  // ---------- Стартовое сообщение ----------

  async function sendStart(chatId, messageId) {
    const stats = getStats();
    const total = stats.total || 0;
    const text =
      `👋 <b>Конструктор подписок</b>\n\n` +
      `Сейчас доступно живых нод: <b>${total}</b>\n\n` +
      `Шаг 1 из 3 — выберите протокол:`;

    const opts = { parse_mode: 'HTML', reply_markup: protocolKeyboard() };
    sessions.delete(chatId);

    if (messageId) {
      try {
        await bot.editMessageText(text, { chat_id: chatId, message_id: messageId, ...opts });
        return;
      } catch { /* fallthrough to sendMessage */ }
    }
    await bot.sendMessage(chatId, text, opts);
  }

  // ---------- Команды ----------

  bot.onText(/^\/start$/, (msg) => sendStart(msg.chat.id));

  bot.onText(/^\/help$/, (msg) => {
    bot.sendMessage(msg.chat.id,
      `ℹ️ <b>Как пользоваться</b>\n\n` +
      `1. /start — открыть конструктор\n` +
      `2. Выберите протокол → страну → количество\n` +
      `3. Получите ссылку и QR-код для импорта\n\n` +
      `Ссылка имеет вид:\n<code>${escapeHtml(base)}/sub/&lt;протокол&gt;/&lt;страна&gt;/&lt;кол-во&gt;</code>`,
      { parse_mode: 'HTML' });
  });

  // ---------- Обработка кнопок ----------

  bot.on('callback_query', async (q) => {
    const chatId = q.message.chat.id;
    const messageId = q.message.message_id;
    const data = q.data || '';

    try {
      // Перезапуск / возвраты могут потребовать пересоздать сообщение,
      // т.к. предыдущее могло быть фото (его текст редактировать нельзя).
      const editMenu = async (text, keyboard) => {
        const opts = { parse_mode: 'HTML', reply_markup: keyboard };
        try {
          await bot.editMessageText(text, { chat_id: chatId, message_id: messageId, ...opts });
        } catch {
          await bot.sendMessage(chatId, text, opts);
        }
      };

      if (data === 'restart' || data === 'back:protocol') {
        const stats = getStats();
        sessions.delete(chatId);
        await editMenu(
          `👋 <b>Конструктор подписок</b>\n\nДоступно живых нод: <b>${stats.total || 0}</b>\n\nШаг 1 из 3 — выберите протокол:`,
          protocolKeyboard()
        );
        return bot.answerCallbackQuery(q.id);
      }

      if (data.startsWith('p:')) {
        const protocol = data.slice(2);
        sessions.set(chatId, { protocol });
        await editMenu(
          `🔌 Протокол: <b>${escapeHtml(PROTOCOL_LABELS[protocol] || protocol)}</b>\n\nШаг 2 из 3 — выберите страну:`,
          countryKeyboard(protocol)
        );
        return bot.answerCallbackQuery(q.id);
      }

      if (data === 'back:country') {
        const sel = sessions.get(chatId) || {};
        await editMenu(
          `🔌 Протокол: <b>${escapeHtml(PROTOCOL_LABELS[sel.protocol] || sel.protocol || 'Любой')}</b>\n\nШаг 2 из 3 — выберите страну:`,
          countryKeyboard(sel.protocol)
        );
        return bot.answerCallbackQuery(q.id);
      }

      if (data.startsWith('c:')) {
        const country = data.slice(2);
        const sel = sessions.get(chatId) || {};
        sel.country = country;
        sessions.set(chatId, sel);
        await editMenu(
          `🔌 Протокол: <b>${escapeHtml(PROTOCOL_LABELS[sel.protocol] || sel.protocol)}</b>\n` +
          `📍 Страна: <b>${escapeHtml(country === 'all' ? 'Любая' : codeToName(country))}</b>\n\n` +
          `Шаг 3 из 3 — выберите количество нод:`,
          countKeyboard()
        );
        return bot.answerCallbackQuery(q.id);
      }

      if (data.startsWith('n:')) {
        const count = parseInt(data.slice(2), 10) || 0;
        const sel = sessions.get(chatId) || {};
        sel.count = count;
        sessions.set(chatId, sel);
        await bot.answerCallbackQuery(q.id, { text: 'Генерирую ссылку и QR…' });
        // Удаляем меню-сообщение, чтобы не мешалось, и отправляем результат отдельным фото.
        try { await bot.deleteMessage(chatId, messageId); } catch {}
        await sendResult(chatId, sel);
        sessions.delete(chatId);
        return;
      }

      return bot.answerCallbackQuery(q.id);
    } catch (err) {
      console.error('Bot callback error:', err.message);
      try { await bot.answerCallbackQuery(q.id, { text: 'Ошибка, попробуйте /start' }); } catch {}
    }
  });

  bot.on('polling_error', (err) => {
    console.error('Telegram polling error:', err.code || err.message);
  });

  console.log('🤖 Telegram-бот запущен (long-polling).');
  return bot;
}

// ==================== START ====================

app.listen(PORT, () => {
  console.log(`🚀 ${CONFIG.name} v${CONFIG.version} running on port ${PORT}`);
  console.log(`📡 Subscriptions: ${CONFIG.subscriptionUrls.length}`);
  console.log(`🔄 Update every ${CONFIG.updateIntervalMinutes} minutes`);
  console.log(`📍 Endpoint: /sub/:protocol/:country/:count  (например /sub/vless/RU/10)`);
  console.log(`📍 Также: /status | /health`);

  // ==================== TELEGRAM BOT ====================
  // На Render публичный URL доступен в RENDER_EXTERNAL_URL — используем его,
  // если BASE_URL не задан явно.
  const baseUrl = CONFIG.baseUrl || process.env.RENDER_EXTERNAL_URL || '';
  startBot({
    token: CONFIG.botToken,
    baseUrl,
    countryNames,
    getStats: computeStats   // бот читает статистику напрямую, в том же процессе
  });
});
