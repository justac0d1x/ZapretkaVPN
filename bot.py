#!/usr/bin/env python3
"""
Python rewrite of the Node.js subscription bot.
- No subscription fetching / pinging / testing.
- One ready-made subscription is provided directly in code (or loaded from file).
- Filtering by protocol / country / count.
"""

import os
import base64
import json
from typing import List, Dict, Any, Optional
from urllib.parse import quote, unquote, urlparse, parse_qs

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse, Response
import uvicorn

from aiogram import Bot, Dispatcher, types, F
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, BufferedInputFile
from aiogram.filters import Command
from aiogram.enums import ParseMode
import qrcode
from io import BytesIO

# ==================== CONFIG ====================
CONFIG = {
    "SERVICE_NAME": os.getenv("SERVICE_NAME", "Zapretka"),
    "SERVICE_VERSION": os.getenv("SERVICE_VERSION", "4.0.0-py"),
    "BOT_TOKEN": os.getenv("BOT_TOKEN", ""),
    # Render автоматически предоставляет RENDER_EXTERNAL_URL
    "BASE_URL": os.getenv("BASE_URL") or os.getenv("RENDER_EXTERNAL_URL", ""),
    "PORT": int(os.getenv("PORT", 8000)),
}

# ==================== SUBSCRIPTION FROM URL ====================
async def fetch_subscription(url: str) -> str:
    """Загружает подписку по ссылке (поддерживает обычный текст и base64)"""
    if not url:
        return ""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={"User-Agent": "HiddifyNext/2.5.7"})
        resp.raise_for_status()
        text = resp.text.strip()

        # Если это base64 — декодируем
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
            if any(proto in decoded for proto in ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://"]):
                return decoded
        except Exception:
            pass

        return text

# ==================== COUNTRY NAMES ====================
country_names = {
    'RU': 'Россия', 'UA': 'Украина', 'BY': 'Беларусь', 'MD': 'Молдова',
    'DE': 'Германия', 'FR': 'Франция', 'GB': 'Великобритания', 'IE': 'Ирландия',
    'NL': 'Нидерланды', 'BE': 'Бельгия', 'LU': 'Люксембург',
    'IT': 'Италия', 'ES': 'Испания', 'PT': 'Португалия',
    'CH': 'Швейцария', 'AT': 'Австрия',
    'SE': 'Швеция', 'NO': 'Норвегия', 'FI': 'Финляндия', 'DK': 'Дания',
    'EE': 'Эстония', 'LV': 'Латвия', 'LT': 'Литва',
    'PL': 'Польша', 'CZ': 'Чехия', 'SK': 'Словакия', 'HU': 'Венгрия',
    'RO': 'Румыния', 'BG': 'Болгария', 'GR': 'Греция',
    'US': 'США', 'CA': 'Канада',
    'BR': 'Бразилия', 'AR': 'Аргентина',
    'CN': 'Китай', 'HK': 'Гонконг', 'JP': 'Япония', 'KR': 'Южная Корея',
    'SG': 'Сингапур', 'MY': 'Малайзия', 'TH': 'Таиланд',
    'TR': 'Турция', 'IL': 'Израиль', 'AE': 'ОАЭ',
    'XX': 'Неизвестно'
}

def get_flag_emoji(code: str) -> str:
    """Возвращает эмодзи флага страны по ее 2-буквенному коду"""
    code = code.upper()
    if code == 'XX':
        return '❓'
    if len(code) == 2 and all(65 <= ord(char) <= 90 for char in code):
        return "".join(chr(127397 + ord(char)) for char in code)
    return "🌐"

PROTOCOL_LABELS = {
    'all': '🌐 Все протоколы',
    'vless': '🔒 VLESS',
    'vmess': '🚀 VMess',
    'trojan': '🐴 Trojan',
    'ss': '🕶️ Shadowsocks',
    'hysteria2': '⚡ Hysteria2'
}

COUNT_OPTIONS = [5, 10, 20, 0]  # 0 = all

# ==================== PARSE READY SUBSCRIPTION ====================
def parse_ready_subscription(text: str) -> List[Dict[str, Any]]:
    nodes = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        node = None
        if line.startswith('vless://'):
            node = parse_vless(line)
        elif line.startswith('vmess://'):
            node = parse_vmess(line)
        elif line.startswith('trojan://'):
            node = parse_trojan(line)
        elif line.startswith('ss://'):
            node = parse_shadowsocks(line)
        elif line.startswith(('hysteria2://', 'hy2://')):
            node = parse_hysteria2(line)
        if node:
            nodes.append(node)
    return nodes

def parse_vless(link: str) -> Optional[Dict]:
    try:
        url = urlparse(link)
        params = parse_qs(url.query)
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": "vless",
            "name": name,
            "server": url.hostname,
            "port": int(url.port or 443),
            "uuid": url.username,
            "raw": link,
            "country": extract_country(name)
        }
    except:
        return None

def parse_vmess(link: str) -> Optional[Dict]:
    try:
        data = base64.b64decode(link.replace('vmess://', '')).decode()
        cfg = json.loads(data)
        name = cfg.get('ps', cfg.get('add', 'vmess'))
        return {
            "protocol": "vmess",
            "name": name,
            "server": cfg.get('add'),
            "port": int(cfg.get('port', 443)),
            "raw": link,
            "country": extract_country(name)
        }
    except:
        return None

def parse_trojan(link: str) -> Optional[Dict]:
    try:
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": "trojan",
            "name": name,
            "server": url.hostname,
            "port": int(url.port or 443),
            "raw": link,
            "country": extract_country(name)
        }
    except:
        return None

def parse_shadowsocks(link: str) -> Optional[Dict]:
    try:
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": "ss",
            "name": name,
            "server": url.hostname,
            "port": int(url.port or 443),
            "raw": link,
            "country": extract_country(name)
        }
    except:
        return None

def parse_hysteria2(link: str) -> Optional[Dict]:
    try:
        url = urlparse(link.replace('hy2://', 'hysteria2://'))
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": "hysteria2",
            "name": name,
            "server": url.hostname,
            "port": int(url.port or 443),
            "raw": link,
            "country": extract_country(name)
        }
    except:
        return None

def extract_country(name: str) -> str:
    flag_to_country = {
        '🇷🇺': 'RU', '🇩🇪': 'DE', '🇫🇷': 'FR', '🇸🇬': 'SG', '🇺🇸': 'US'
    }
    for flag, code in flag_to_country.items():
        if flag in name:
            return code
    return 'XX'

# Глобальный список нод (загружается при старте)
NODES: List[Dict[str, Any]] = []

async def load_nodes():
    """Загружает ноды из подписки (по URL или из переменной окружения)"""
    global NODES
    sub_url = os.getenv("NODE_URL", "").strip()

    if sub_url:
        try:
            raw = await fetch_subscription(sub_url)
            NODES = parse_ready_subscription(raw)
            print(f"✅ Загружено {len(NODES)} нод из подписки")
        except Exception as e:
            print(f"❌ Ошибка загрузки подписки: {e}")
            NODES = []
    else:
        print("⚠️ NODE_URL не задан — ноды не загружены")
        NODES = []

# ==================== FILTERING ====================
def filter_nodes(protocol: str = "all", country: str = "all", count: int = 0) -> List[Dict]:
    result = NODES.copy()

    # Нормализуем параметры для регистронезависимого поиска
    protocol = protocol.lower()
    country = country.upper()

    if protocol != "all":
        result = [n for n in result if n["protocol"] == protocol]

    if country != "ALL":
        result = [n for n in result if n.get("country") == country]

    if count > 0:
        result = result[:count]

    return result

def generate_subscription(nodes: List[Dict]) -> str:
    if not nodes:
        return ""
    return "\n".join(n["raw"] for n in nodes)

def get_stats(protocol: str = "all"):
    """Возвращает статистику по нодам, при необходимости фильтруя страны по выбранному протоколу"""
    by_protocol = {}
    by_country = {}
    total_nodes = 0
    for node in NODES:
        p = node["protocol"]
        c = node.get("country", "XX")
        by_protocol[p] = by_protocol.get(p, 0) + 1
        
        # Если фильтр протокола активен, считаем страны только для этого протокола
        if protocol == "all" or p == protocol:
            by_country[c] = by_country.get(c, 0) + 1
            total_nodes += 1
            
    return {
        "total": total_nodes,
        "byProtocol": by_protocol,
        "byCountry": by_country
    }

# ==================== FASTAPI ====================
app = FastAPI(title=CONFIG["SERVICE_NAME"])

@app.get("/sub/{protocol}/{country}/{count}")
async def get_subscription(protocol: str, country: str, count: int):
    nodes = filter_nodes(protocol, country, count)
    content = generate_subscription(nodes)
    if not content:
        raise HTTPException(status_code=404, detail="No nodes found")
    return PlainTextResponse(content, media_type="text/plain")

@app.get("/status")
async def status():
    stats = get_stats()
    return {"status": "ok", "nodes": stats}

@app.get("/health")
async def health():
    return {"status": "healthy"}

# ==================== TELEGRAM BOT ====================
bot = None
dp = None

if CONFIG["BOT_TOKEN"]:
    bot = Bot(token=CONFIG["BOT_TOKEN"])
    dp = Dispatcher()

    sessions = {}

    def code_to_name(code: str) -> str:
        return country_names.get(code, code)

    def protocol_keyboard():
        stats = get_stats()
        available = stats["byProtocol"]
        rows = []
        row = []
        row.append(InlineKeyboardButton(text=PROTOCOL_LABELS["all"], callback_data="p:all"))
        for proto in ["vless", "vmess", "trojan", "ss", "hysteria2"]:
            cnt = available.get(proto, 0)
            if cnt == 0:
                continue
            row.append(InlineKeyboardButton(
                text=f"{PROTOCOL_LABELS[proto]} ({cnt})",
                callback_data=f"p:{proto}"
            ))
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def country_keyboard(protocol: str):
        stats = get_stats(protocol)
        by_country = stats["byCountry"]
        entries = sorted(by_country.items(), key=lambda x: -x[1])

        rows = [[InlineKeyboardButton(text="🌍 Любая страна", callback_data="c:all")]]
        row = []
        for code, n in entries:
            row.append(InlineKeyboardButton(
                text=f"{get_flag_emoji(code)} {code_to_name(code)} ({n})",
                callback_data=f"c:{code}"
            ))
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        rows.append([InlineKeyboardButton(text="« Назад к протоколу", callback_data="back:protocol")])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def count_keyboard():
        rows = []
        row = []
        for c in COUNT_OPTIONS:
            row.append(InlineKeyboardButton(
                text="Все" if c == 0 else str(c),
                callback_data=f"n:{c}"
            ))
            if len(row) == 3:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        rows.append([InlineKeyboardButton(text="« Назад к стране", callback_data="back:country")])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def build_sub_url(protocol: str, country: str, count: int) -> str:
        base = CONFIG["BASE_URL"].rstrip("/")
        return f"{base}/sub/{protocol}/{country}/{count}"

    async def send_result(chat_id: int, sel: dict):
        url = build_sub_url(sel.get("protocol", "all"), sel.get("country", "all"), sel.get("count", 0))
        proto_label = PROTOCOL_LABELS.get(sel.get("protocol"), sel.get("protocol"))
        
        country_code = sel.get("country", "all")
        if country_code == "all":
            country_label = "🌍 Любая страна"
        else:
            country_label = f"{get_flag_emoji(country_code)} {code_to_name(country_code)}"
            
        count_label = "Все" if not sel.get("count") else str(sel.get("count"))

        caption = (
            f"✅ <b>Ваша подписка готова</b>\n\n"
            f"🔌 Протокол: <b>{proto_label}</b>\n"
            f"📍 Страна: <b>{country_label}</b>\n"
            f"🔢 Количество: <b>{count_label}</b>\n\n"
            f"🔗 <code>{url}</code>"
        )

        # Generate QR
        qr = qrcode.make(url)
        buf = BytesIO()
        qr.save(buf, format="PNG")
        buf.seek(0)

        await bot.send_photo(
            chat_id,
            photo=BufferedInputFile(buf.getvalue(), filename="qr.png"),
            caption=caption,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="🔄 Создать ещё", callback_data="restart")
            ]])
        )

    @dp.message(Command("start"))
    async def cmd_start(message: types.Message):
        stats = get_stats()
        text = f"👋 <b>Конструктор подписок</b>\n\nДоступно нод: <b>{stats['total']}</b>\n\nШаг 1 из 3 — выберите протокол:"
        await message.answer(text, parse_mode=ParseMode.HTML, reply_markup=protocol_keyboard())
        sessions.pop(message.chat.id, None)

    @dp.callback_query(F.data.startswith("p:"))
    async def cb_protocol(query: types.CallbackQuery):
        protocol = query.data.split(":")[1]
        sessions[query.message.chat.id] = {"protocol": protocol}
        await query.message.edit_text(
            f"🔌 Протокол: <b>{PROTOCOL_LABELS.get(protocol, protocol)}</b>\n\nШаг 2 из 3 — выберите страну:",
            parse_mode=ParseMode.HTML,
            reply_markup=country_keyboard(protocol)
        )
        await query.answer()

    @dp.callback_query(F.data.startswith("c:"))
    async def cb_country(query: types.CallbackQuery):
        country = query.data.split(":")[1]
        sel = sessions.get(query.message.chat.id, {})
        sel["country"] = country
        sessions[query.message.chat.id] = sel
        
        country_display = "🌍 Любая страна" if country == "all" else f"{get_flag_emoji(country)} {code_to_name(country)}"
        
        await query.message.edit_text(
            f"🔌 Протокол: <b>{PROTOCOL_LABELS.get(sel.get('protocol'), sel.get('protocol'))}</b>\n"
            f"📍 Страна: <b>{country_display}</b>\n\n"
            f"Шаг 3 из 3 — выберите количество:",
            parse_mode=ParseMode.HTML,
            reply_markup=count_keyboard()
        )
        await query.answer()

    @dp.callback_query(F.data.startswith("n:"))
    async def cb_count(query: types.CallbackQuery):
        count = int(query.data.split(":")[1])
        sel = sessions.get(query.message.chat.id, {})
        sel["count"] = count
        await query.answer("Генерирую ссылку...")
        try:
            await query.message.delete()
        except:
            pass
        await send_result(query.message.chat.id, sel)
        sessions.pop(query.message.chat.id, None)

    @dp.callback_query(F.data == "restart")
    async def cb_restart(query: types.CallbackQuery):
        stats = get_stats()
        text = f"👋 <b>Конструктор подписок</b>\n\nДоступно нод: <b>{stats['total']}</b>\n\nШаг 1 из 3 — выберите протокол:"
        await query.message.answer(text, parse_mode=ParseMode.HTML, reply_markup=protocol_keyboard())
        sessions.pop(query.message.chat.id, None)
        await query.answer()

    @dp.callback_query(F.data == "back:protocol")
    async def cb_back_protocol(query: types.CallbackQuery):
        stats = get_stats()
        text = f"👋 <b>Конструктор подписок</b>\n\nДоступно нод: <b>{stats['total']}</b>\n\nШаг 1 из 3 — выберите протокол:"
        await query.message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=protocol_keyboard())
        await query.answer()

    @dp.callback_query(F.data == "back:country")
    async def cb_back_country(query: types.CallbackQuery):
        sel = sessions.get(query.message.chat.id, {})
        await query.message.edit_text(
            f"🔌 Протокол: <b>{PROTOCOL_LABELS.get(sel.get('protocol'), sel.get('protocol'))}</b>\n\nШаг 2 из 3 — выберите страну:",
            parse_mode=ParseMode.HTML,
            reply_markup=country_keyboard(sel.get("protocol", "all"))
        )
        await query.answer()

# ==================== RUN ====================
async def main():
    print(f"🚀 {CONFIG['SERVICE_NAME']} v{CONFIG['SERVICE_VERSION']} starting...")
    await load_nodes()
    print(f"📦 Загружено {len(NODES)} нод")
    
    if dp and bot:
        print("🤖 Starting Telegram bot polling...")
        asyncio.create_task(dp.start_polling(bot))
    
    config = uvicorn.Config(app, host="0.0.0.0", port=CONFIG["PORT"])
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    import asyncio
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
