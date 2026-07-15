#!/usr/bin/env python3
"""
Python rewrite of the Node.js subscription bot.
- Custom subscriptions: combine up to 5 rules (protocol + country + count).
- Compact URL format: /sub/vRU5:tNL3:sUS10
"""

import os
import re
import base64
import json
from pathlib import Path
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
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageOps
from io import BytesIO

# ==================== CONFIG ====================
CONFIG = {
    "SERVICE_NAME": os.getenv("SERVICE_NAME", "Zapretka"),
    "SERVICE_VERSION": os.getenv("SERVICE_VERSION", "5.0.0-py"),
    "BOT_TOKEN": os.getenv("BOT_TOKEN", ""),
    "BASE_URL": os.getenv("BASE_URL") or os.getenv("RENDER_EXTERNAL_URL", ""),
    "PORT": int(os.getenv("PORT", 8000)),
}

MAX_RULES = 5

# ==================== COMPACT SPEC ====================
# Protocol letters: v=vless, m=vmess, t=trojan, s=shadowsocks, h=hysteria2
PROTO_LETTERS = {"v": "vless", "m": "vmess", "t": "trojan", "s": "ss", "h": "hysteria2"}
PROTO_TO_LETTER = {v: k for k, v in PROTO_LETTERS.items()}

_SPEC_RULE_RE = re.compile(r"^([vmthsh])([A-Z]{2}|\*)(\d*)$")


def parse_compact_spec(spec: str) -> List[Dict[str, Any]]:
    """Parse compact spec like 'vRU5:tNL3' into list of rule dicts."""
    rules = []
    for part in spec.split(":"):
        m = _SPEC_RULE_RE.match(part)
        if not m:
            raise ValueError(f"Invalid spec part: {part}")
        proto_letter, country, count_str = m.group(1), m.group(2), m.group(3)
        rules.append({
            "protocol": PROTO_LETTERS[proto_letter],
            "country": "all" if country == "*" else country,
            "count": int(count_str) if count_str else 0,
        })
    if not rules:
        raise ValueError("Empty spec")
    return rules


def build_compact_spec(rules: List[Dict]) -> str:
    """Build compact spec from list of rule dicts: vRU5:tNL3"""
    parts = []
    for r in rules:
        letter = PROTO_TO_LETTER.get(r["protocol"], "v")
        country = "*" if r["country"] == "all" else r["country"]
        count = str(r["count"]) if r["count"] else ""
        parts.append(f"{letter}{country}{count}")
    return ":".join(parts)


# ==================== QR BACKGROUND ====================
def _find_qr_background() -> Optional[str]:
    """Ищет qr.jpg рядом со скриптом, в cwd и по env-переменной."""
    env_path = os.getenv("QR_BACKGROUND", "").strip()
    if env_path and Path(env_path).is_file():
        return env_path
    script_dir = Path(__file__).resolve().parent
    for candidate in [script_dir / "qr.jpg", script_dir / "static" / "qr.jpg"]:
        if candidate.is_file():
            return str(candidate)
    cwd_path = Path.cwd() / "qr.jpg"
    if cwd_path.is_file():
        return str(cwd_path)
    return None


_QR_BACKGROUND = _find_qr_background()
print(f"🖼️ QR background: {_QR_BACKGROUND or 'не найден, используется заливка'}")


# ==================== STYLED QR GENERATOR ====================
def _qr_is_finder(row: int, col: int, n: int) -> bool:
    return (
        (row < 7 and col < 7)
        or (row < 7 and col >= n - 7)
        or (row >= n - 7 and col < 7)
    )


def make_telegram_qr(
    data: str,
    *,
    box_size: int = 32,
    border: int = 4,
    radius: float = 0.38,
    foreground: str = "#FFFFFF",
    background_image: Optional[str] = None,
    blur: float = 14.0,
    dim: float = 0.12,
) -> BytesIO:
    if not data:
        raise ValueError("Строка data не должна быть пустой")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=1,
        border=0,
    )
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    n = len(matrix)

    scale = 4
    cell = box_size * scale
    offset = border * cell
    side = (n + border * 2) * cell

    mask = Image.new("L", (side, side), 0)
    draw = ImageDraw.Draw(mask)
    corner = int(cell * radius)

    def bounds(row: int, col: int) -> tuple:
        x0 = offset + col * cell
        y0 = offset + row * cell
        return x0, y0, x0 + cell, y0 + cell

    for row in range(n):
        for col in range(n):
            if not matrix[row][col] or _qr_is_finder(row, col, n):
                continue
            x0, y0, x1, y1 = bounds(row, col)
            draw.rounded_rectangle((x0, y0, x1, y1), radius=corner, fill=255)
            if col + 1 < n and matrix[row][col + 1] and not _qr_is_finder(row, col + 1, n):
                draw.rectangle((x0 + cell // 2, y0, x1 + cell // 2, y1), fill=255)
            if row + 1 < n and matrix[row + 1][col] and not _qr_is_finder(row + 1, col, n):
                draw.rectangle((x0, y0 + cell // 2, x1, y1 + cell // 2), fill=255)

    for row, col in ((0, 0), (0, n - 7), (n - 7, 0)):
        x0, y0, _, _ = bounds(row, col)
        outer = (x0, y0, x0 + 7 * cell, y0 + 7 * cell)
        middle = (x0 + cell, y0 + cell, x0 + 6 * cell, y0 + 6 * cell)
        inner = (x0 + 2 * cell, y0 + 2 * cell, x0 + 5 * cell, y0 + 5 * cell)
        draw.rounded_rectangle(outer, radius=int(1.22 * cell), fill=255)
        draw.rounded_rectangle(middle, radius=int(1.25 * cell), fill=0)
        draw.rounded_rectangle(inner, radius=int(0.8 * cell), fill=255)

    final_side = (n + border * 2) * box_size
    mask = mask.resize((final_side, final_side), Image.Resampling.LANCZOS)

    bg_found = background_image and Path(background_image).is_file()
    if bg_found:
        with Image.open(background_image) as source:
            backdrop = ImageOps.fit(
                source.convert("RGB"),
                (final_side, final_side),
                method=Image.Resampling.LANCZOS,
            )
        if blur:
            backdrop = backdrop.filter(ImageFilter.GaussianBlur(blur))
        if dim:
            backdrop = ImageEnhance.Brightness(backdrop).enhance(1.0 - dim)
    else:
        backdrop = Image.new("RGB", (final_side, final_side), "#1A1A2E")

    ink = Image.new("RGB", (final_side, final_side), foreground)
    image = Image.composite(ink, backdrop, mask)

    buf = BytesIO()
    image.save(buf, format="PNG")
    buf.seek(0)
    return buf


# ==================== SUBSCRIPTION FROM URL ====================
async def fetch_subscription(url: str) -> str:
    if not url:
        return ""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={"User-Agent": "HiddifyNext/2.5.7"})
        resp.raise_for_status()
        text = resp.text.strip()
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
    'TW': 'Тайвань', 'SG': 'Сингапур', 'MY': 'Малайзия', 'TH': 'Таиланд',
    'TR': 'Турция', 'IL': 'Израиль', 'AE': 'ОАЭ',
    'IN': 'Индия', 'IR': 'Иран', 'AU': 'Австралия', 'NZ': 'Новая Зеландия',
    'KZ': 'Казахстан', 'AL': 'Албания', 'RS': 'Сербия', 'SA': 'Саудовская Аравия',
    'SC': 'Сейшельские о-ва', 'CO': 'Колумбия', 'ZA': 'ЮАР',
    'MT': 'Мальта', 'CY': 'Кипр',
    'XX': 'Неизвестно'
}


def get_flag_emoji(code: str) -> str:
    code = code.upper()
    if code == 'XX':
        return '❓'
    if len(code) == 2 and all(65 <= ord(char) <= 90 for char in code):
        return "".join(chr(127397 + ord(char)) for char in code)
    return "🌐"


PROTOCOL_LABELS = {
    'vless': '🔒 VLESS',
    'vmess': '🚀 VMess',
    'trojan': '🐴 Trojan',
    'ss': '🕶️ Shadowsocks',
    'hysteria2': '⚡ Hysteria2'
}

COUNT_OPTIONS = [5, 10, 20, 0]  # 0 = all
COUNTRIES_PER_PAGE = 6


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
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": "vless", "name": name, "server": url.hostname,
            "port": int(url.port or 443), "uuid": url.username,
            "raw": link, "country": extract_country(name)
        }
    except:
        return None


def _b64decode_padded(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def parse_vmess(link: str) -> Optional[Dict]:
    try:
        data = _b64decode_padded(link.replace('vmess://', '').split('#', 1)[0]).decode()
        cfg = json.loads(data)
        name = cfg.get('ps', cfg.get('add', 'vmess'))
        return {
            "protocol": "vmess", "name": name, "server": cfg.get('add'),
            "port": int(cfg.get('port', 443)),
            "raw": link, "country": extract_country(name)
        }
    except:
        return None


def parse_trojan(link: str) -> Optional[Dict]:
    try:
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": "trojan", "name": name, "server": url.hostname,
            "port": int(url.port or 443),
            "raw": link, "country": extract_country(name)
        }
    except:
        return None


def parse_shadowsocks(link: str) -> Optional[Dict]:
    try:
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": "ss", "name": name, "server": url.hostname,
            "port": int(url.port or 443),
            "raw": link, "country": extract_country(name)
        }
    except:
        return None


def parse_hysteria2(link: str) -> Optional[Dict]:
    try:
        url = urlparse(link.replace('hy2://', 'hysteria2://'))
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": "hysteria2", "name": name, "server": url.hostname,
            "port": int(url.port or 443),
            "raw": link, "country": extract_country(name)
        }
    except:
        return None


# Региональные индикаторы Unicode
FLAG_EMOJI_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")


def extract_country(name: str) -> str:
    if name:
        m = FLAG_EMOJI_RE.search(name)
        if m:
            flag = m.group(0)
            return "".join(chr(ord(c) - 127397) for c in flag).upper()
    return 'XX'


# ==================== NODES ====================
NODES: List[Dict[str, Any]] = []


async def load_nodes():
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
    protocol = protocol.lower()
    country = country.upper()

    if protocol != "all":
        result = [n for n in result if n["protocol"] == protocol]
    if country != "ALL":
        result = [n for n in result if n.get("country") == country]
    if count > 0:
        result = result[:count]
    return result


def filter_nodes_by_spec(spec: str) -> List[Dict]:
    """Filter nodes using compact spec like 'vRU5:tNL3'."""
    rules = parse_compact_spec(spec)
    seen = set()
    result = []
    for rule in rules:
        nodes = filter_nodes(rule["protocol"], rule["country"], rule["count"])
        for n in nodes:
            if n["raw"] not in seen:
                seen.add(n["raw"])
                result.append(n)
    return result


def generate_subscription(nodes: List[Dict]) -> str:
    if not nodes:
        return ""
    return "\n".join(n["raw"] for n in nodes)


def get_stats(protocol: str = "all"):
    by_protocol = {}
    by_country = {}
    total_nodes = 0
    for node in NODES:
        p = node["protocol"]
        c = node.get("country", "XX")
        by_protocol[p] = by_protocol.get(p, 0) + 1
        if protocol == "all" or p == protocol:
            by_country[c] = by_country.get(c, 0) + 1
            total_nodes += 1
    return {"total": total_nodes, "byProtocol": by_protocol, "byCountry": by_country}


# ==================== FASTAPI ====================
app = FastAPI(title=CONFIG["SERVICE_NAME"])


@app.get("/sub/{spec:path}")
async def get_subscription(spec: str):
    """Subscription by compact spec: /sub/vRU5:tNL3:sUS10"""
    try:
        nodes = filter_nodes_by_spec(spec)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid spec format")
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

    sessions = {}  # chat_id -> {"rules": [...], "current": {...}}

    def code_to_name(code: str) -> str:
        return country_names.get(code, code)

    def rule_display(rule: dict) -> str:
        """Format one rule for display: 🇷🇺 VLESS × 5"""
        proto = PROTOCOL_LABELS.get(rule["protocol"], rule["protocol"])
        if rule["country"] == "all":
            country = "🌍 Любая"
        else:
            country = f"{get_flag_emoji(rule['country'])} {code_to_name(rule['country'])}"
        count = "все" if not rule["count"] else str(rule["count"])
        return f"{country} {proto} × {count}"

    def review_text(rules: list) -> str:
        lines = [f"📋 <b>Подписка</b> ({len(rules)}/{MAX_RULES}):"]
        for i, rule in enumerate(rules, 1):
            lines.append(f"  {i}. {rule_display(rule)}")
        return "\n".join(lines)

    # ---------- keyboards ----------

    def protocol_keyboard():
        stats = get_stats()
        available = stats["byProtocol"]
        rows, row = [], []
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

    def country_keyboard(protocol: str, page: int = 0):
        stats = get_stats(protocol)
        by_country = stats["byCountry"]
        entries = sorted(by_country.items(), key=lambda x: -x[1])

        total_pages = max(1, (len(entries) + COUNTRIES_PER_PAGE - 1) // COUNTRIES_PER_PAGE)
        page = max(0, min(page, total_pages - 1))

        start = page * COUNTRIES_PER_PAGE
        page_entries = entries[start:start + COUNTRIES_PER_PAGE]

        rows = [[InlineKeyboardButton(text="🌍 Любая страна", callback_data="c:all")]]
        row = []
        for code, n in page_entries:
            row.append(InlineKeyboardButton(
                text=f"{get_flag_emoji(code)} {code_to_name(code)} ({n})",
                callback_data=f"c:{code}"
            ))
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)

        nav_row = []
        if page > 0:
            nav_row.append(InlineKeyboardButton(text="◀️ Назад", callback_data=f"cp:{page - 1}"))
        nav_row.append(InlineKeyboardButton(
            text=f"{page + 1}/{total_pages}", callback_data="noop"
        ))
        if page < total_pages - 1:
            nav_row.append(InlineKeyboardButton(text="Ещё ▶️", callback_data=f"cp:{page + 1}"))
        rows.append(nav_row)

        rows.append([InlineKeyboardButton(text="⏪ К протоколу", callback_data="back:protocol")])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def count_keyboard():
        rows, row = [], []
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
        rows.append([InlineKeyboardButton(text="⏪ К стране", callback_data="back:country")])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def review_keyboard(rules_count: int) -> InlineKeyboardMarkup:
        rows = []
        row = []
        if rules_count < MAX_RULES:
            row.append(InlineKeyboardButton(text="➕ Ещё", callback_data="add"))
        row.append(InlineKeyboardButton(text="🔗 Создать", callback_data="generate"))
        rows.append(row)
        if rules_count > 0:
            rows.append([InlineKeyboardButton(text="🗑️ Удалить последнюю", callback_data="remove")])
        rows.append([InlineKeyboardButton(text="⏪ Заново", callback_data="restart")])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    # ---------- send result ----------

    async def send_result(chat_id: int, rules: list):
        spec = build_compact_spec(rules)
        url = f"{CONFIG['BASE_URL'].rstrip('/')}/sub/{spec}"

        rules_text = "\n".join(f"  • {rule_display(r)}" for r in rules)
        caption = (
            f"✅ <b>Подписка готова</b>\n\n"
            f"{rules_text}\n\n"
            f"🔗 <code>{url}</code>"
        )

        buf = make_telegram_qr(url, background_image=_QR_BACKGROUND)
        await bot.send_photo(
            chat_id,
            photo=BufferedInputFile(buf.getvalue(), filename="qr.png"),
            caption=caption,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="🔄 Создать ещё", callback_data="restart")
            ]])
        )

    # ---------- handlers ----------

    @dp.message(Command("start"))
    async def cmd_start(message: types.Message):
        sessions.pop(message.chat.id, None)
        stats = get_stats()
        await message.answer(
            f"👋 <b>Конструктор подписок</b>\n\n"
            f"Доступно нод: <b>{stats['total']}</b>\n\n"
            f"Соберите подписку из нескольких правил (до {MAX_RULES}).\n"
            f"Правило {1}/{MAX_RULES} — выберите протокол:",
            parse_mode=ParseMode.HTML,
            reply_markup=protocol_keyboard()
        )

    @dp.callback_query(F.data.startswith("p:"))
    async def cb_protocol(query: types.CallbackQuery):
        protocol = query.data.split(":")[1]
        sel = sessions.setdefault(query.message.chat.id, {"rules": [], "current": {}})
        sel["current"] = {"protocol": protocol}
        stats = get_stats(protocol)
        total_countries = len(stats["byCountry"])
        rule_num = len(sel["rules"]) + 1
        await query.message.edit_text(
            f"🔌 Правило {rule_num}/{MAX_RULES}: "
            f"<b>{PROTOCOL_LABELS.get(protocol, protocol)}</b>\n\n"
            f"Выберите страну ({total_countries} стран):",
            parse_mode=ParseMode.HTML,
            reply_markup=country_keyboard(protocol)
        )
        await query.answer()

    @dp.callback_query(F.data.startswith("c:"))
    async def cb_country(query: types.CallbackQuery):
        country = query.data.split(":")[1]
        sel = sessions.get(query.message.chat.id, {"rules": [], "current": {}})
        if "current" not in sel:
            sel["current"] = {}
        sel["current"]["country"] = country
        country_display = "🌍 Любая" if country == "all" else f"{get_flag_emoji(country)} {code_to_name(country)}"
        proto = sel["current"].get("protocol", "")
        await query.message.edit_text(
            f"🔌 {PROTOCOL_LABELS.get(proto, proto)} · {country_display}\n\n"
            f"Выберите количество:",
            parse_mode=ParseMode.HTML,
            reply_markup=count_keyboard()
        )
        await query.answer()

    @dp.callback_query(F.data.startswith("cp:"))
    async def cb_country_page(query: types.CallbackQuery):
        page = int(query.data.split(":")[1])
        sel = sessions.get(query.message.chat.id, {"rules": [], "current": {}})
        protocol = sel.get("current", {}).get("protocol", "vless")
        rule_num = len(sel.get("rules", [])) + 1
        await query.message.edit_text(
            f"🔌 Правило {rule_num}/{MAX_RULES}: "
            f"<b>{PROTOCOL_LABELS.get(protocol, protocol)}</b>\n\n"
            f"Выберите страну:",
            parse_mode=ParseMode.HTML,
            reply_markup=country_keyboard(protocol, page)
        )
        await query.answer()

    @dp.callback_query(F.data == "noop")
    async def cb_noop(query: types.CallbackQuery):
        await query.answer()

    @dp.callback_query(F.data.startswith("n:"))
    async def cb_count(query: types.CallbackQuery):
        count = int(query.data.split(":")[1])
        sel = sessions.get(query.message.chat.id, {"rules": [], "current": {}})
        current = sel.get("current", {})

        # Finalize rule
        rule = {
            "protocol": current.get("protocol", "vless"),
            "country": current.get("country", "all"),
            "count": count,
        }
        if "rules" not in sel:
            sel["rules"] = []
        sel["rules"].append(rule)
        sel["current"] = {}

        rules = sel["rules"]
        await query.message.edit_text(
            review_text(rules),
            parse_mode=ParseMode.HTML,
            reply_markup=review_keyboard(len(rules))
        )
        await query.answer()

    @dp.callback_query(F.data == "add")
    async def cb_add(query: types.CallbackQuery):
        sel = sessions.get(query.message.chat.id, {"rules": [], "current": {}})
        rule_num = len(sel.get("rules", [])) + 1
        await query.message.edit_text(
            f"➕ Правило {rule_num}/{MAX_RULES} — выберите протокол:",
            parse_mode=ParseMode.HTML,
            reply_markup=protocol_keyboard()
        )
        await query.answer()

    @dp.callback_query(F.data == "remove")
    async def cb_remove(query: types.CallbackQuery):
        sel = sessions.get(query.message.chat.id, {"rules": [], "current": {}})
        rules = sel.get("rules", [])
        if rules:
            rules.pop()
        if not rules:
            await query.message.edit_text(
                "📋 Список пуст. Начните заново:",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(text="🔄 Начать", callback_data="restart")
                ]])
            )
        else:
            await query.message.edit_text(
                review_text(rules),
                parse_mode=ParseMode.HTML,
                reply_markup=review_keyboard(len(rules))
            )
        await query.answer()

    @dp.callback_query(F.data == "generate")
    async def cb_generate(query: types.CallbackQuery):
        sel = sessions.get(query.message.chat.id, {})
        rules = sel.get("rules", [])
        if not rules:
            await query.answer("❌ Нет правил")
            return
        await query.answer("Генерирую...")
        try:
            await query.message.delete()
        except:
            pass
        await send_result(query.message.chat.id, rules)
        sessions.pop(query.message.chat.id, None)

    @dp.callback_query(F.data == "restart")
    async def cb_restart(query: types.CallbackQuery):
        sessions.pop(query.message.chat.id, None)
        stats = get_stats()
        await query.message.answer(
            f"👋 <b>Конструктор подписок</b>\n\n"
            f"Доступно нод: <b>{stats['total']}</b>\n\n"
            f"Соберите подписку из нескольких правил (до {MAX_RULES}).\n"
            f"Правило 1/{MAX_RULES} — выберите протокол:",
            parse_mode=ParseMode.HTML,
            reply_markup=protocol_keyboard()
        )
        await query.answer()

    @dp.callback_query(F.data == "back:protocol")
    async def cb_back_protocol(query: types.CallbackQuery):
        sel = sessions.get(query.message.chat.id, {"rules": [], "current": {}})
        rule_num = len(sel.get("rules", [])) + 1
        await query.message.edit_text(
            f"➕ Правило {rule_num}/{MAX_RULES} — выберите протокол:",
            parse_mode=ParseMode.HTML,
            reply_markup=protocol_keyboard()
        )
        await query.answer()

    @dp.callback_query(F.data == "back:country")
    async def cb_back_country(query: types.CallbackQuery):
        sel = sessions.get(query.message.chat.id, {"rules": [], "current": {}})
        protocol = sel.get("current", {}).get("protocol", "vless")
        stats = get_stats(protocol)
        total_countries = len(stats["byCountry"])
        rule_num = len(sel.get("rules", [])) + 1
        await query.message.edit_text(
            f"🔌 Правило {rule_num}/{MAX_RULES}: "
            f"<b>{PROTOCOL_LABELS.get(protocol, protocol)}</b>\n\n"
            f"Выберите страну ({total_countries} стран):",
            parse_mode=ParseMode.HTML,
            reply_markup=country_keyboard(protocol)
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
