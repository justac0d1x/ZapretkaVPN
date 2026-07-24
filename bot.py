#!/usr/bin/env python3
"""
ZapretkaVPN Bot — конструктор кастомных подписок.
До 5 групп (протокол + страна + количество) в одной подписке.
Компактный формат URL: /sub/vRU5:tNL3:sUS10
"""

import os
import re
import base64
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import unquote, urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, RedirectResponse
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
    "SERVICE_VERSION": os.getenv("SERVICE_VERSION", "5.2.0-py"),
    "BOT_TOKEN": os.getenv("BOT_TOKEN", ""),
    "BASE_URL": os.getenv("BASE_URL") or os.getenv("RENDER_EXTERNAL_URL", ""),
    "PORT": int(os.getenv("PORT", 8000)),
}

MAX_RULES = 5

# ==================== COMPACT SPEC ====================
# a = все протоколы, v = vless, m = vmess, t = trojan, s = ss, h = hysteria2
PROTO_LETTERS = {"a": "all", "v": "vless", "m": "vmess", "t": "trojan", "s": "ss", "h": "hysteria2"}
PROTO_TO_LETTER = {v: k for k, v in PROTO_LETTERS.items()}
PROTO_ORDER = ["vless", "vmess", "trojan", "ss", "hysteria2"]

_SPEC_RULE_RE = re.compile(r"^([avmthsh])([A-Z]{2}|\*)(\d*)$")


def parse_compact_spec(spec: str) -> List[Dict[str, Any]]:
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
    parts = []
    for r in rules:
        letter = PROTO_TO_LETTER.get(r["protocol"], "a")
        country = "*" if r["country"] == "all" else r["country"]
        count = str(r["count"]) if r["count"] else ""
        parts.append(f"{letter}{country}{count}")
    return ":".join(parts)


# ==================== QR BACKGROUND ====================
def _find_qr_background() -> Optional[str]:
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
    return (row < 7 and col < 7) or (row < 7 and col >= n - 7) or (row >= n - 7 and col < 7)


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

    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_H,
                        box_size=1, border=0)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    n = len(matrix)

    scale = 4
    cell = box_size * scale
    offset, side = border * cell, (n + border * 2) * cell

    mask = Image.new("L", (side, side), 0)
    draw = ImageDraw.Draw(mask)
    corner = int(cell * radius)

    def bounds(r, c):
        x0, y0 = offset + c * cell, offset + r * cell
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
        draw.rounded_rectangle((x0, y0, x0 + 7 * cell, y0 + 7 * cell), radius=int(1.22 * cell), fill=255)
        draw.rounded_rectangle((x0 + cell, y0 + cell, x0 + 6 * cell, y0 + 6 * cell), radius=int(1.25 * cell), fill=0)
        draw.rounded_rectangle((x0 + 2 * cell, y0 + 2 * cell, x0 + 5 * cell, y0 + 5 * cell), radius=int(0.8 * cell), fill=255)

    final_side = (n + border * 2) * box_size
    mask = mask.resize((final_side, final_side), Image.Resampling.LANCZOS)

    bg_found = background_image and Path(background_image).is_file()
    if bg_found:
        with Image.open(background_image) as source:
            backdrop = ImageOps.fit(source.convert("RGB"), (final_side, final_side), method=Image.Resampling.LANCZOS)
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
    'XX': 'Неизвестно',
}


def get_flag_emoji(code: str) -> str:
    code = code.upper()
    if code == 'XX':
        return '❓'
    if len(code) == 2 and all(65 <= ord(c) <= 90 for c in code):
        return "".join(chr(127397 + ord(c)) for c in code)
    return "🌐"


PROTOCOL_LABELS = {
    'all': '🌐 Все протоколы',
    'vless': '🔒 VLESS', 'vmess': '🚀 VMess',
    'trojan': '🐴 Trojan', 'ss': '🕶️ Shadowsocks', 'hysteria2': '⚡ Hysteria2',
}

COUNT_OPTIONS = [5, 10, 20, 0]
COUNTRIES_PER_PAGE = 6


# ==================== PARSE NODES ====================
FLAG_EMOJI_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")


def extract_country(name: str) -> str:
    if name:
        m = FLAG_EMOJI_RE.search(name)
        if m:
            return "".join(chr(ord(c) - 127397) for c in m.group(0)).upper()
    return 'XX'


def _b64decode_padded(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def _parse_url_node(link: str, protocol: str, normalize: Optional[str] = None) -> Optional[Dict]:
    """Парсер для протоколов на базе URL (vless, trojan, ss, hysteria2)."""
    try:
        url = urlparse(link if normalize is None else link.replace(normalize, "hysteria2://"))
        name = unquote(url.fragment) if url.fragment else url.hostname
        return {
            "protocol": protocol, "name": name, "server": url.hostname,
            "port": int(url.port or 443), "raw": link,
            "country": extract_country(name),
        }
    except Exception:
        return None


def parse_vmess(link: str) -> Optional[Dict]:
    try:
        data = _b64decode_padded(link.replace('vmess://', '').split('#', 1)[0]).decode()
        cfg = json.loads(data)
        name = cfg.get('ps', cfg.get('add', 'vmess'))
        return {
            "protocol": "vmess", "name": name, "server": cfg.get('add'),
            "port": int(cfg.get('port', 443)), "raw": link,
            "country": extract_country(name),
        }
    except Exception:
        return None


# Маппинг: префикс → (парсер, аргументы)
_PARSE_MAP = {
    "vless://": (_parse_url_node, "vless", None),
    "trojan://": (_parse_url_node, "trojan", None),
    "ss://":     (_parse_url_node, "ss", None),
    "hysteria2://": (_parse_url_node, "hysteria2", None),
    "hy2://":    (_parse_url_node, "hysteria2", "hy2://"),
    "vmess://":  (parse_vmess, None, None),
}


def parse_ready_subscription(text: str) -> List[Dict[str, Any]]:
    nodes = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        for prefix, (parser, proto, norm) in _PARSE_MAP.items():
            if line.startswith(prefix):
                node = parser(line, proto, normalize=norm) if proto else parser(line)
                if node:
                    nodes.append(node)
                break
    return nodes


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


# ==================== FILTERING & STATS ====================
def filter_nodes(protocol: str = "all", country: str = "all", count: int = 0) -> List[Dict]:
    result = NODES
    if protocol != "all":
        result = [n for n in result if n["protocol"] == protocol]
    if country != "all":
        result = [n for n in result if n.get("country") == country]
    if count > 0:
        result = result[:count]
    return result


def filter_nodes_by_spec(spec: str) -> List[Dict]:
    rules = parse_compact_spec(spec)
    seen, result = set(), []
    for rule in rules:
        for n in filter_nodes(rule["protocol"], rule["country"], rule["count"]):
            if n["raw"] not in seen:
                seen.add(n["raw"])
                result.append(n)
    return result


def generate_subscription(nodes: List[Dict]) -> str:
    return "\n".join(n["raw"] for n in nodes) if nodes else ""


def get_stats(protocol: str = "all"):
    by_protocol, by_country = {}, {}
    total = 0
    for node in NODES:
        p, c = node["protocol"], node.get("country", "XX")
        by_protocol[p] = by_protocol.get(p, 0) + 1
        if protocol == "all" or p == protocol:
            by_country[c] = by_country.get(c, 0) + 1
            total += 1
    return {"total": total, "byProtocol": by_protocol, "byCountry": by_country}


def get_available_count(protocol: str, country: str) -> int:
    """Возвращает реальное количество доступных нод для протокола + страны"""
    filtered = filter_nodes(protocol, country)
    return len(filtered)


# ==================== FASTAPI ====================
app = FastAPI(title=CONFIG["SERVICE_NAME"])


@app.get("/sub/{spec:path}")
async def get_subscription(spec: str):
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
    return {"status": "ok", "nodes": get_stats()}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/redir/{client_path:path}")
async def redirect_to_app(client_path: str):
    """
    Простой редиректор:
    /redir/h;xxx   → Happ
    /redir/i;xxx   → Incy
    """
    if ";" not in client_path:
        return {"error": "invalid format. Use /redir/h;xxx or /redir/i;xxx"}

    client_code, spec = client_path.split(";", 1)

    if client_code == "h":
        app_scheme = "happ"
    elif client_code == "i":
        app_scheme = "incy"
    else:
        return {"error": "unknown client (use h or i)"}

    sub_url = f"{CONFIG['BASE_URL'].rstrip('/')}/sub/{spec}"

    try:
        encoded = base64.urlsafe_b64encode(sub_url.encode()).decode().rstrip("=")
    except Exception:
        return {"error": "invalid spec"}

    redirect_url = f"{app_scheme}://import/{encoded}"
    return RedirectResponse(url=redirect_url, status_code=302)


# ==================== TELEGRAM BOT ====================
bot = None
dp = None

if CONFIG["BOT_TOKEN"]:
    bot = Bot(token=CONFIG["BOT_TOKEN"])
    dp = Dispatcher()

    sessions = {}  # chat_id -> {"rules": [...], "current": {...}}

    # ---------- helpers ----------

    def _sess(chat_id: int) -> dict:
        return sessions.setdefault(chat_id, {"rules": [], "current": {}})

    def _rule_num(chat_id: int) -> int:
        return len(_sess(chat_id).get("rules", [])) + 1

    def code_to_name(code: str) -> str:
        return country_names.get(code, code)

    def rule_display(rule: dict) -> str:
        proto = PROTOCOL_LABELS.get(rule["protocol"], rule["protocol"])
        country = "🌍 Любая" if rule["country"] == "all" else f"{get_flag_emoji(rule['country'])} {code_to_name(rule['country'])}"
        count = "все" if not rule["count"] else str(rule["count"])
        return f"{country} {proto} × {count}"

    def _review_text(rules: list) -> str:
        lines = [f"📋 <b>Подписка</b> ({len(rules)}/{MAX_RULES}):"]
        for i, rule in enumerate(rules, 1):
            lines.append(f"  {i}. {rule_display(rule)}")
        return "\n".join(lines)

    # ==================== НОВОЕ ПРИВЕТСТВИЕ ====================
    def _welcome_text() -> str:
        stats = get_stats()
        return (
            f"👋 <b>Добро пожаловать в Zapretka!</b>\n\n"
            f"Zapretka — это удобный конструктор персональных VPN-подписок.\n\n"
            f"🔹 <b>Что можно сделать:</b>\n"
            f"• Собрать подписку из нескольких групп серверов (до {MAX_RULES})\n"
            f"• Выбрать протокол, страну и количество серверов\n"
            f"• Получить красивую ссылку + QR-код\n\n"
            f"📊 <b>Сейчас доступно:</b> <b>{stats['total']}</b> серверов\n\n"
            f"Готовы начать?"
        )

    def welcome_keyboard() -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🚀 Начать", callback_data="start_constructor")]
        ])

    async def _show_welcome(target, edit: bool = False):
        """Показывает красивое приветственное сообщение"""
        sessions.pop(target.chat.id, None)
        text = _welcome_text()
        kb = welcome_keyboard()
        if edit:
            await target.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
        else:
            await target.answer(text, parse_mode=ParseMode.HTML, reply_markup=kb)



    # ---------- keyboards ----------

    def protocol_keyboard(existing_rules: int = 0):
        stats = get_stats()
        available = stats["byProtocol"]
        total = sum(available.values())
        rows = [[InlineKeyboardButton(text=f"🌐 Все протоколы ({total})", callback_data="p:all")]]
        row = []
        for proto in PROTO_ORDER:
            cnt = available.get(proto, 0)
            if cnt == 0:
                continue
            row.append(InlineKeyboardButton(
                text=f"{PROTOCOL_LABELS[proto]} ({cnt})", callback_data=f"p:{proto}"
            ))
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        if existing_rules > 0:
            rows.append([InlineKeyboardButton(text="⏪ Назад", callback_data="restart")])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def country_keyboard(protocol: str, page: int = 0):
        stats = get_stats(protocol)
        entries = sorted(stats["byCountry"].items(), key=lambda x: -x[1])
        total_pages = max(1, (len(entries) + COUNTRIES_PER_PAGE - 1) // COUNTRIES_PER_PAGE)
        page = max(0, min(page, total_pages - 1))
        page_entries = entries[page * COUNTRIES_PER_PAGE:(page + 1) * COUNTRIES_PER_PAGE]

        total_nodes = stats["total"]
        rows = [[InlineKeyboardButton(text=f"🌍 Любая страна ({total_nodes})", callback_data="c:all")]]
        row = []
        for code, n in page_entries:
            row.append(InlineKeyboardButton(
                text=f"{get_flag_emoji(code)} {code_to_name(code)} ({n})",
                callback_data=f"c:{code}",
            ))
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)

        nav = []
        if page > 0:
            nav.append(InlineKeyboardButton(text="◀️", callback_data=f"cp:{page - 1}"))
        nav.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="noop"))
        if page < total_pages - 1:
            nav.append(InlineKeyboardButton(text="▶️", callback_data=f"cp:{page + 1}"))
        rows.append(nav)
        rows.append([InlineKeyboardButton(text="⏪ Назад", callback_data="back:protocol")])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def count_keyboard(protocol: str, country: str, current: int = 1, max_available: int = 0):
        """Красивый селектор количества с + / -"""
        min_count = 1
        current = max(min_count, min(current, max_available))

        rows = []

        # Верхняя строка: -   текущее   +
        row = [
            InlineKeyboardButton(text="➖", callback_data="count:dec"),
            InlineKeyboardButton(text=f"📦 {current}", callback_data="noop"),
            InlineKeyboardButton(text="➕", callback_data="count:inc"),
        ]
        rows.append(row)

        # Кнопка "Все"
        rows.append([InlineKeyboardButton(text=f"🌍 Все ({max_available})", callback_data="count:all")])

        # Кнопка подтверждения
        rows.append([InlineKeyboardButton(text="✅ Выбрать", callback_data="count:confirm")])

        # Назад
        rows.append([InlineKeyboardButton(text="⏪ Назад", callback_data="back:country")])

        return InlineKeyboardMarkup(inline_keyboard=rows)

    def review_keyboard(n: int) -> InlineKeyboardMarkup:
        rows = []
        row = []
        if n < MAX_RULES:
            row.append(InlineKeyboardButton(text="➕ Ещё", callback_data="add"))
        row.append(InlineKeyboardButton(text="🔗 Создать", callback_data="generate"))
        rows.append(row)
        if n > 0:
            rows.append([InlineKeyboardButton(text="🗑️ Удалить последнюю", callback_data="remove")])
        if n > 1:
            rows.append([InlineKeyboardButton(text="🏠 В начало", callback_data="restart")])
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

        markup = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="📱 Happ", callback_data=f"import:happ:{spec}"),
                InlineKeyboardButton(text="📱 Incy", callback_data=f"import:incy:{spec}"),
            ],
            [InlineKeyboardButton(text="🔄 Создать ещё", callback_data="restart")]
        ])

        await bot.send_photo(
            chat_id,
            photo=BufferedInputFile(buf.getvalue(), filename="qr.png"),
            caption=caption,
            parse_mode=ParseMode.HTML,
            reply_markup=markup,
        )

    # ---------- handlers ----------

    @dp.message(Command("start"))
    async def cmd_start(message: types.Message):
        await _show_welcome(message, edit=False)

    # ==================== ЕДИНАЯ ФУНКЦИЯ ВЫБОРА ПРОТОКОЛА ====================
    async def show_protocol_selection(target, chat_id: int, edit: bool = False):
        """Единая функция показа экрана выбора протокола"""
        rule_num = _rule_num(chat_id)
        rules_count = len(_sess(chat_id)["rules"])
        text = f"➕ Группа {rule_num}/{MAX_RULES} — выберите протокол:"
        kb = protocol_keyboard(rules_count)

        if edit:
            await target.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
        else:
            await target.answer(text, parse_mode=ParseMode.HTML, reply_markup=kb)

    # Новая кнопка "Начать конструктор"
    @dp.callback_query(F.data == "start_constructor")
    async def cb_start_constructor(query: types.CallbackQuery):
        await query.answer()
        await show_protocol_selection(query.message, query.message.chat.id, edit=True)

    @dp.callback_query(F.data.startswith("import:"))
    async def cb_import_app(query: types.CallbackQuery):
        _, client, spec = query.data.split(":", 2)

        # Новый формат: /redir/h;xxx или /redir/i;xxx
        if client == "happ":
            path = f"h;{spec}"
        else:
            path = f"i;{spec}"

        redirect_url = f"{CONFIG['BASE_URL'].rstrip('/')}/redir/{path}"

        await query.answer()
        try:
            await query.message.reply(
                f"Нажми, чтобы открыть подписку:\n\n"
                f"[📱 Открыть в {client.upper()}]({redirect_url})",
                parse_mode=ParseMode.MARKDOWN,
                disable_web_page_preview=True
            )
        except Exception:
            await query.message.reply(f"Ссылка: {redirect_url}")

    @dp.callback_query(F.data.startswith("p:"))
    async def cb_protocol(query: types.CallbackQuery):
        protocol = query.data.split(":")[1]
        sel = _sess(query.message.chat.id)
        sel["current"] = {"protocol": protocol}
        rule_num = _rule_num(query.message.chat.id)
        await query.message.edit_text(
            f"🔌 Группа {rule_num}/{MAX_RULES}: "
            f"<b>{PROTOCOL_LABELS.get(protocol, protocol)}</b>\n\n"
            f"Выберите страну:",
            parse_mode=ParseMode.HTML,
            reply_markup=country_keyboard(protocol),
        )
        await query.answer()

    @dp.callback_query(F.data.startswith("c:"))
    async def cb_country(query: types.CallbackQuery):
        country = query.data.split(":")[1]
        sel = _sess(query.message.chat.id)
        sel["current"]["country"] = country
        sel["current"]["count"] = 1                    # ← Сбрасываем счётчик при выборе новой страны
        proto = sel["current"].get("protocol", "all")
        country_display = "🌍 Любая" if country == "all" else f"{get_flag_emoji(country)} {code_to_name(country)}"

        max_available = get_available_count(proto, country)
        current_count = max(1, min(sel["current"].get("count", 1), max_available))

        await query.message.edit_text(
            f"🔌 {PROTOCOL_LABELS.get(proto, proto)} · {country_display}\n\n"
            f"Выберите количество:",
            parse_mode=ParseMode.HTML,
            reply_markup=count_keyboard(proto, country, current_count, max_available),
        )
        await query.answer()

    @dp.callback_query(F.data.startswith("cp:"))
    async def cb_country_page(query: types.CallbackQuery):
        page = int(query.data.split(":")[1])
        sel = _sess(query.message.chat.id)
        protocol = sel.get("current", {}).get("protocol", "all")
        rule_num = _rule_num(query.message.chat.id)
        await query.message.edit_text(
            f"🔌 Группа {rule_num}/{MAX_RULES}: "
            f"<b>{PROTOCOL_LABELS.get(protocol, protocol)}</b>\n\n"
            f"Выберите страну:",
            parse_mode=ParseMode.HTML,
            reply_markup=country_keyboard(protocol, page),
        )
        await query.answer()

    @dp.callback_query(F.data == "noop")
    async def cb_noop(query: types.CallbackQuery):
        await query.answer()

    # ==================== ИНТЕРАКТИВНЫЙ ВЫБОР КОЛИЧЕСТВА ====================
    @dp.callback_query(F.data.startswith("count:"))
    async def cb_count_interactive(query: types.CallbackQuery):
        sel = _sess(query.message.chat.id)
        proto = sel["current"].get("protocol", "all")
        country = sel["current"].get("country", "all")

        max_available = get_available_count(proto, country)
        if max_available == 0:
            await query.answer("❌ Нет доступных нод", show_alert=True)
            return

        current = sel["current"].get("count", 1)
        min_count = 1

        data = query.data.split(":")[1]

        # Умный шаг: 1 при <5, 5 при >=5
        if current < 5:
            step = 1
        else:
            step = 5

        if data == "inc":
            if current < 5:
                current = min(current + 1, 5)
            else:
                current = min(current + 5, max_available)
        elif data == "dec":
            if current <= 5:
                current = max(current - 1, min_count)
            else:
                # Отматываем к ближайшему меньшему кратному 5
                current = max(((current - 1) // 5) * 5, 5)

        # Защита: никогда не оставляем значения 6,7,8,9
        if 5 < current < 10:
            current = 10 if data == "inc" else 5
        elif data == "all":
            current = max_available
        elif data == "confirm":
            # Сохраняем и переходим к обзору
            sel["rules"].append({
                "protocol": proto,
                "country": country,
                "count": current,
            })
            sel["current"] = {}
            rules = sel["rules"]
            await query.message.edit_text(
                _review_text(rules), parse_mode=ParseMode.HTML,
                reply_markup=review_keyboard(len(rules)),
            )
            await query.answer()
            return

        # Обновляем текущее значение
        sel["current"]["count"] = current

        country_display = "🌍 Любая" if country == "all" else f"{get_flag_emoji(country)} {code_to_name(country)}"

        try:
            await query.message.edit_text(
                f"🔌 {PROTOCOL_LABELS.get(proto, proto)} · {country_display}\n\n"
                f"Выберите количество:",
                parse_mode=ParseMode.HTML,
                reply_markup=count_keyboard(proto, country, current, max_available),
            )
        except Exception:
            # Игнорируем ошибку "message is not modified"
            pass

        await query.answer()

    @dp.callback_query(F.data == "add")
    async def cb_add(query: types.CallbackQuery):
        await query.answer()
        await show_protocol_selection(query.message, query.message.chat.id, edit=True)

    @dp.callback_query(F.data == "remove")
    async def cb_remove(query: types.CallbackQuery):
        sel = _sess(query.message.chat.id)
        if sel["rules"]:
            sel["rules"].pop()
        rules = sel["rules"]
        if not rules:
            await query.message.edit_text(
                "📋 Список пуст. Начните заново:",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(text="🔄 Начать", callback_data="restart")
                ]]),
            )
        else:
            await query.message.edit_text(
                _review_text(rules), parse_mode=ParseMode.HTML,
                reply_markup=review_keyboard(len(rules)),
            )
        await query.answer()

    @dp.callback_query(F.data == "generate")
    async def cb_generate(query: types.CallbackQuery):
        rules = _sess(query.message.chat.id)["rules"]
        if not rules:
            await query.answer("❌ Нет групп")
            return
        await query.answer("Генерирую...")
        chat_id = query.message.chat.id
        try:
            await query.message.delete()
        except Exception:
            pass
        try:
            await send_result(chat_id, rules)
        except Exception as e:
            print(f"❌ Ошибка генерации QR: {e}")
            # Фолбэк: отправляем только текст
            spec = build_compact_spec(rules)
            url = f"{CONFIG['BASE_URL'].rstrip('/')}/sub/{spec}"
            rules_text = "\n".join(f"  • {rule_display(r)}" for r in rules)
            try:
                await bot.send_message(
                    chat_id,
                    f"✅ <b>Подписка готова</b>\n\n{rules_text}\n\n"
                    f"🔗 <code>{url}</code>",
                    parse_mode=ParseMode.HTML,
                    reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                        InlineKeyboardButton(text="🔄 Создать ещё", callback_data="restart")
                    ]]),
                )
            except Exception as e2:
                print(f"❌ Ошибка отправки фолбэка: {e2}")
        sessions.pop(chat_id, None)

    @dp.callback_query(F.data == "restart")
    async def cb_restart(query: types.CallbackQuery):
        sel = _sess(query.message.chat.id)
        rules = sel.get("rules", [])

        await query.answer()

        if rules:
            # Есть собранные группы → возвращаемся к странице обзора
            await query.message.edit_text(
                _review_text(rules),
                parse_mode=ParseMode.HTML,
                reply_markup=review_keyboard(len(rules))
            )
        else:
            # Нет групп → идём к выбору протокола
            sessions.pop(query.message.chat.id, None)
            await show_protocol_selection(query.message, query.message.chat.id, edit=True)

    @dp.callback_query(F.data == "back:protocol")
    async def cb_back_protocol(query: types.CallbackQuery):
        await query.answer()
        await show_protocol_selection(query.message, query.message.chat.id, edit=True)

    @dp.callback_query(F.data == "back:country")
    async def cb_back_country(query: types.CallbackQuery):
        sel = _sess(query.message.chat.id)
        protocol = sel.get("current", {}).get("protocol", "all")
        rule_num = _rule_num(query.message.chat.id)
        await query.message.edit_text(
            f"🔌 Группа {rule_num}/{MAX_RULES}: "
            f"<b>{PROTOCOL_LABELS.get(protocol, protocol)}</b>\n\n"
            f"Выберите страну:",
            parse_mode=ParseMode.HTML,
            reply_markup=country_keyboard(protocol),
        )
        await query.answer()

    @dp.callback_query(F.data == "back:review")
    async def cb_back_review(query: types.CallbackQuery):
        await show_protocol_selection(query.message, query.message.chat.id, edit=True)
        await query.answer()


# ==================== RUN ====================
async def main():
    print(f"🚀 {CONFIG['SERVICE_NAME']} v{CONFIG['SERVICE_VERSION']} starting...")
    await load_nodes()
    print(f"📦 Загружено {len(NODES)} нод")

    if dp and bot:
        print("🤖 Starting Telegram bot polling...")
        import asyncio
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
