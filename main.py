"""
Vinted Sniper Web — V2
======================
- Multi-utilisateurs avec authentification (bcrypt + JWT en cookie HttpOnly)
- Filtres et items par utilisateur (isolation totale)
- Tiers : free, accompaniment, pro, admin
- Codes d'invitation pour les membres de l'accompagnement
- WebSocket avec auth pour les notifs temps réel
"""

import asyncio
import os
import json
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

# Charger le fichier .env automatiquement (résout le bug de clé temporaire + admin)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import aiohttp
import aiosqlite
import bcrypt
import jwt
try:
    import stripe as stripe_sdk
except ImportError:
    stripe_sdk = None
from collections import defaultdict
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

# =============================================================================
# CONFIGURATION
# =============================================================================
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logging.warning(
        "⚠️  SECRET_KEY non défini, une clé temporaire a été générée. "
        "Configure SECRET_KEY dans .env pour la production !"
    )

# ── RATE LIMITING simple en mémoire (IP → liste de timestamps) ──
_rate_limit_store: dict = defaultdict(list)
RATE_LIMIT_LOGIN = 8        # max 8 tentatives par minute
RATE_LIMIT_REGISTER = 5     # max 5 inscriptions par 10 min par IP
RATE_LIMIT_WINDOW_LOGIN = 60
RATE_LIMIT_WINDOW_REGISTER = 600


def check_rate_limit(key: str, max_attempts: int, window: int) -> bool:
    """Retourne True si la requête peut passer, False si bloquée."""
    now = datetime.now().timestamp()
    timestamps = _rate_limit_store[key]
    # On enlève les timestamps expirés
    timestamps[:] = [t for t in timestamps if now - t < window]
    if len(timestamps) >= max_attempts:
        return False
    timestamps.append(now)
    return True


def get_client_ip(request: Request) -> str:
    """Récupère l'IP réelle (gère X-Forwarded-For pour Railway/Cloudflare)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

JWT_ALGO = "HS256"
TOKEN_EXPIRE_HOURS = 24 * 14  # 14 jours
COOKIE_NAME = "vsw_session"
SECURE_COOKIE = os.getenv("SECURE_COOKIE", "false").lower() == "true"

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", 20))  # Délai entre scans (en secondes)
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", 3))  # Filtres traités en parallèle
DB_NAME = os.getenv("DB_NAME", "vinted_sniper.db")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))
INITIAL_ADMIN_EMAIL = os.getenv("INITIAL_ADMIN_EMAIL", "").lower().strip()
ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "true").lower() == "true"

# Limites par tier
TRIAL_DURATION_DAYS = int(os.getenv("TRIAL_DURATION_DAYS", 7))
MAX_FILTERS_FREE   = int(os.getenv("MAX_FILTERS_FREE",   1))   # Gratuit après essai : 1 filtre
MAX_FILTERS_TRIAL  = int(os.getenv("MAX_FILTERS_TRIAL",  3))   # Essai 7 jours : 3 filtres
TRIAL_TIERS = ("trial", "pro", "accompaniment", "admin")  # Reçoivent les notifs WS temps réel

# Plan tarifaire
PLAN_PRICE    = os.getenv("PLAN_PRICE", "9.99")
PLAN_CURRENCY = os.getenv("PLAN_CURRENCY", "EUR")

# ══ FILTRAGE TEMPOREL STRICT (anti-vieilles-annonces) ══
# Une annonce n'est considérée "nouvelle" que si elle a été créée dans les X dernières secondes.
# Vinted remonte parfois des annonces de plusieurs MOIS quand le vendeur les "boost".
# Avec cette limite, on rejette ces fausses nouveautés.
MAX_ITEM_AGE_SECONDS = int(os.getenv("MAX_ITEM_AGE_SECONDS", 600))  # 10 minutes par défaut

# =============================================================================
# STRIPE CONFIGURATION
# =============================================================================
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "")
STRIPE_SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", "http://localhost:8000/?payment=success")
STRIPE_CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", "http://localhost:8000/?payment=cancelled")

# =============================================================================
# PAYPAL CONFIGURATION
# =============================================================================
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
PAYPAL_PLAN_ID = os.getenv("PAYPAL_PLAN_ID", "")
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "")
PAYPAL_MODE = os.getenv("PAYPAL_MODE", "sandbox")
PAYPAL_API_BASE = (
    "https://api-m.sandbox.paypal.com" if PAYPAL_MODE == "sandbox"
    else "https://api-m.paypal.com"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


# =============================================================================
# UTILS AUTH (mots de passe + JWT)
# =============================================================================
def hash_password(plain: str) -> str:
    """Hash bcrypt (cost 12 par défaut, robuste contre brute-force)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Vérifie un mot de passe. Loggue les erreurs bcrypt pour debug."""
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError as e:
        # Hash corrompu en DB
        logging.error(f"❌ bcrypt ValueError : {e}")
        return False
    except Exception as e:
        logging.error(f"❌ bcrypt Exception : {type(e).__name__}: {e}")
        return False


def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)


def decode_token(token: Optional[str]) -> Optional[int]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
        return int(payload.get("sub"))
    except (jwt.PyJWTError, ValueError, TypeError):
        return None


# =============================================================================
# SCRAPER VINTED
# =============================================================================
class VintedScraper:
    """Scraper Vinted robuste avec gestion d'erreurs et rotation de sessions."""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "fr-FR,fr;q=0.9",
            "Referer": "https://www.vinted.fr/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "X-Requested-With": "XMLHttpRequest",
        }
        self.cookies = None
        self.cookies_fetched_at = None
        self.fail_count = 0
        self.lock = asyncio.Lock()  # Protection contre les races sur cookies

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=12),
                connector=aiohttp.TCPConnector(limit=25, ttl_dns_cache=300),
            )
        return self.session

    async def fetch_cookies(self, force=False):
        """Récupère / rafraîchit les cookies Vinted (toutes les 30 min ou en cas d'échec)."""
        async with self.lock:
            # Évite les requêtes en parallèle pour récupérer les cookies
            if not force and self.cookies_fetched_at:
                age = (datetime.now() - self.cookies_fetched_at).total_seconds()
                if age < 1800:  # 30 minutes
                    return
            try:
                session = await self._get_session()
                async with session.get("https://www.vinted.fr/", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    self.cookies = resp.cookies
                    self.cookies_fetched_at = datetime.now()
                    self.fail_count = 0
                    logging.info("🍪 Cookies Vinted actualisés.")
            except Exception as e:
                logging.error(f"Erreur cookies : {e}")

    async def fetch_items(self, url: str) -> list:
        """Récupère les items d'une URL de recherche Vinted."""
        if self.cookies is None:
            await self.fetch_cookies()
        session = await self._get_session()

        # Convertir l'URL catalog → API v2
        api_url = (
            url.replace("vinted.fr/catalog", "vinted.fr/api/v2/catalog/items")
            if "api/v2" not in url else url
        )

        try:
            async with session.get(api_url, cookies=self.cookies) as resp:
                if resp.status in (401, 403):
                    logging.warning(f"⚠️  Vinted rejette ({resp.status}), refresh cookies")
                    await self.fetch_cookies(force=True)
                    return []
                if resp.status == 429:
                    self.fail_count += 1
                    logging.warning(f"⚠️  Rate limit Vinted (429), pause prolongée")
                    await asyncio.sleep(min(30, 5 * self.fail_count))
                    return []
                if resp.status != 200:
                    logging.warning(f"⚠️  Vinted status {resp.status}")
                    return []

                data = await resp.json()
                items = data.get("items", [])
                self.fail_count = 0
                return items
        except asyncio.TimeoutError:
            logging.warning(f"⏱️  Timeout fetch Vinted")
            return []
        except Exception as e:
            logging.error(f"❌ Erreur fetch : {type(e).__name__}: {e}")
            return []

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()


def _extract_real_creation_ts(item: dict) -> Optional[float]:
    """
    Détermine le timestamp de CRÉATION RÉELLE d'une annonce Vinted.

    Vinted expose plusieurs champs et c'est piégeux :
    - photo.high_resolution.timestamp → le plus fiable (timestamp de la 1ère photo upload)
    - created_at_ts → souvent absent
    - updated_at_ts → BIAISÉ : modifié quand le vendeur boost/modifie l'annonce
                      C'est pour ça qu'on récupère des annonces de 9 mois en haut du tri "newest"

    On prend le PLUS ANCIEN parmi les sources disponibles pour avoir l'âge réel.
    """
    candidates = []

    # Source 1 : photo.high_resolution.timestamp (le plus fiable)
    photo = item.get("photo") or {}
    if isinstance(photo, dict):
        hr = photo.get("high_resolution") or {}
        if isinstance(hr, dict) and hr.get("timestamp"):
            try:
                candidates.append(float(hr["timestamp"]))
            except (ValueError, TypeError):
                pass

    # Source 2 : photos[0].high_resolution.timestamp (si plusieurs photos)
    photos = item.get("photos") or []
    if isinstance(photos, list) and photos:
        first = photos[0]
        if isinstance(first, dict):
            hr = first.get("high_resolution") or {}
            if isinstance(hr, dict) and hr.get("timestamp"):
                try:
                    candidates.append(float(hr["timestamp"]))
                except (ValueError, TypeError):
                    pass

    # Source 3 : created_at_ts (rarement présent)
    if item.get("created_at_ts"):
        try:
            candidates.append(float(item["created_at_ts"]))
        except (ValueError, TypeError):
            pass

    # On retourne le plus ANCIEN (= date de création réelle, pas le boost)
    return min(candidates) if candidates else None


async def send_discord_webhook(webhook_url: str, item: dict):
    """Envoie une notification Discord rich embed pour un nouvel item Vinted."""
    try:
        age = item.get("age_seconds")
        color = 0x00FF88 if (age is not None and age < 120) else 0x09B0B0
        embed = {
            "title": (item.get("title") or "Nouvelle annonce")[:256],
            "url": item.get("url", ""),
            "color": color,
            "fields": [
                {
                    "name": "💰 Prix",
                    "value": f"{item['price']:.2f} {item['currency']} *(TTC: {item['price_ttc']:.2f} €)*",
                    "inline": True,
                },
                {"name": "🏷️ Marque", "value": item.get("brand") or "—", "inline": True},
                {"name": "📏 Taille", "value": item.get("size") or "—", "inline": True},
                {"name": "💎 État", "value": item.get("status") or "—", "inline": True},
                {"name": "⌛ Publié", "value": item.get("published_at", "Récent"), "inline": True},
                {"name": "🔍 Filtre", "value": item.get("filter_name", "—"), "inline": True},
            ],
            "footer": {
                "text": f"Vinted Sniper • {item.get('seller', {}).get('login', '?')} "
                        f"({item.get('seller', {}).get('feedback_count', 0)} avis)"
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if item.get("main_photo"):
            embed["thumbnail"] = {"url": item["main_photo"]}

        payload = {
            "username": "Vinted Sniper 🔍",
            "embeds": [embed],
            "components": [
                {
                    "type": 1,
                    "components": [
                        {
                            "type": 2,
                            "style": 5,
                            "label": "🛒 Voir l'annonce",
                            "url": item.get("url", "https://vinted.fr"),
                        },
                        {
                            "type": 2,
                            "style": 5,
                            "label": "💬 Négocier",
                            "url": item.get("negotiate_url", "https://vinted.fr"),
                        },
                    ],
                }
            ],
        }
        async with aiohttp.ClientSession() as s:
            async with s.post(
                webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=6),
            ) as resp:
                if resp.status not in (200, 204):
                    logging.warning(f"Discord webhook erreur {resp.status}")
    except Exception as exc:
        logging.error(f"Discord webhook échec: {exc}")


def process_item(item: dict, filter_name: str, filter_id: int) -> dict:
    """Transforme un item Vinted brut en objet propre pour l'app.
    Tous les champs sont sécurisés contre les valeurs manquantes."""
    item_id = item.get("id")

    # ── Détermination de l'âge réel de l'annonce ──
    # Vinted expose plusieurs timestamps :
    #  - photo.high_resolution.timestamp = timestamp de création RÉELLE (le plus fiable)
    #  - created_at_ts = peut être absent
    #  - updated_at_ts = mis à jour quand le vendeur "boost" / modifie l'annonce
    # On prend le plus ancien disponible (= date de création réelle)
    age_seconds = None
    real_ts = _extract_real_creation_ts(item)
    if real_ts is not None:
        try:
            age_seconds = int(datetime.now().timestamp() - float(real_ts))
            if age_seconds < 0:
                age_seconds = 0
        except (ValueError, TypeError):
            age_seconds = None

    # Affichage humain
    if age_seconds is None:
        published_at = "Récent"
    elif age_seconds < 60:
        published_at = "À l'instant"
    elif age_seconds < 3600:
        published_at = f"il y a {age_seconds // 60} min"
    elif age_seconds < 86400:
        published_at = f"il y a {age_seconds // 3600} h"
    elif age_seconds < 86400 * 30:
        published_at = f"il y a {age_seconds // 86400} j"
    elif age_seconds < 86400 * 365:
        published_at = f"il y a {age_seconds // (86400 * 30)} mois"
    else:
        published_at = f"il y a {age_seconds // (86400 * 365)} an(s)"

    # ── Vendeur (avis & rating) ──
    user = item.get("user") or {}
    try:
        rating = float(user.get("rating") or 0)
    except (ValueError, TypeError):
        rating = 0.0
    try:
        feedback_count = int(user.get("feedback_count") or 0)
    except (ValueError, TypeError):
        feedback_count = 0

    # ── Prix + TTC (frais Vinted estimés : 0,70€ + 5%) ──
    price_data = item.get("price") or {}
    if isinstance(price_data, dict):
        price_amount = price_data.get("amount", "0.00")
        currency = price_data.get("currency_code", "EUR")
    else:
        price_amount = price_data
        currency = "EUR"
    currency_symbol = "€" if currency == "EUR" else (currency or "€")
    try:
        p = float(price_amount or 0)
        ttc = p + 0.70 + (p * 0.05)
    except (ValueError, TypeError):
        p, ttc = 0.0, 0.0

    # ── Photos ──
    photos = item.get("photos") or []
    if not isinstance(photos, list):
        photos = []
    all_photos = [
        ph["url"] for ph in photos
        if isinstance(ph, dict) and ph.get("url")
    ]
    main_photo = all_photos[0] if all_photos else (
        (item.get("photo") or {}).get("url") if isinstance(item.get("photo"), dict) else None
    )

    # ── État (neuf, très bon état, etc.) ──
    status = item.get("status") or item.get("status_title") or "—"
    if isinstance(status, dict):
        status = status.get("title") or "—"

    return {
        "id": item_id,
        "title": (item.get("title") or "Sans titre").strip(),
        "url": f"https://www.vinted.fr/items/{item_id}" if item_id else "#",
        "negotiate_url": f"https://www.vinted.fr/messages/new?item_id={item_id}" if item_id else "#",
        "price": round(p, 2),
        "price_ttc": round(ttc, 2),
        "currency": currency_symbol,
        "brand": (item.get("brand_title") or "—").strip(),
        "size": (item.get("size_title") or "—").strip(),
        "status": str(status).strip(),
        "main_photo": main_photo,
        "photos": all_photos,
        "published_at": published_at,
        "age_seconds": age_seconds,
        "seller": {
            "login": (user.get("login") or "Inconnu").strip(),
            "rating": round(rating, 2),
            "feedback_count": feedback_count,
            "feedback_reputation": user.get("feedback_reputation"),  # Note Vinted (sur 5)
        },
        "filter_id": filter_id,
        "filter_name": filter_name,
        "detected_at": datetime.now().isoformat(),
    }


# =============================================================================
# WEBSOCKET MANAGER (push par utilisateur)
# =============================================================================
class ConnectionManager:
    def __init__(self):
        self.connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, ws: WebSocket, user_id: int):
        await ws.accept()
        self.connections.setdefault(user_id, []).append(ws)
        total = sum(len(v) for v in self.connections.values())
        logging.info(f"🟢 WS connecté (user={user_id}). Total: {total}")

    def disconnect(self, ws: WebSocket, user_id: int):
        if user_id in self.connections:
            try:
                self.connections[user_id].remove(ws)
            except ValueError:
                pass
            if not self.connections[user_id]:
                del self.connections[user_id]

    async def send_to_user(self, user_id: int, payload: dict):
        if user_id not in self.connections:
            return
        dead = []
        for ws in self.connections[user_id]:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, user_id)


# =============================================================================
# BOUCLE DE SCAN
# =============================================================================
async def _scan_filter(app: FastAPI, filter_id: int, user_id: int, url: str, name: str, sem: asyncio.Semaphore):
    """
    Traite un seul filtre :
    - Premier scan → marque tous les items comme vus sans notifier
    - Scans suivants → charge les seen_ids en batch, rejette les vieux, notifie les nouveaux
    """
    async with sem:
        items = await app.state.scraper.fetch_items(url)
        if not items:
            return

        # ── Premier scan ? (1 requête COUNT au lieu de N requêtes SELECT) ──
        async with app.state.db.execute(
            "SELECT COUNT(*) FROM seen_items WHERE filter_id = ?", (filter_id,)
        ) as c:
            already_seen_count = (await c.fetchone())[0]

        if already_seen_count == 0:
            logging.info(
                f"🔄 Premier scan du filtre '{name}' (id={filter_id}) — "
                f"marquage de {len(items)} items existants comme déjà vus."
            )
            batch = [
                (item.get("id"), filter_id, datetime.now())
                for item in items if item.get("id")
            ]
            if batch:
                await app.state.db.executemany(
                    "INSERT OR IGNORE INTO seen_items (item_id, filter_id, timestamp) VALUES (?, ?, ?)",
                    batch,
                )
                await app.state.db.commit()
            return

        # ── Chargement en batch de TOUS les seen_ids du filtre (élimine le N+1) ──
        async with app.state.db.execute(
            "SELECT item_id FROM seen_items WHERE filter_id = ?", (filter_id,)
        ) as c:
            seen_ids: set = {row[0] for row in await c.fetchall()}

        # ── Tier utilisateur (1 requête par filtre, pas par item) ──
        async with app.state.db.execute(
            "SELECT tier, discord_webhook_url FROM users WHERE id = ?", (user_id,)
        ) as c:
            urow = await c.fetchone()
        user_tier = urow[0] if urow else "free"
        discord_url = urow[1] if urow else None

        new_items_count = 0
        rejected_old_count = 0
        rejected_no_ts_count = 0

        new_seen_batch: list = []
        new_cache_batch: list = []
        new_item_payloads: list = []

        now = datetime.now()

        for item in items[:20]:
            item_id = item.get("id")
            if not item_id or item_id in seen_ids:
                continue

            real_ts = _extract_real_creation_ts(item)

            if real_ts is None:
                rejected_no_ts_count += 1
                new_seen_batch.append((item_id, filter_id, now))
                continue

            age = now.timestamp() - float(real_ts)

            if age > MAX_ITEM_AGE_SECONDS or age < 0:
                if age > 0:
                    rejected_old_count += 1
                new_seen_batch.append((item_id, filter_id, now))
                continue

            # ✅ Item vraiment nouveau
            new_items_count += 1
            new_seen_batch.append((item_id, filter_id, now))
            processed = process_item(item, name, filter_id)
            new_cache_batch.append((item_id, user_id, filter_id, json.dumps(processed)))
            new_item_payloads.append(processed)

        # ── Insertions en batch (1 commit par filtre) ──
        if new_seen_batch:
            await app.state.db.executemany(
                "INSERT OR IGNORE INTO seen_items (item_id, filter_id, timestamp) VALUES (?, ?, ?)",
                new_seen_batch,
            )
        if new_cache_batch:
            await app.state.db.executemany(
                "INSERT INTO items_cache (item_id, user_id, filter_id, data) VALUES (?, ?, ?, ?)",
                new_cache_batch,
            )
        if new_seen_batch or new_cache_batch:
            await app.state.db.commit()

        # ── Notifications WS + Discord (tiers payants uniquement) ──
        if user_tier in TRIAL_TIERS:
            for processed in new_item_payloads:
                await app.state.manager.send_to_user(
                    user_id, {"type": "new_item", "item": processed}
                )
                if discord_url:
                    await send_discord_webhook(discord_url, processed)

        if new_items_count or rejected_old_count or rejected_no_ts_count:
            logging.info(
                f"📊 Filtre '{name}' (id={filter_id}) : "
                f"{new_items_count} nouveau(x), "
                f"{rejected_old_count} ancien(s) rejeté(s), "
                f"{rejected_no_ts_count} sans-ts rejeté(s)"
            )


async def scan_loop(app: FastAPI):
    """
    Boucle principale de scan.
    Tous les filtres sont scannés en parallèle (SCAN_CONCURRENCY à la fois)
    pour réduire la latence de détection quand de nombreux filtres sont actifs.
    """
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    while True:
        try:
            async with app.state.db.execute(
                "SELECT id, user_id, url, name FROM filters"
            ) as cursor:
                filters = await cursor.fetchall()

            if filters:
                tasks = [
                    _scan_filter(app, fid, uid, url, name, sem)
                    for fid, uid, url, name in filters
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, r in enumerate(results):
                    if isinstance(r, Exception):
                        logging.error(f"❌ Erreur filtre id={filters[i][0]} : {r}")

        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.error(f"Erreur scan_loop : {e}")

        await asyncio.sleep(CHECK_INTERVAL)


# =============================================================================
# NETTOYAGE AUTOMATIQUE DE LA BASE DE DONNÉES
# =============================================================================
async def cleanup_loop(app: FastAPI):
    """
    Supprime périodiquement les données obsolètes pour éviter la croissance
    incontrôlée de la base SQLite :
    - seen_items > 30 jours (les items anciens ne seront jamais re-détectés)
    - items_cache > 7 jours (l'historique affiché dans l'UI reste léger)
    """
    while True:
        try:
            await asyncio.sleep(3600)  # Toutes les heures
            cutoff_seen = (datetime.now() - timedelta(days=30)).isoformat()
            cutoff_cache = (datetime.now() - timedelta(days=7)).isoformat()
            await app.state.db.execute(
                "DELETE FROM seen_items WHERE timestamp < ?", (cutoff_seen,)
            )
            await app.state.db.execute(
                "DELETE FROM items_cache WHERE detected_at < ?", (cutoff_cache,)
            )
            await app.state.db.commit()
            logging.info("🧹 Nettoyage DB effectué (seen_items > 30j, cache > 7j)")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.error(f"Erreur cleanup_loop : {e}")


# =============================================================================
# LIFECYCLE
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    db = await aiosqlite.connect(DB_NAME)
    await db.execute("PRAGMA journal_mode = WAL")       # Lectures concurrentes sans blocage
    await db.execute("PRAGMA synchronous = NORMAL")     # Plus rapide tout en restant safe
    await db.execute("PRAGMA cache_size = -32768")      # 32 MB de cache en mémoire
    await db.execute("PRAGMA temp_store = MEMORY")      # Tables temporaires en RAM
    await db.execute("PRAGMA foreign_keys = ON")

    await db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'trial',
            invite_code_used TEXT,
            trial_started_at DATETIME,
            trial_ends_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- Migration douce pour DB existante (ignore l'erreur si la colonne existe déjà)

        CREATE TABLE IF NOT EXISTS invite_codes (
            code TEXT PRIMARY KEY,
            tier TEXT NOT NULL DEFAULT 'accompaniment',
            note TEXT,
            used_by INTEGER,
            used_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS seen_items (
            item_id INTEGER NOT NULL,
            filter_id INTEGER NOT NULL,
            timestamp DATETIME,
            PRIMARY KEY (item_id, filter_id),
            FOREIGN KEY (filter_id) REFERENCES filters(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS items_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            filter_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (filter_id) REFERENCES filters(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS feature_codes (
            code TEXT PRIMARY KEY,
            feature TEXT NOT NULL DEFAULT 'discord',
            note TEXT,
            max_uses INTEGER DEFAULT 1,
            use_count INTEGER DEFAULT 0,
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS user_features (
            user_id INTEGER NOT NULL,
            feature TEXT NOT NULL,
            unlocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            code_used TEXT,
            PRIMARY KEY (user_id, feature),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_filters_user ON filters(user_id);
        CREATE INDEX IF NOT EXISTS idx_items_user ON items_cache(user_id, detected_at DESC);
        CREATE INDEX IF NOT EXISTS idx_items_filter ON items_cache(filter_id);
        CREATE INDEX IF NOT EXISTS idx_seen_filter ON seen_items(filter_id);
        CREATE INDEX IF NOT EXISTS idx_user_features ON user_features(user_id);
    """)

    # Migrations douces (pour DBs créées avant l'ajout de trial_started_at / trial_ends_at)
    for col in ("trial_started_at DATETIME", "trial_ends_at DATETIME"):
        try:
            await db.execute(f"ALTER TABLE users ADD COLUMN {col}")
        except Exception:
            pass  # colonne déjà présente

    # Migrations paiements & notifications
    for col in (
        "stripe_customer_id TEXT",
        "stripe_subscription_id TEXT",
        "paypal_subscription_id TEXT",
        "discord_webhook_url TEXT",
    ):
        try:
            await db.execute(f"ALTER TABLE users ADD COLUMN {col}")
        except Exception:
            pass

    await db.commit()

    app.state.db = db
    app.state.scraper = VintedScraper()
    await app.state.scraper.fetch_cookies()
    app.state.manager = ConnectionManager()
    app.state.scan_task = asyncio.create_task(scan_loop(app))
    app.state.cleanup_task = asyncio.create_task(cleanup_loop(app))

    logging.info(f"✅ Vinted Sniper Web prêt sur http://{HOST}:{PORT}")
    yield

    app.state.scan_task.cancel()
    app.state.cleanup_task.cancel()
    for task in (app.state.scan_task, app.state.cleanup_task):
        try:
            await task
        except asyncio.CancelledError:
            pass
    await app.state.scraper.close()
    await db.close()


app = FastAPI(title="Vinted Sniper Web", lifespan=lifespan)


# ── Middleware de sécurité : ajout d'en-têtes HTTP protecteurs ──
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Empêche le clickjacking (le site ne peut pas être affiché dans un iframe externe)
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    # Empêche le browser de "deviner" le type MIME (réduit les attaques XSS)
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Limite l'envoi du Referer aux sites externes
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Empêche le browser de cacher les pages auth en arrière-plan
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    # Active une protection XSS basique (legacy)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Force HTTPS sur 1 an (uniquement si HTTPS activé)
    if SECURE_COOKIE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# =============================================================================
# DEPENDENCIES (auth)
# =============================================================================
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    user_id = decode_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Non authentifié")

    async with app.state.db.execute(
        "SELECT id, email, username, tier, created_at, trial_started_at, trial_ends_at "
        "FROM users WHERE id = ?",
        (user_id,),
    ) as c:
        row = await c.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")

    user_id_db, email, username, tier, created_at, trial_start, trial_end = row

    # ── Expiration automatique du trial : passage en 'free' ──
    if tier == "trial" and trial_end:
        # Parse la date stockée en string SQLite
        try:
            te = datetime.fromisoformat(trial_end) if isinstance(trial_end, str) else trial_end
            if datetime.now() > te:
                await app.state.db.execute(
                    "UPDATE users SET tier = 'free' WHERE id = ?", (user_id_db,)
                )
                await app.state.db.commit()
                tier = "free"
        except (ValueError, TypeError):
            pass

    # ── Admin auto si l'email correspond à INITIAL_ADMIN_EMAIL (failsafe) ──
    if INITIAL_ADMIN_EMAIL and email == INITIAL_ADMIN_EMAIL and tier != "admin":
        await app.state.db.execute(
            "UPDATE users SET tier = 'admin' WHERE id = ?", (user_id_db,)
        )
        await app.state.db.commit()
        tier = "admin"

    return {
        "id": user_id_db,
        "email": email,
        "username": username,
        "tier": tier,
        "created_at": created_at,
        "trial_started_at": trial_start,
        "trial_ends_at": trial_end,
    }


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["tier"] != "admin":
        raise HTTPException(status_code=403, detail="Réservé aux administrateurs")
    return user


def set_auth_cookie(response: Response, user_id: int):
    token = create_token(user_id)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=TOKEN_EXPIRE_HOURS * 3600,
        httponly=True,         # JS du navigateur ne peut pas lire le cookie -> protège du XSS
        samesite="lax",        # Protège du CSRF cross-site
        secure=SECURE_COOKIE,  # Mettre à True en HTTPS (production)
        path="/",
    )


# =============================================================================
# MODÈLES PYDANTIC
# =============================================================================
class RegisterIn(BaseModel):
    email: str
    username: str
    password: str
    invite_code: Optional[str] = None

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[-1] or len(v) < 5:
            raise ValueError("Email invalide")
        return v

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3 or len(v) > 24:
            raise ValueError("Le pseudo doit faire entre 3 et 24 caractères")
        if not all(c.isalnum() or c in "_-." for c in v):
            raise ValueError("Le pseudo ne peut contenir que lettres, chiffres, _ - .")
        return v

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Mot de passe : 8 caractères minimum")
        if len(v) > 200:
            raise ValueError("Mot de passe trop long")
        return v


class LoginIn(BaseModel):
    identifier: str  # email ou username
    password: str


class FilterCreate(BaseModel):
    name: str
    url: str

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Nom requis")
        if len(v) > 60:
            raise ValueError("Nom trop long (max 60)")
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip()
        if "vinted." not in v:
            raise ValueError("URL Vinted invalide")
        return v


class InviteCreate(BaseModel):
    count: int = 1
    tier: str = "accompaniment"
    note: Optional[str] = None


class SettingsUpdate(BaseModel):
    discord_webhook_url: Optional[str] = None

    @field_validator("discord_webhook_url")
    @classmethod
    def _webhook_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None or (isinstance(v, str) and v.strip() == ""):
            return None
        v = v.strip()
        valid = "discord.com/api/webhooks/" in v or "discordapp.com/api/webhooks/" in v
        if not valid:
            raise ValueError("URL Discord Webhook invalide — colle l'URL depuis Discord (Intégrations → Webhooks)")
        return v


class TierUpdate(BaseModel):
    tier: str


class PayPalVerifyIn(BaseModel):
    subscription_id: str


VALID_FEATURES = ("discord",)
FEATURE_LABELS = {"discord": "Notifications Discord"}


class FeatureCodeCreate(BaseModel):
    count: int = 1
    feature: str = "discord"
    note: Optional[str] = None
    max_uses: int = 1  # 0 = illimité

    @field_validator("feature")
    @classmethod
    def _feature(cls, v: str) -> str:
        if v not in VALID_FEATURES:
            raise ValueError(f"Feature inconnue : {v!r}")
        return v

    @field_validator("count")
    @classmethod
    def _count(cls, v: int) -> int:
        if v < 1 or v > 100:
            raise ValueError("Quantité entre 1 et 100")
        return v

    @field_validator("max_uses")
    @classmethod
    def _max_uses(cls, v: int) -> int:
        if v < 0:
            raise ValueError("max_uses doit être >= 0")
        return v


class FeatureCodeRedeem(BaseModel):
    code: str

    @field_validator("code")
    @classmethod
    def _code(cls, v: str) -> str:
        v = v.strip().upper()
        if not v:
            raise ValueError("Code vide")
        return v


# =============================================================================
# ROUTES AUTH
# =============================================================================
@app.post("/api/auth/register")
async def register(payload: RegisterIn, response: Response, request: Request):
    # Rate limiting par IP : max 5 inscriptions/10min
    ip = get_client_ip(request)
    if not check_rate_limit(f"register:{ip}", RATE_LIMIT_REGISTER, RATE_LIMIT_WINDOW_REGISTER):
        logging.warning(f"🚫 Rate limit register dépassé pour IP {ip}")
        raise HTTPException(429, "Trop d'inscriptions depuis cette IP, réessaie plus tard")

    if not ALLOW_REGISTRATION:
        raise HTTPException(403, "Inscription désactivée")

    db = app.state.db

    # Unicité
    async with db.execute(
        "SELECT 1 FROM users WHERE email = ? OR username = ?",
        (payload.email, payload.username),
    ) as c:
        if await c.fetchone():
            raise HTTPException(409, "Email ou pseudo déjà utilisé")

    # Tier par défaut : trial (7 jours d'accès complet) — passe à 'free' à expiration
    tier = "trial"
    invite_used = None
    if payload.invite_code:
        code = payload.invite_code.strip().upper()
        async with db.execute(
            "SELECT code, tier, used_by, used_at FROM invite_codes WHERE code = ?", (code,)
        ) as c:
            row = await c.fetchone()
        if not row:
            logging.warning(f"🎟️  Code invitation inexistant : {code}")
            raise HTTPException(400, "Code d'invitation invalide")
        if row[2] is not None:
            logging.warning(f"🎟️  Code déjà utilisé : {code} par user_id={row[2]} le {row[3]}")
            raise HTTPException(400, "Code d'invitation déjà utilisé")
        tier = row[1]
        invite_used = code
        logging.info(f"🎟️  Code valide utilisé à l'inscription : {code} (tier={tier})")

    # Admin auto par email (utile pour le 1er compte)
    if INITIAL_ADMIN_EMAIL and payload.email == INITIAL_ADMIN_EMAIL:
        tier = "admin"

    # Si trial, fixer les dates de début et fin
    trial_start = trial_end = None
    if tier == "trial":
        trial_start = datetime.now()
        trial_end = trial_start + timedelta(days=TRIAL_DURATION_DAYS)

    cursor = await db.execute(
        "INSERT INTO users (email, username, password_hash, tier, invite_code_used, "
        "trial_started_at, trial_ends_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            payload.email,
            payload.username,
            hash_password(payload.password),
            tier,
            invite_used,
            trial_start,
            trial_end,
        ),
    )
    user_id = cursor.lastrowid

    if invite_used:
        await db.execute(
            "UPDATE invite_codes SET used_by = ?, used_at = ? WHERE code = ?",
            (user_id, datetime.now(), invite_used),
        )

    await db.commit()

    set_auth_cookie(response, user_id)
    logging.info(f"➕ User créé : {payload.username} ({payload.email}) tier={tier}")

    return {
        "id": user_id,
        "email": payload.email,
        "username": payload.username,
        "tier": tier,
        "trial_ends_at": trial_end.isoformat() if trial_end else None,
    }


@app.post("/api/auth/login")
async def login(payload: LoginIn, response: Response, request: Request):
    # Rate limiting par IP : max 8 tentatives/min
    ip = get_client_ip(request)
    if not check_rate_limit(f"login:{ip}", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_LOGIN):
        logging.warning(f"🚫 Rate limit login dépassé pour IP {ip}")
        raise HTTPException(429, "Trop de tentatives, réessaie dans 1 minute")

    """Login robuste avec logs détaillés pour debug."""
    db = app.state.db
    ident = payload.identifier.strip().lower()
    if not ident or not payload.password:
        raise HTTPException(400, "Email/pseudo et mot de passe requis")

    try:
        async with db.execute(
            "SELECT id, email, username, password_hash, tier, trial_ends_at FROM users "
            "WHERE LOWER(email) = ? OR LOWER(username) = ?",
            (ident, ident),
        ) as c:
            row = await c.fetchone()
    except Exception as e:
        logging.error(f"❌ Erreur DB login : {e}")
        raise HTTPException(500, "Erreur serveur")

    if not row:
        logging.warning(f"🔒 Login échoué : aucun user pour '{ident}'")
        raise HTTPException(401, "Identifiants invalides")

    if not verify_password(payload.password, row[3]):
        logging.warning(f"🔒 Login échoué : mot de passe incorrect pour user_id={row[0]}")
        raise HTTPException(401, "Identifiants invalides")

    user_id_db, email, username, tier, trial_end = row[0], row[1], row[2], row[4], row[5]

    # ── Promotion admin automatique (même failsafe que get_current_user) ──
    # Corrige le cas où le compte a été créé avant que INITIAL_ADMIN_EMAIL soit défini,
    # ou quand le trial a expiré et a dégradé le compte admin en 'free'.
    if INITIAL_ADMIN_EMAIL and email == INITIAL_ADMIN_EMAIL and tier != "admin":
        await db.execute(
            "UPDATE users SET tier = 'admin' WHERE id = ?", (user_id_db,)
        )
        await db.commit()
        tier = "admin"
        logging.info(f"🔧 Promotion admin auto au login pour {email}")

    try:
        set_auth_cookie(response, user_id_db)
    except Exception as e:
        logging.error(f"❌ Erreur création cookie : {e}")
        raise HTTPException(500, "Erreur serveur")

    logging.info(f"✅ Login réussi : {username} (id={user_id_db}, tier={tier})")
    return {
        "id": user_id_db,
        "email": email,
        "username": username,
        "tier": tier,
        "trial_ends_at": trial_end,
    }


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "ok"}


@app.get("/api/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


# =============================================================================
# ROUTES FILTRES (par utilisateur)
# =============================================================================
@app.get("/api/filters")
async def list_filters(user: dict = Depends(get_current_user)):
    async with app.state.db.execute(
        "SELECT id, name, url, created_at FROM filters "
        "WHERE user_id = ? ORDER BY created_at DESC",
        (user["id"],),
    ) as c:
        rows = await c.fetchall()
    return [
        {"id": r[0], "name": r[1], "url": r[2], "created_at": r[3]}
        for r in rows
    ]


@app.post("/api/filters")
async def create_filter(
    payload: FilterCreate, user: dict = Depends(get_current_user)
):
    # ── Limites de filtres selon le tier ──
    if user["tier"] in ("free", "trial"):
        limit = MAX_FILTERS_FREE if user["tier"] == "free" else MAX_FILTERS_TRIAL
        async with app.state.db.execute(
            "SELECT COUNT(*) FROM filters WHERE user_id = ?", (user["id"],)
        ) as c:
            count = (await c.fetchone())[0]
        if count >= limit:
            if user["tier"] == "free":
                raise HTTPException(
                    403,
                    f"Limite de {MAX_FILTERS_FREE} filtre(s) atteinte en plan gratuit. "
                    "Passe à Pro pour des filtres illimités.",
                )
            else:
                raise HTTPException(
                    403,
                    f"Limite de {MAX_FILTERS_TRIAL} filtres atteinte pendant l'essai gratuit. "
                    "Passe à Pro pour des filtres illimités.",
                )

    url = payload.url
    if "order=newest_first" not in url:
        url += ("&" if "?" in url else "?") + "order=newest_first"

    cursor = await app.state.db.execute(
        "INSERT INTO filters (user_id, name, url) VALUES (?, ?, ?)",
        (user["id"], payload.name, url),
    )
    await app.state.db.commit()
    return {
        "id": cursor.lastrowid,
        "name": payload.name,
        "url": url,
    }


@app.delete("/api/filters/{filter_id}")
async def delete_filter(filter_id: int, user: dict = Depends(get_current_user)):
    cursor = await app.state.db.execute(
        "DELETE FROM filters WHERE id = ? AND user_id = ?",
        (filter_id, user["id"]),
    )
    await app.state.db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(404, "Filtre introuvable")
    return {"status": "ok"}


@app.delete("/api/filters")
async def delete_all_filters(user: dict = Depends(get_current_user)):
    await app.state.db.execute(
        "DELETE FROM filters WHERE user_id = ?", (user["id"],)
    )
    await app.state.db.commit()
    return {"status": "ok"}


# =============================================================================
# ROUTES ITEMS (par utilisateur)
# =============================================================================
@app.get("/api/items")
async def list_items(
    limit: int = 100,
    filter_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    if filter_id:
        async with app.state.db.execute(
            "SELECT data FROM items_cache "
            "WHERE user_id = ? AND filter_id = ? "
            "ORDER BY detected_at DESC LIMIT ?",
            (user["id"], filter_id, limit),
        ) as c:
            rows = await c.fetchall()
    else:
        async with app.state.db.execute(
            "SELECT data FROM items_cache "
            "WHERE user_id = ? "
            "ORDER BY detected_at DESC LIMIT ?",
            (user["id"], limit),
        ) as c:
            rows = await c.fetchall()
    return [json.loads(r[0]) for r in rows]


@app.delete("/api/items")
async def clear_items(user: dict = Depends(get_current_user)):
    # On vide le cache + les seen pour les filtres de l'user (pour pouvoir re-recevoir les annonces)
    await app.state.db.execute(
        "DELETE FROM items_cache WHERE user_id = ?", (user["id"],)
    )
    await app.state.db.execute(
        "DELETE FROM seen_items WHERE filter_id IN "
        "(SELECT id FROM filters WHERE user_id = ?)",
        (user["id"],),
    )
    await app.state.db.commit()
    return {"status": "ok"}


# =============================================================================
# ROUTES ADMIN (codes d'invitation)
# =============================================================================
def _gen_code(length=10) -> str:
    import string
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@app.get("/api/admin/invites")
async def list_invites(admin: dict = Depends(require_admin)):
    async with app.state.db.execute(
        "SELECT code, tier, note, used_by, used_at, created_at "
        "FROM invite_codes ORDER BY created_at DESC"
    ) as c:
        rows = await c.fetchall()
    return [
        {
            "code": r[0],
            "tier": r[1],
            "note": r[2],
            "used_by": r[3],
            "used_at": r[4],
            "created_at": r[5],
            "is_used": r[3] is not None,
            # Marqué manuellement = utilisé par l'admin lui-même
            "marked_manually": r[3] == admin["id"],
        }
        for r in rows
    ]


@app.post("/api/admin/invites")
async def create_invites(
    payload: InviteCreate, admin: dict = Depends(require_admin)
):
    """
    Génère des codes d'invitation uniques.
    Gère :
    - les collisions (très rare mais possible) en réessayant
    - les tiers invalides
    - le rollback en cas d'erreur DB
    """
    # Validation
    if payload.count < 1 or payload.count > 100:
        raise HTTPException(400, "Quantité entre 1 et 100")
    if payload.tier not in ("free", "accompaniment", "pro"):
        raise HTTPException(400, f"Tier invalide : {payload.tier!r}")

    db = app.state.db
    codes = []
    note = (payload.note or "").strip() or None

    try:
        for i in range(payload.count):
            # Tentative max 10 fois pour générer un code unique
            attempts = 0
            while attempts < 10:
                code = _gen_code()
                try:
                    await db.execute(
                        "INSERT INTO invite_codes (code, tier, note) VALUES (?, ?, ?)",
                        (code, payload.tier, note),
                    )
                    codes.append(code)
                    break
                except aiosqlite.IntegrityError:
                    # Collision sur la PK → on retente
                    attempts += 1
            else:
                # 10 collisions consécutives → impossible (chance ~ 0)
                await db.rollback()
                raise HTTPException(500, "Impossible de générer un code unique, réessaie")

        await db.commit()
        logging.info(f"🎟️  {len(codes)} code(s) [{payload.tier}] générés par admin {admin['username']}")
        return {"codes": codes}

    except HTTPException:
        raise
    except Exception as e:
        try:
            await db.rollback()
        except Exception:
            pass
        logging.error(f"Erreur génération codes : {e}")
        raise HTTPException(500, f"Erreur serveur : {e}")


@app.delete("/api/admin/invites/{code}")
async def delete_invite(code: str, _: dict = Depends(require_admin)):
    await app.state.db.execute(
        "DELETE FROM invite_codes WHERE code = ? AND used_by IS NULL", (code,)
    )
    await app.state.db.commit()
    return {"status": "ok"}


# ── Marquer un code comme "utilisé manuellement" (sans qu'un user l'ait saisi) ──
@app.post("/api/admin/invites/{code}/mark-used")
async def mark_invite_used(code: str, admin: dict = Depends(require_admin)):
    """L'admin coche manuellement un code comme utilisé. Empêche sa réutilisation et son affichage clair."""
    cursor = await app.state.db.execute(
        "UPDATE invite_codes SET used_by = ?, used_at = ? "
        "WHERE code = ? AND used_by IS NULL",
        (admin["id"], datetime.now(), code),
    )
    await app.state.db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(404, "Code introuvable ou déjà utilisé")
    return {"status": "ok"}


# ── Annuler le marquage manuel (rendre le code à nouveau disponible) ──
@app.post("/api/admin/invites/{code}/unmark-used")
async def unmark_invite_used(code: str, admin: dict = Depends(require_admin)):
    """Annule le marquage manuel. On vérifie que le code n'a pas été utilisé par un autre user."""
    async with app.state.db.execute(
        "SELECT used_by FROM invite_codes WHERE code = ?", (code,)
    ) as c:
        row = await c.fetchone()
    if not row:
        raise HTTPException(404, "Code introuvable")
    if row[0] != admin["id"]:
        raise HTTPException(400, "Ce code a été utilisé par un utilisateur réel, impossible de l'annuler")
    await app.state.db.execute(
        "UPDATE invite_codes SET used_by = NULL, used_at = NULL WHERE code = ?",
        (code,),
    )
    await app.state.db.commit()
    return {"status": "ok"}


# =============================================================================
# ADMIN — CODES FONCTIONNALITÉS
# =============================================================================
@app.post("/api/admin/feature-codes")
async def create_feature_codes(
    payload: FeatureCodeCreate, admin: dict = Depends(require_admin)
):
    codes = []
    note = (payload.note or "").strip() or None
    try:
        for _ in range(payload.count):
            attempts = 0
            while attempts < 10:
                code = _gen_code()
                try:
                    await app.state.db.execute(
                        "INSERT INTO feature_codes (code, feature, note, max_uses, created_by) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (code, payload.feature, note, payload.max_uses, admin["id"]),
                    )
                    codes.append(code)
                    break
                except aiosqlite.IntegrityError:
                    attempts += 1
            else:
                await app.state.db.rollback()
                raise HTTPException(500, "Impossible de générer un code unique, réessaie")
        await app.state.db.commit()
        logging.info(
            f"🔐 {len(codes)} code(s) feature [{payload.feature}] générés par {admin['username']}"
        )
        return {"codes": codes}
    except HTTPException:
        raise
    except Exception as e:
        try:
            await app.state.db.rollback()
        except Exception:
            pass
        raise HTTPException(500, f"Erreur serveur : {e}")


@app.get("/api/admin/feature-codes")
async def list_feature_codes(_: dict = Depends(require_admin)):
    async with app.state.db.execute(
        "SELECT code, feature, note, max_uses, use_count, created_at "
        "FROM feature_codes ORDER BY created_at DESC"
    ) as c:
        rows = await c.fetchall()
    return [
        {
            "code": r[0],
            "feature": r[1],
            "feature_label": FEATURE_LABELS.get(r[1], r[1]),
            "note": r[2],
            "max_uses": r[3],
            "use_count": r[4],
            "created_at": r[5],
            "is_exhausted": r[3] > 0 and r[4] >= r[3],
        }
        for r in rows
    ]


@app.delete("/api/admin/feature-codes/{code}")
async def delete_feature_code(code: str, _: dict = Depends(require_admin)):
    await app.state.db.execute("DELETE FROM feature_codes WHERE code = ?", (code,))
    await app.state.db.commit()
    return {"status": "ok"}


# =============================================================================
# USER — FONCTIONNALITÉS DÉBLOQUÉES
# =============================================================================
@app.get("/api/features")
async def list_user_features(user: dict = Depends(get_current_user)):
    async with app.state.db.execute(
        "SELECT feature, unlocked_at FROM user_features WHERE user_id = ?",
        (user["id"],),
    ) as c:
        rows = await c.fetchall()
    return {
        "features": [
            {"feature": r[0], "label": FEATURE_LABELS.get(r[0], r[0]), "unlocked_at": r[1]}
            for r in rows
        ]
    }


@app.post("/api/features/redeem")
async def redeem_feature_code(
    payload: FeatureCodeRedeem, user: dict = Depends(get_current_user)
):
    code = payload.code

    async with app.state.db.execute(
        "SELECT feature, max_uses, use_count FROM feature_codes WHERE code = ?", (code,)
    ) as c:
        row = await c.fetchone()

    if not row:
        raise HTTPException(404, "Code invalide ou inexistant")

    feature, max_uses, use_count = row

    if max_uses > 0 and use_count >= max_uses:
        raise HTTPException(400, "Ce code a déjà été utilisé au maximum")

    async with app.state.db.execute(
        "SELECT 1 FROM user_features WHERE user_id = ? AND feature = ?",
        (user["id"], feature),
    ) as c:
        if await c.fetchone():
            raise HTTPException(400, "Tu as déjà accès à cette fonctionnalité !")

    await app.state.db.execute(
        "INSERT INTO user_features (user_id, feature, code_used) VALUES (?, ?, ?)",
        (user["id"], feature, code),
    )
    await app.state.db.execute(
        "UPDATE feature_codes SET use_count = use_count + 1 WHERE code = ?", (code,)
    )
    await app.state.db.commit()
    logging.info(f"🔓 User {user['id']} ({user['username']}) a débloqué '{feature}' avec code {code}")
    return {"feature": feature, "label": FEATURE_LABELS.get(feature, feature)}


# =============================================================================
# CONFIGURATION PUBLIQUE (clés front-end non-sensibles)
# =============================================================================
@app.get("/api/config")
async def get_config():
    return {
        "stripe_publishable_key": STRIPE_PUBLISHABLE_KEY,
        "paypal_client_id": PAYPAL_CLIENT_ID,
        "paypal_plan_id": PAYPAL_PLAN_ID,
        "paypal_mode": PAYPAL_MODE,
        "payments_enabled": bool(STRIPE_SECRET_KEY or PAYPAL_CLIENT_ID),
        "plan_price": PLAN_PRICE,
        "plan_currency": PLAN_CURRENCY,
    }


# =============================================================================
# PARAMÈTRES UTILISATEUR (Discord webhook, etc.)
# =============================================================================
async def _user_has_feature(db, user_id: int, feature: str) -> bool:
    async with db.execute(
        "SELECT 1 FROM user_features WHERE user_id = ? AND feature = ?",
        (user_id, feature),
    ) as c:
        return (await c.fetchone()) is not None


@app.get("/api/settings")
async def get_settings(user: dict = Depends(get_current_user)):
    async with app.state.db.execute(
        "SELECT discord_webhook_url, stripe_subscription_id, paypal_subscription_id "
        "FROM users WHERE id = ?",
        (user["id"],),
    ) as c:
        row = await c.fetchone()

    # Admin a toujours accès ; les autres ont besoin du code feature
    has_discord = user["tier"] == "admin" or await _user_has_feature(
        app.state.db, user["id"], "discord"
    )

    async with app.state.db.execute(
        "SELECT feature, unlocked_at FROM user_features WHERE user_id = ?",
        (user["id"],),
    ) as c:
        feat_rows = await c.fetchall()

    return {
        "discord_webhook_url": row[0] if row else None,
        "has_stripe_sub": bool(row[1]) if row else False,
        "has_paypal_sub": bool(row[2]) if row else False,
        "has_discord_feature": has_discord,
        "features": [
            {"feature": r[0], "label": FEATURE_LABELS.get(r[0], r[0]), "unlocked_at": r[1]}
            for r in feat_rows
        ],
    }


@app.put("/api/settings")
async def update_settings(payload: SettingsUpdate, user: dict = Depends(get_current_user)):
    if payload.discord_webhook_url is not None:
        # Admin : toujours autorisé. Autres : besoin du code feature discord
        if user["tier"] != "admin":
            if not await _user_has_feature(app.state.db, user["id"], "discord"):
                raise HTTPException(
                    403,
                    "Cette fonctionnalité nécessite un code spécial. "
                    "Entre ton code dans Paramètres → Mes codes."
                )
    await app.state.db.execute(
        "UPDATE users SET discord_webhook_url = ? WHERE id = ?",
        (payload.discord_webhook_url, user["id"]),
    )
    await app.state.db.commit()
    return {"status": "ok"}


# =============================================================================
# STRIPE — Paiements par abonnement
# =============================================================================
@app.post("/api/payments/stripe/checkout")
async def stripe_create_checkout(user: dict = Depends(get_current_user)):
    if not stripe_sdk:
        raise HTTPException(503, "Package stripe non installé sur ce serveur")
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        raise HTTPException(503, "Paiement Stripe non configuré sur ce serveur")
    if user["tier"] == "pro":
        raise HTTPException(400, "Tu es déjà abonné Pro !")

    stripe_sdk.api_key = STRIPE_SECRET_KEY

    # Récupérer ou créer le customer Stripe
    async with app.state.db.execute(
        "SELECT stripe_customer_id FROM users WHERE id = ?", (user["id"],)
    ) as c:
        row = await c.fetchone()
    customer_id = row[0] if row else None

    if not customer_id:
        customer = await asyncio.to_thread(
            lambda: stripe_sdk.Customer.create(
                email=user["email"],
                metadata={"user_id": str(user["id"]), "username": user["username"]},
            )
        )
        customer_id = customer.id
        await app.state.db.execute(
            "UPDATE users SET stripe_customer_id = ? WHERE id = ?",
            (customer_id, user["id"]),
        )
        await app.state.db.commit()

    session = await asyncio.to_thread(
        lambda: stripe_sdk.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=STRIPE_SUCCESS_URL,
            cancel_url=STRIPE_CANCEL_URL,
            metadata={"user_id": str(user["id"])},
            allow_promotion_codes=True,
        )
    )
    logging.info(f"💳 Stripe checkout créé pour user {user['id']}")
    return {"url": session.url}


@app.post("/api/payments/stripe/webhook")
async def stripe_webhook(request: Request):
    if not stripe_sdk or not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe non configuré")

    stripe_sdk.api_key = STRIPE_SECRET_KEY
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")

    try:
        event = await asyncio.to_thread(
            lambda: stripe_sdk.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        )
    except Exception as e:
        logging.error(f"Stripe webhook signature invalide: {e}")
        raise HTTPException(400, "Signature Stripe invalide")

    etype = event["type"]
    logging.info(f"🔔 Stripe event: {etype}")

    if etype == "checkout.session.completed":
        session = event["data"]["object"]
        uid = int(session.get("metadata", {}).get("user_id", 0) or 0)
        sub_id = session.get("subscription")
        if uid:
            await app.state.db.execute(
                "UPDATE users SET tier = 'pro', stripe_subscription_id = ? WHERE id = ?",
                (sub_id, uid),
            )
            await app.state.db.commit()
            logging.info(f"✅ User {uid} → Pro (Stripe sub={sub_id})")

    elif etype in ("customer.subscription.deleted", "customer.subscription.paused"):
        sub = event["data"]["object"]
        sub_id = sub["id"]
        await app.state.db.execute(
            "UPDATE users SET tier = 'free', stripe_subscription_id = NULL "
            "WHERE stripe_subscription_id = ?",
            (sub_id,),
        )
        await app.state.db.commit()
        logging.info(f"⬇️ Stripe sub {sub_id} résiliée → free")

    elif etype == "invoice.payment_failed":
        inv = event["data"]["object"]
        logging.warning(f"⚠️ Paiement Stripe échoué pour sub {inv.get('subscription')}")

    return {"status": "ok"}


@app.get("/api/payments/stripe/portal")
async def stripe_portal(user: dict = Depends(get_current_user)):
    if not stripe_sdk or not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe non configuré")

    stripe_sdk.api_key = STRIPE_SECRET_KEY

    async with app.state.db.execute(
        "SELECT stripe_customer_id FROM users WHERE id = ?", (user["id"],)
    ) as c:
        row = await c.fetchone()
    customer_id = row[0] if row else None
    if not customer_id:
        raise HTTPException(400, "Aucun abonnement Stripe trouvé")

    portal = await asyncio.to_thread(
        lambda: stripe_sdk.billing_portal.Session.create(
            customer=customer_id,
            return_url=STRIPE_SUCCESS_URL,
        )
    )
    return {"url": portal.url}


# =============================================================================
# PAYPAL — Paiements alternatifs
# =============================================================================
async def _paypal_get_token() -> str:
    async with aiohttp.ClientSession() as s:
        async with s.post(
            f"{PAYPAL_API_BASE}/v1/oauth2/token",
            data="grant_type=client_credentials",
            auth=aiohttp.BasicAuth(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            data = await resp.json()
            return data.get("access_token", "")


@app.post("/api/payments/paypal/verify")
async def paypal_verify_subscription(
    payload: PayPalVerifyIn, user: dict = Depends(get_current_user)
):
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
        raise HTTPException(503, "PayPal non configuré sur ce serveur")

    token = await _paypal_get_token()
    if not token:
        raise HTTPException(502, "Impossible d'obtenir un token PayPal")

    async with aiohttp.ClientSession() as s:
        async with s.get(
            f"{PAYPAL_API_BASE}/v1/billing/subscriptions/{payload.subscription_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            sub = await resp.json()

    pp_status = sub.get("status", "")
    pp_plan = sub.get("plan_id", "")

    if pp_status == "ACTIVE" and (not PAYPAL_PLAN_ID or pp_plan == PAYPAL_PLAN_ID):
        await app.state.db.execute(
            "UPDATE users SET tier = 'pro', paypal_subscription_id = ? WHERE id = ?",
            (payload.subscription_id, user["id"]),
        )
        await app.state.db.commit()
        logging.info(f"✅ User {user['id']} → Pro (PayPal sub={payload.subscription_id})")
        return {"status": "ok", "tier": "pro"}

    raise HTTPException(
        400,
        f"Abonnement PayPal invalide (status: {pp_status!r}, plan: {pp_plan!r})",
    )


@app.post("/api/payments/paypal/webhook")
async def paypal_webhook(request: Request):
    body = await request.body()

    # ── Vérification de signature PayPal (si PAYPAL_WEBHOOK_ID configuré) ──
    if PAYPAL_WEBHOOK_ID and PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET:
        try:
            token = await _paypal_get_token()
            verify_payload = {
                "auth_algo": request.headers.get("paypal-auth-algo", ""),
                "cert_url": request.headers.get("paypal-cert-url", ""),
                "transmission_id": request.headers.get("paypal-transmission-id", ""),
                "transmission_sig": request.headers.get("paypal-transmission-sig", ""),
                "transmission_time": request.headers.get("paypal-transmission-time", ""),
                "webhook_id": PAYPAL_WEBHOOK_ID,
                "webhook_event": json.loads(body),
            }
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature",
                    json=verify_payload,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    verify_data = await resp.json()
            if verify_data.get("verification_status") != "SUCCESS":
                logging.warning("⚠️ PayPal webhook : signature invalide, requête rejetée")
                raise HTTPException(400, "Signature webhook PayPal invalide")
        except HTTPException:
            raise
        except Exception as e:
            logging.error(f"Erreur vérification webhook PayPal : {e}")
            # Mode dégradé : on laisse passer si la vérif échoue côté réseau

    data = json.loads(body)
    etype = data.get("event_type", "")
    logging.info(f"🔔 PayPal event: {etype}")

    if etype in ("BILLING.SUBSCRIPTION.CANCELLED", "BILLING.SUBSCRIPTION.SUSPENDED"):
        sub_id = data.get("resource", {}).get("id")
        if sub_id:
            await app.state.db.execute(
                "UPDATE users SET tier = 'free', paypal_subscription_id = NULL "
                "WHERE paypal_subscription_id = ?",
                (sub_id,),
            )
            await app.state.db.commit()
            logging.info(f"⬇️ PayPal sub {sub_id} annulée → free")

    return {"status": "ok"}


# =============================================================================
# ADMIN — GESTION DES UTILISATEURS
# =============================================================================
@app.get("/api/admin/users")
async def admin_list_users(admin: dict = Depends(require_admin)):
    async with app.state.db.execute(
        "SELECT id, email, username, tier, created_at, trial_ends_at "
        "FROM users ORDER BY created_at DESC"
    ) as c:
        rows = await c.fetchall()
    return [
        {
            "id": r[0],
            "email": r[1],
            "username": r[2],
            "tier": r[3],
            "created_at": r[4],
            "trial_ends_at": r[5],
        }
        for r in rows
    ]


@app.put("/api/admin/users/{target_id}/tier")
async def admin_update_user_tier(
    target_id: int, payload: TierUpdate, admin: dict = Depends(require_admin)
):
    if payload.tier not in ("free", "trial", "accompaniment", "pro", "admin"):
        raise HTTPException(400, f"Tier invalide: {payload.tier!r}")
    async with app.state.db.execute(
        "SELECT id FROM users WHERE id = ?", (target_id,)
    ) as c:
        if not await c.fetchone():
            raise HTTPException(404, "Utilisateur introuvable")
    await app.state.db.execute(
        "UPDATE users SET tier = ? WHERE id = ?", (payload.tier, target_id)
    )
    await app.state.db.commit()
    logging.info(
        f"🔧 Admin {admin['username']} → user {target_id} tier={payload.tier}"
    )
    return {"status": "ok"}


# =============================================================================
# WEBSOCKET
# =============================================================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.cookies.get(COOKIE_NAME)
    user_id = decode_token(token)
    if user_id is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await app.state.manager.connect(websocket, user_id)
    try:
        while True:
            await websocket.receive_text()  # pings client
    except WebSocketDisconnect:
        app.state.manager.disconnect(websocket, user_id)
    except Exception:
        app.state.manager.disconnect(websocket, user_id)


# =============================================================================
# STATIC
# =============================================================================
@app.get("/")
async def index():
    return FileResponse("index.html")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Le navigateur demande /favicon.ico à la racine — on le sert directement."""
    path = "favicon.ico"
    if os.path.isfile(path):
        return FileResponse(
            path,
            media_type="image/x-icon",
            headers={"Cache-Control": "public, max-age=86400"},
        )
    if os.path.isfile("logo.png"):
        return FileResponse("logo.png", media_type="image/png")
    raise HTTPException(404, "Favicon introuvable")


# Endpoint dédié pour le logo (mêmes raisons que favicon : éviter cache buggé)
@app.get("/logo", include_in_schema=False)
async def logo_redirect():
    """Logo sur la racine pour fiabilité (sert depuis /static/logo.png)."""
    if os.path.isfile("logo.png"):
        return FileResponse(
            "logo.png",
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )
    raise HTTPException(404, "Logo introuvable")


app.mount("/", StaticFiles(directory=".", html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
