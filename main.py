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

import aiohttp
import aiosqlite
import bcrypt
import jwt
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

JWT_ALGO = "HS256"
TOKEN_EXPIRE_HOURS = 24 * 14  # 14 jours
COOKIE_NAME = "vsw_session"
SECURE_COOKIE = os.getenv("SECURE_COOKIE", "false").lower() == "true"

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", 30))
DB_NAME = os.getenv("DB_NAME", "vinted_sniper.db")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))
INITIAL_ADMIN_EMAIL = os.getenv("INITIAL_ADMIN_EMAIL", "").lower().strip()
ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "true").lower() == "true"

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
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
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
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "fr-FR,fr;q=0.9",
            "Referer": "https://www.vinted.fr/",
        }
        self.cookies = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=15),
            )
        return self.session

    async def fetch_cookies(self):
        try:
            session = await self._get_session()
            async with session.get("https://www.vinted.fr/") as resp:
                self.cookies = resp.cookies
                logging.info("🍪 Cookies Vinted actualisés.")
        except Exception as e:
            logging.error(f"Erreur cookies : {e}")

    async def fetch_items(self, url: str) -> list:
        if self.cookies is None:
            await self.fetch_cookies()
        session = await self._get_session()

        api_url = (
            url.replace("vinted.fr/catalog", "vinted.fr/api/v2/catalog/items")
            if "api/v2" not in url else url
        )

        try:
            async with session.get(api_url, cookies=self.cookies) as resp:
                if resp.status in (401, 403):
                    await self.fetch_cookies()
                    return []
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("items", [])
                return []
        except Exception as e:
            logging.error(f"Erreur fetch : {e}")
            return []

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()


def process_item(item: dict, filter_name: str, filter_id: int) -> dict:
    item_id = item.get("id")

    # Temps écoulé
    published_at = "À l'instant"
    ts = item.get("created_at_ts") or item.get("updated_at_ts")
    if ts:
        diff = int(datetime.now().timestamp() - float(ts))
        if diff < 60:
            published_at = "À l'instant"
        elif diff < 3600:
            published_at = f"il y a {diff // 60} min"
        elif diff < 86400:
            published_at = f"il y a {diff // 3600} h"
        else:
            published_at = f"il y a {diff // 86400} j"

    user = item.get("user", {}) or {}
    rating = float(user.get("rating") or 0)
    feedback_count = user.get("feedback_count", 0)

    price_data = item.get("price", {}) or {}
    price_amount = price_data.get("amount", "0.00")
    currency = price_data.get("currency_code", "EUR")
    currency_symbol = "€" if currency == "EUR" else currency
    try:
        p = float(price_amount)
        ttc = p + 0.70 + (p * 0.05)
    except Exception:
        p, ttc = 0.0, 0.0

    photos = item.get("photos", []) or []
    main_photo = (
        photos[0]["url"] if photos else (item.get("photo", {}) or {}).get("url")
    )
    all_photos = [photo["url"] for photo in photos if photo.get("url")]

    return {
        "id": item_id,
        "title": item.get("title"),
        "url": f"https://www.vinted.fr/items/{item_id}",
        "negotiate_url": f"https://www.vinted.fr/messages/new?item_id={item_id}",
        "price": round(p, 2),
        "price_ttc": round(ttc, 2),
        "currency": currency_symbol,
        "brand": item.get("brand_title") or "—",
        "size": item.get("size_title") or "—",
        "status": item.get("status_title") or "—",
        "main_photo": main_photo,
        "photos": all_photos,
        "published_at": published_at,
        "seller": {
            "login": user.get("login", "Inconnu"),
            "rating": round(rating, 2),
            "feedback_count": feedback_count,
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
async def scan_loop(app: FastAPI):
    while True:
        try:
            async with app.state.db.execute(
                "SELECT id, user_id, url, name FROM filters"
            ) as cursor:
                filters = await cursor.fetchall()

            for filter_id, user_id, url, name in filters:
                items = await app.state.scraper.fetch_items(url)
                if not items:
                    continue

                for item in items[:15]:
                    item_id = item.get("id")
                    if not item_id:
                        continue

                    async with app.state.db.execute(
                        "SELECT 1 FROM seen_items WHERE item_id = ? AND filter_id = ?",
                        (item_id, filter_id),
                    ) as c:
                        if await c.fetchone():
                            continue

                    await app.state.db.execute(
                        "INSERT INTO seen_items (item_id, filter_id, timestamp) "
                        "VALUES (?, ?, ?)",
                        (item_id, filter_id, datetime.now()),
                    )

                    processed = process_item(item, name, filter_id)

                    await app.state.db.execute(
                        "INSERT INTO items_cache (item_id, user_id, filter_id, data) "
                        "VALUES (?, ?, ?, ?)",
                        (item_id, user_id, filter_id, json.dumps(processed)),
                    )
                    await app.state.db.commit()

                    await app.state.manager.send_to_user(
                        user_id, {"type": "new_item", "item": processed}
                    )
                    await asyncio.sleep(0.3)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.error(f"Erreur scan : {e}")

        await asyncio.sleep(CHECK_INTERVAL)


# =============================================================================
# LIFECYCLE
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    db = await aiosqlite.connect(DB_NAME)
    await db.execute("PRAGMA foreign_keys = ON")

    await db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'free',
            invite_code_used TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

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

        CREATE INDEX IF NOT EXISTS idx_filters_user ON filters(user_id);
        CREATE INDEX IF NOT EXISTS idx_items_user ON items_cache(user_id, detected_at DESC);
        CREATE INDEX IF NOT EXISTS idx_items_filter ON items_cache(filter_id);
    """)
    await db.commit()

    app.state.db = db
    app.state.scraper = VintedScraper()
    await app.state.scraper.fetch_cookies()
    app.state.manager = ConnectionManager()
    app.state.scan_task = asyncio.create_task(scan_loop(app))

    logging.info(f"✅ Vinted Sniper Web prêt sur http://{HOST}:{PORT}")
    yield

    app.state.scan_task.cancel()
    try:
        await app.state.scan_task
    except asyncio.CancelledError:
        pass
    await app.state.scraper.close()
    await db.close()


app = FastAPI(title="Vinted Sniper Web", lifespan=lifespan)


# =============================================================================
# DEPENDENCIES (auth)
# =============================================================================
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    user_id = decode_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Non authentifié")

    async with app.state.db.execute(
        "SELECT id, email, username, tier, created_at FROM users WHERE id = ?",
        (user_id,),
    ) as c:
        row = await c.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    return {
        "id": row[0],
        "email": row[1],
        "username": row[2],
        "tier": row[3],
        "created_at": row[4],
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


# =============================================================================
# ROUTES AUTH
# =============================================================================
@app.post("/api/auth/register")
async def register(payload: RegisterIn, response: Response):
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

    # Tier par défaut + invite code
    tier = "free"
    invite_used = None
    if payload.invite_code:
        code = payload.invite_code.strip().upper()
        async with db.execute(
            "SELECT code, tier, used_by FROM invite_codes WHERE code = ?", (code,)
        ) as c:
            row = await c.fetchone()
        if not row:
            raise HTTPException(400, "Code d'invitation invalide")
        if row[2] is not None:
            raise HTTPException(400, "Code d'invitation déjà utilisé")
        tier = row[1]
        invite_used = code

    # Admin auto par email (utile pour le 1er compte)
    if INITIAL_ADMIN_EMAIL and payload.email == INITIAL_ADMIN_EMAIL:
        tier = "admin"

    cursor = await db.execute(
        "INSERT INTO users (email, username, password_hash, tier, invite_code_used) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            payload.email,
            payload.username,
            hash_password(payload.password),
            tier,
            invite_used,
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
    }


@app.post("/api/auth/login")
async def login(payload: LoginIn, response: Response):
    db = app.state.db
    ident = payload.identifier.strip().lower()

    async with db.execute(
        "SELECT id, email, username, password_hash, tier FROM users "
        "WHERE email = ? OR LOWER(username) = ?",
        (ident, ident),
    ) as c:
        row = await c.fetchone()

    if not row or not verify_password(payload.password, row[3]):
        raise HTTPException(401, "Identifiants invalides")

    set_auth_cookie(response, row[0])
    return {
        "id": row[0],
        "email": row[1],
        "username": row[2],
        "tier": row[4],
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
async def list_invites(_: dict = Depends(require_admin)):
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
        }
        for r in rows
    ]


@app.post("/api/admin/invites")
async def create_invites(
    payload: InviteCreate, _: dict = Depends(require_admin)
):
    if payload.count < 1 or payload.count > 100:
        raise HTTPException(400, "Quantité entre 1 et 100")
    if payload.tier not in ("free", "accompaniment", "pro"):
        raise HTTPException(400, "Tier invalide")

    codes = []
    for _ in range(payload.count):
        code = _gen_code()
        await app.state.db.execute(
            "INSERT INTO invite_codes (code, tier, note) VALUES (?, ?, ?)",
            (code, payload.tier, payload.note),
        )
        codes.append(code)
    await app.state.db.commit()
    return {"codes": codes}


@app.delete("/api/admin/invites/{code}")
async def delete_invite(code: str, _: dict = Depends(require_admin)):
    await app.state.db.execute(
        "DELETE FROM invite_codes WHERE code = ? AND used_by IS NULL", (code,)
    )
    await app.state.db.commit()
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


app.mount("/", StaticFiles(directory=".", html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
