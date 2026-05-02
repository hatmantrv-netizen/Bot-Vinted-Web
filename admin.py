"""
Petit utilitaire CLI pour créer des codes d'invitation sans passer par l'API.
À utiliser avant que tu aies un compte admin, ou en backup.

Exemples :
    python admin.py invite                              # 1 code accompaniment
    python admin.py invite 10 accompaniment "Promo Avril"
    python admin.py invite 5 pro
    python admin.py list-invites
    python admin.py list-users
    python admin.py promote alice@email.com admin       # bascule un user en admin
    python admin.py reset-code Q1BAE735M2                # libère un code (utile si bug)
"""

import asyncio
import os
import secrets
import string
import sys
from datetime import datetime

import aiosqlite

DB_NAME = os.getenv("DB_NAME", "vinted_sniper.db")


def gen_code(length=10) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def ensure_schema(db):
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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    await db.commit()


async def cmd_invite(count: int, tier: str, note: str):
    async with aiosqlite.connect(DB_NAME) as db:
        await ensure_schema(db)
        codes = []
        for _ in range(count):
            code = gen_code()
            await db.execute(
                "INSERT INTO invite_codes (code, tier, note) VALUES (?, ?, ?)",
                (code, tier, note),
            )
            codes.append(code)
        await db.commit()
    print(f"\n✅ {count} code(s) [{tier}] créé(s)" + (f" — note: {note}" if note else ""))
    print("─" * 40)
    for c in codes:
        print(f"  {c}")
    print("─" * 40)
    print("Partage-les à tes membres : ils les saisiront au moment de l'inscription.\n")


async def cmd_list_invites():
    async with aiosqlite.connect(DB_NAME) as db:
        await ensure_schema(db)
        async with db.execute(
            "SELECT code, tier, note, used_by, used_at, created_at "
            "FROM invite_codes ORDER BY created_at DESC"
        ) as c:
            rows = await c.fetchall()
    if not rows:
        print("Aucun code d'invitation pour le moment.")
        return
    print(f"\n{len(rows)} code(s) au total :\n")
    print(f"{'CODE':<14}{'TIER':<16}{'STATUT':<14}{'NOTE'}")
    print("─" * 70)
    for code, tier, note, used_by, used_at, _ in rows:
        statut = f"utilisé (#{used_by})" if used_by else "libre"
        print(f"{code:<14}{tier:<16}{statut:<14}{note or ''}")
    print()


async def cmd_list_users():
    async with aiosqlite.connect(DB_NAME) as db:
        await ensure_schema(db)
        async with db.execute(
            "SELECT id, email, username, tier, created_at FROM users ORDER BY id"
        ) as c:
            rows = await c.fetchall()
    if not rows:
        print("Aucun utilisateur encore inscrit.")
        return
    print(f"\n{len(rows)} utilisateur(s) :\n")
    print(f"{'ID':<5}{'PSEUDO':<20}{'EMAIL':<30}{'TIER'}")
    print("─" * 70)
    for uid, email, username, tier, _ in rows:
        print(f"{uid:<5}{username:<20}{email:<30}{tier}")
    print()


async def cmd_promote(email_or_user: str, tier: str):
    if tier not in ("free", "accompaniment", "pro", "admin"):
        print(f"❌ Tier invalide. Choisis parmi : free, accompaniment, pro, admin")
        return
    async with aiosqlite.connect(DB_NAME) as db:
        await ensure_schema(db)
        cursor = await db.execute(
            "UPDATE users SET tier = ? WHERE email = ? OR username = ?",
            (tier, email_or_user.lower(), email_or_user),
        )
        await db.commit()
    if cursor.rowcount == 0:
        print(f"❌ Aucun utilisateur trouvé avec '{email_or_user}'")
    else:
        print(f"✅ {email_or_user} → tier '{tier}'")


async def cmd_reset_code(code: str):
    """Libère un code mal-marqué comme utilisé. Vérifie qu'aucun user ne l'utilise réellement."""
    code = code.strip().upper()
    async with aiosqlite.connect(DB_NAME) as db:
        await ensure_schema(db)
        # Vérifier que personne n'utilise vraiment ce code
        async with db.execute(
            "SELECT id FROM users WHERE invite_code_used = ?", (code,)
        ) as c:
            user_row = await c.fetchone()
        if user_row:
            print(f"⚠️  Le code '{code}' est lié à l'utilisateur ID {user_row[0]} — annulation.")
            print("   Si tu veux quand même libérer ce code, supprime d'abord cet utilisateur.")
            return
        cursor = await db.execute(
            "UPDATE invite_codes SET used_by = NULL, used_at = NULL WHERE code = ?",
            (code,),
        )
        await db.commit()
    if cursor.rowcount == 0:
        print(f"❌ Code '{code}' introuvable.")
    else:
        print(f"✅ Code '{code}' libéré et de nouveau utilisable.")


def usage():
    print(__doc__)


async def main():
    if len(sys.argv) < 2:
        usage()
        return

    cmd = sys.argv[1]

    if cmd == "invite":
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        tier = sys.argv[3] if len(sys.argv) > 3 else "accompaniment"
        note = sys.argv[4] if len(sys.argv) > 4 else ""
        if tier not in ("free", "accompaniment", "pro"):
            print("❌ Tier invalide. Choisis parmi : free, accompaniment, pro")
            return
        await cmd_invite(count, tier, note)

    elif cmd == "list-invites":
        await cmd_list_invites()

    elif cmd == "list-users":
        await cmd_list_users()

    elif cmd == "promote":
        if len(sys.argv) < 4:
            print("Usage: python admin.py promote <email_ou_pseudo> <tier>")
            return
        await cmd_promote(sys.argv[2], sys.argv[3])

    elif cmd == "reset-code":
        if len(sys.argv) < 3:
            print("Usage: python admin.py reset-code <CODE>")
            return
        await cmd_reset_code(sys.argv[2])

    else:
        usage()


if __name__ == "__main__":
    asyncio.run(main())
