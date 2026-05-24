# 🛒 Vinted Sniper Web — V2

Application web de surveillance Vinted en temps réel, avec **comptes utilisateurs**, **filtres personnalisés**, et **catégories supplémentaires** (Conseils / Niche / Ebooks à venir).

---

## ✨ Nouveautés V2

- 🔐 **Comptes utilisateurs** (inscription / connexion sécurisées)
- 👥 **Multi-utilisateur** : chaque user a ses propres filtres et son propre feed
- 📑 **Page "All"** + une **page par filtre** (navigation latérale)
- 🎯 **Catégories** Conseils / Niche / Ebooks (grisées, "À venir prochainement")
- 🎟️ **Codes d'invitation** pour ton accompagnement (accès gratuit / pro)
- 🛡️ **Sécurité renforcée** : bcrypt, JWT en cookie HttpOnly, SameSite, validation stricte

---

## 🚀 Installation

```bash
cd vinted-web

# Environnement virtuel (recommandé)
python -m venv venv
source venv/bin/activate          # Linux/Mac
venv\Scripts\activate             # Windows

# Dépendances
pip install -r requirements.txt

# Config (TRÈS IMPORTANT)
cp .env.example .env
# Édite .env et change SECRET_KEY + INITIAL_ADMIN_EMAIL

# Lancer
python main.py
```

Puis ouvre **http://localhost:8000**.

> 💡 **Génère une SECRET_KEY robuste** :
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

---


### Option API (admin connecté)
Si tu te connectes avec l'email défini dans `INITIAL_ADMIN_EMAIL`, tu deviens admin et peux utiliser :

- `POST /api/admin/invites` → `{count, tier, note}` génère N codes
- `GET /api/admin/invites` → liste tous les codes avec leur statut
- `DELETE /api/admin/invites/{code}` → supprime un code non utilisé

---

## 🔐 Sécurité

| Point | Implémentation |
|---|---|
| Hash mots de passe | **bcrypt** (cost 12) |
| Tokens session | **JWT signés** (HMAC-SHA256) |
| Stockage token | **Cookie HttpOnly + SameSite=Lax** (immune au XSS et CSRF de base) |
| Cookie HTTPS | `SECURE_COOKIE=true` en prod |
| Validation entrées | **Pydantic v2** + regex pseudo + min 8 chars mdp |
| Isolation users | Toutes les requêtes filtres/items vérifient `user_id` |
| WebSocket auth | Token JWT lu depuis le cookie à la connexion WS |

### À ajouter pour aller plus loin
- **Rate limiting** sur `/api/auth/login` (lib `slowapi`)
- **CAPTCHA** (Cloudflare Turnstile, gratuit) au signup
- **2FA** (TOTP via `pyotp`)
- **Email de vérification** au signup (SMTP ou Resend)
- **Reset mot de passe** par email
- **Logs d'audit** (connexions, modifications)

---

## 🌐 Hébergement — Mes recommandations

Tu héberges **un seul service Python** (le `main.py`) qui sert l'API + le frontend statique. SQLite suffit jusqu'à quelques centaines d'utilisateurs.

### 🏆 Mon top 3 selon ton besoin

| Plateforme | Prix | Avantages | Inconvénients |
|---|---|---|---|
| **Railway** | ~5 $/mois | Déploiement Git en 2 clics, super simple, logs propres, domaine HTTPS auto | Petit coût, 500h/mois en gratuit |
| **Fly.io** | Gratuit (jusqu'à 3 petites VMs) | Free tier généreux, HTTPS auto, perf correcte | Plus technique, CLI à maîtriser |
| **Hetzner Cloud** | ~4 €/mois | Le meilleur rapport perf/prix, VM stable 24/7, contrôle total | Setup VPS (Caddy/nginx + systemd) |

### Détail des options

**🥇 Railway (le plus simple)**
- Tu pushes ton code sur GitHub
- Tu connectes le repo à Railway
- Tu colles tes variables (`SECRET_KEY`, etc.)
- C'est en ligne avec un domaine HTTPS gratuit
- ⚠️ Pense à activer un volume persistant pour la DB SQLite, sinon elle se reset à chaque deploy

**🥈 Fly.io**
- `fly launch` détecte automatiquement le projet Python
- Free tier : 3 VMs partagées de 256 Mo (largement assez)
- HTTPS automatique
- Volume persistant pour la DB

**🥉 Hetzner / OVH / DigitalOcean (VPS classique)**
- Tu prends un serveur à 4-6 €/mois
- Tu installes Python, **Caddy** (reverse proxy avec HTTPS automatique gratuit via Let's Encrypt)
- Tu configures `systemd` pour relancer auto
- Le plus stable et le moins cher long terme

**🆓 Oracle Cloud Free Tier (toujours gratuit)**
- 1 VM ARM gratuite à vie (4 vCPU, 24 Go RAM 🤯)
- Setup technique mais c'est cadeau
- Bon plan si tu acceptes 1h de config

### Ce qu'il faut héberger
1. **Le code Python** (FastAPI) — c'est le seul process à faire tourner
2. **La base SQLite** (un fichier `vinted_sniper.db`) — sur un volume persistant
3. **Un nom de domaine** (~10 €/an chez Cloudflare ou Namecheap) — optionnel mais conseillé
4. **HTTPS** (gratuit via Let's Encrypt, automatique avec Caddy/Railway/Fly)

### Avant de mettre en production, check-list :
- [ ] `SECRET_KEY` aléatoire et robuste (64 caractères)
- [ ] `SECURE_COOKIE=true` (cookies envoyés en HTTPS uniquement)
- [ ] `INITIAL_ADMIN_EMAIL` configuré
- [ ] HTTPS activé (Let's Encrypt ou via le PaaS)
- [ ] Backup auto de `vinted_sniper.db` (cron qui copie le fichier ailleurs chaque nuit)
- [ ] `ALLOW_REGISTRATION=false` si tu veux garder ton service privé
- [ ] Si scaling : migration vers PostgreSQL recommandée (>200 users actifs)

---

## 💰 Rendre ça payant (futur)

### Système recommandé : **Stripe** + tier "pro"

**Étapes :**
1. **Créer un compte Stripe** (gratuit, validation en 1-2 jours)
2. Créer un **produit récurrent** (ex: 19,90 €/mois) → Stripe te donne un "Payment Link"
3. Côté UI, ajouter un bouton "Passer Pro" qui redirige vers ce lien
4. **Webhook Stripe** : quand un paiement réussit, ton backend reçoit un événement → tu mets l'utilisateur en `tier = 'pro'`
5. Quand l'abonnement est annulé, retour en `tier = 'free'`

**Implémentation rapide (à venir) :**
```python
# Endpoint à ajouter
@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request):
    event = stripe.Webhook.construct_event(...)
    if event["type"] == "checkout.session.completed":
        user_email = event["data"]["object"]["customer_email"]
        # UPDATE users SET tier='pro' WHERE email = user_email
```

### Stratégie de monétisation
- 🎁 **Free** : 1 filtre max, scan toutes les 5 min → onboarding doux
- 💎 **Pro** (19,90 €/mois) : filtres illimités, scan toutes les 30 s, support prioritaire
- 🎓 **Accompaniment** : équivalent Pro, gratuit via code d'invitation
- ⚡ **Lifetime** (offre de lancement, 99 €) : abonnement à vie pour les early adopters

### Alternatives à Stripe
- **Lemon Squeezy** (Merchant of Record, gère la TVA EU pour toi)
- **Paddle** (idem)
- **Stripe** reste le plus connu, le plus complet, mais tu gères ta propre TVA (auto-entrepreneur OK jusqu'à un certain seuil)

---

## 🔮 Idées pour la suite

### Court terme (impact rapide)
- 📧 **Notifications email** des bonnes affaires (filtres prioritaires)
- 🔔 **Push notifications navigateur** (Web Push API, gratuit)
- ⭐ **Favoris** : marquer des annonces pour les retrouver
- 🚫 **Filtres exclusifs** (mots-clés à exclure : "réservé", "lot", etc.)
- 💵 **Prix max par filtre** : alerte uniquement si en dessous d'un seuil
- 🔇 **Mute d'un filtre** sans le supprimer
- 📊 **Stats** : nombre d'annonces par filtre/jour, prix moyen, top marques

### Moyen terme (différenciation)
- 🤖 **Estimation de profit IA** : compare l'annonce aux ventes récentes similaires → score "rentabilité"
- 📱 **App mobile** (PWA installable, ça suffit en première version)
- 🌐 **Extension Chrome** : ajout de filtre direct depuis Vinted en 1 clic
- 🔄 **Multi-marketplace** : Leboncoin, Depop, eBay → même interface
- 📈 **Historique de prix** : courbe d'un produit dans le temps
- 🎯 **Templates de filtres** : tu partages tes setups gagnants à tes membres

### Long terme (gros chantiers)
- 👥 **Comptes équipes** : un patron + ses sourceurs partagent les mêmes filtres
- 🤝 **Communauté** : feed des bonnes affaires partagées par les membres pro
- 🎓 **Onboarding interactif** : tutoriel à l'inscription
- 📚 **Vraie section Conseils / Niche / Ebooks** : ton contenu d'accompagnement intégré
- 🏆 **Leaderboard** : top sourceurs du mois (gamification)

### Côté technique
- ☁️ **Migration PostgreSQL** quand tu dépasses ~200 users actifs
- 🚀 **Optimisation scraping** : déduplication des URLs (1 requête sert N users avec le même filtre)
- 🛡️ **Proxies rotatifs** pour éviter le ban Vinted (Bright Data, Oxylabs)
- 📊 **Monitoring** : Sentry (gratuit jusqu'à 5k erreurs/mois) + Uptime Robot

---

## 📋 Récapitulatif

### Ce qui est livré dans cette V2
✅ Authentification complète (inscription, connexion, déconnexion)
✅ Multi-utilisateur avec isolation totale
✅ Page "Toutes les annonces" + une page par filtre
✅ Catégories Conseils / Niche / Ebooks grisées avec "À venir"
✅ Système de codes d'invitation pour ton accompagnement
✅ Tiers : `free`, `accompaniment`, `pro`, `admin`
✅ Sécurité : bcrypt, JWT en cookie HttpOnly, validation stricte
✅ CLI admin (`admin.py`) pour gérer codes/users
✅ Documentation complète

### Ce qu'il te reste à faire
1. **Configurer ton `.env`** (SECRET_KEY + INITIAL_ADMIN_EMAIL)
2. **Tester en local** (`python main.py`)
3. **Choisir un hébergeur** (Railway pour la simplicité, VPS pour le prix)
4. **Acheter un domaine** (~10 €/an, optionnel)
5. **Configurer HTTPS** (auto sur Railway/Fly, sinon Caddy)
6. **Backup régulier** de `vinted_sniper.db`

### Ce qu'on peut faire ensemble plus tard
- Implémenter Stripe (passer payant)
- Ajouter le contenu réel pour Conseils / Niche / Ebooks
- Notifications email / push
- Filtres avancés (prix max, mots exclus, etc.)
- Migration vers PostgreSQL si besoin de scaler
- App mobile PWA / extension Chrome

---

## 📁 Structure du projet

```
vinted-web/
├── main.py              # Backend FastAPI + scraper + auth
├── admin.py             # CLI : codes d'invitation, users
├── requirements.txt
├── .env.example         # Template config (renommer en .env)
├── README.md            # Ce fichier
└── static/
    └── index.html       # Frontend SPA (login + app)
```

## 🔌 Endpoints API

### Auth
- `POST /api/auth/register` `{email, username, password, invite_code?}`
- `POST /api/auth/login` `{identifier, password}`
- `POST /api/auth/logout`
- `GET /api/auth/me`

### Filtres (auth requise)
- `GET /api/filters`
- `POST /api/filters` `{name, url}`
- `DELETE /api/filters/{id}`
- `DELETE /api/filters`

### Items (auth requise)
- `GET /api/items?limit=100&filter_id=X`
- `DELETE /api/items`

### Admin (admin requis)
- `GET /api/admin/invites`
- `POST /api/admin/invites` `{count, tier, note?}`
- `DELETE /api/admin/invites/{code}`

### Realtime
- `WS /ws` (cookie auth)

⚠️ **Aspects légaux** : Vinted n'expose pas d'API publique. Le scraping peut violer leurs CGU. Vérifie tes obligations légales et les CGU avant de monétiser.
