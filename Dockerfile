FROM python:3.11-slim

# Répertoire de travail
WORKDIR /app

# Dépendances d'abord (cache Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code source
COPY . .

# Crée le dossier data pour la base SQLite (monté en volume sur Fly)
RUN mkdir -p /data

# Port exposé (Fly.io utilise 8080 par défaut)
EXPOSE 8080

# Démarrage
CMD ["python", "main.py"]
