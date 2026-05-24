#!/usr/bin/env python
import re

with open('/root/repo/main.py', 'r') as f:
    content = f.read()

# Fix 1: FileResponse("static/index.html") -> FileResponse("index.html")
content = content.replace('FileResponse("static/index.html")', 'FileResponse("index.html")')

# Fix 2: path = "static/favicon.ico" -> path = "favicon.ico"
content = content.replace('path = "static/favicon.ico"', 'path = "favicon.ico"')

# Fix 3: FileResponse("static/logo.png" -> FileResponse("logo.png"
content = content.replace('FileResponse("static/logo.png"', 'FileResponse("logo.png"')

# Fix 4: Replace the mount block
old_mount = '''if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")'''
new_mount = '''app.mount("/", StaticFiles(directory=".", html=True), name="static")'''
content = content.replace(old_mount, new_mount)

with open('/root/repo/main.py', 'w') as f:
    f.write(content)

print("✅ Corrections appliquées!")

