# 🛡️ CyberShield & Intelligence Hub

An asynchronous Telegram bot for defensive security assistance and public-data discovery, built with **Python 3.11+**, **aiogram 3**, **aiohttp**, and **aiomysql**.

---

## ✨ Key Features

- 🛡️ **Defend & Patch Config:** Generates hardened Nginx configuration guidance with OpenRouter AI.
- 🕵️ **Asset & Archive Discovery:** Combines certificate transparency data from `crt.sh` with archived URLs from the Wayback Machine.
- 🚨 **Crypto & Leak Radar:** Provides AI-assisted scam-risk analysis for public addresses, emails, or suspicious messages.
- 🤖 **Attack Path Simulator:** Produces high-level threat models and countermeasures for authorized environments.
- 📊 **MySQL Audit Logging & CSV Export:** Stores query history and allows users to export their activity as a `.csv` file.
- 👑 **Admin Dashboard (`/admin`):** Restricted command for system telemetry (user counts, total scans, top features).

---

## 🧰 Tech Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Aiogram 3](https://img.shields.io/badge/Aiogram_3-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![AsyncIO](https://img.shields.io/badge/AsyncIO-000000?style=for-the-badge&logo=python&logoColor=white)
![Aiohttp](https://img.shields.io/badge/aiohttp-2C5BB4?style=for-the-badge&logo=python&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenRouter-412991?style=for-the-badge&logo=openai&logoColor=white)

---

## 🚀 Quick Start & Installation

### 1. Clone Repository
```bash
git clone https://github.com/s1aeka/cybersecurity-telegram-bot.git
cd cybersecurity-telegram-bot
```

### 2. Install Dependencies
```powershell
pip install aiogram aiomysql aiohttp openai
```

### 3. Environment Variables & Setup
Set these environment variables before launching (PowerShell example):
```powershell
$env:BOT_TOKEN = "your_telegram_bot_token"
$env:MYSQL_PASSWORD = "your_mysql_password"
$env:OPENROUTER_API_KEY = "your_openrouter_api_key"
$env:ADMIN_ID = "your_telegram_id"
python main.py
```

The MySQL account must be able to create the configured database and tables.
Search queries and generated results are saved in MySQL history. AI requests are
sent to OpenRouter; never submit passwords, private keys, or seed phrases.