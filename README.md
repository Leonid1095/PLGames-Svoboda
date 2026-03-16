<div align="center">

# 🛡️ PLGames Svoboda

### AI-Powered Internet Freedom Tool

**Your internet — your rules. Powered by genetic algorithm + artificial intelligence.**

[🇷🇺 Русский](#-русский) • [🇬🇧 English](#-english) • [⬇️ Download](#-quick-start) • [💰 Support](#-support-the-project)

---

<img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows" alt="Windows">
<img src="https://img.shields.io/badge/Engine-zapret2-green?style=for-the-badge" alt="zapret2">
<img src="https://img.shields.io/badge/AI-Powered-purple?style=for-the-badge&logo=openai" alt="AI">
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT">

</div>

---

## 🇷🇺 Русский

### Что это?

PLGames Svoboda — инструмент который **автоматически** находит способ обойти блокировки интернета. Не нужно ничего настраивать — запустил и работает.

### Чем отличается от аналогов?

| | Svoboda | GoodbyeDPI | Zapret GUI | ByeDPI |
|---|:---:|:---:|:---:|:---:|
| AI анализ блокировок | ✅ | ❌ | ❌ | ❌ |
| Автоподбор стратегии | ✅ | ❌ | ❌ | ❌ |
| Коллективный интеллект | ✅ | ❌ | ❌ | ❌ |
| Определение типа DPI | ✅ | ❌ | ❌ | ❌ |
| Автообновление | ✅ | ❌ | ❌ | ❌ |
| 80 000+ доменов | ✅ | ❌ | ❌ | ❌ |

### Как работает?

```
Запустил → AI определил провайдера и тип блокировки →
Получил рабочую стратегию от сообщества → Применил за 5 секунд →
Мониторит 24/7 → Если блокировка изменилась — адаптируется автоматически
```

**Под капотом:**
- 🧬 **Генетический алгоритм** — эволюционирует стратегии обхода как Geneva
- 🤖 **AI анализатор** — определяет тип DPI и подбирает метод (не угадывает, а анализирует пакеты)
- 👥 **Коллективный интеллект** — стратегии от тысяч пользователей на вашем провайдере
- 🔄 **Автоадаптация** — ТСПУ обновился? Svoboda найдёт новый обход автоматически
- 📋 **81 000+ доменов** — список блокировок обновляется при каждом запуске

### Что разблокирует?

YouTube • Discord • Twitter/X • Twitch • Instagram • Facebook • LinkedIn • и всё остальное из реестра

### ⬇️ Быстрый старт

```
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
run.bat
```

**Требования:** Windows 10+, Python 3.10+, права администратора

### 🔒 Приватность

- Никаких личных данных — ни IP, ни MAC, ни имени компьютера
- Анонимная телеметрия — только тип провайдера и результат стратегии
- Всё шифрование на стороне сервера — в коде нет ключей API
- Телеметрия помогает AI учиться и улучшать обход для всех пользователей
- Можно отключить в config.json (`"telemetry_consent": false`)

---

## 🇬🇧 English

### What is this?

PLGames Svoboda is a tool that **automatically** finds ways to bypass internet censorship. No configuration needed — just run and it works.

### How is it different?

Most tools give you a static set of bypass rules. Svoboda uses **AI + genetic algorithm** to find what works for YOUR specific ISP and adapt when censorship changes.

- 🧬 **Genetic Algorithm** — evolves bypass strategies like [Geneva](https://geneva.cs.umd.edu/)
- 🤖 **AI Analyzer** — profiles your DPI middlebox (hop distance, type, behavior)
- 👥 **Collective Intelligence** — strategies from community, voted by real users
- 🔄 **Auto-adaptation** — DPI firmware updated? Svoboda re-evolves automatically
- 📋 **81,000+ domains** — blocklist updated every launch

### Quick Start

```
git clone https://github.com/Leonid1095/PLGames-Svoboda.git
cd PLGames-Svoboda
run.bat
```

**Requirements:** Windows 10+, Python 3.10+, Administrator rights

### How It Works

```
Launch → AI detects ISP + DPI type → Community strategy (5 sec) →
Fast enumeration (40 sec) → Genetic evolution (if needed) →
Apply + Monitor 24/7 → Re-evolve on degradation
```

### Privacy

- Zero personal data collected (no IP, MAC, hostname)
- Anonymous telemetry: ISP type + strategy results only
- Telemetry trains the AI to improve bypass for everyone
- Opt-out: set `"telemetry_consent": false` in config.json

---

## 🗺️ Roadmap

### ✅ Done
- AI block classifier (RST, SNI, HTTP/2-kill, throttling, IP block)
- TSPU profiler (DPI distance, type, recommended TTL)
- Genetic algorithm with AI feedback (auto-excludes dead strategies)
- Community intelligence (instant strategies, voting, TSPU change detection)
- Fast enumeration — 19 proven strategies in priority order
- Circular orchestrator — auto-failover between strategies
- 4-profile winws2 (TLS, YouTube CDN, HTTP, QUIC)
- System tray mode + Windows notifications
- 81K domain blocklist + auto-detection of new blocks

### 🔜 Next
- **ByeDPI mode** — works without admin rights (SOCKS proxy)
- **Traffic Morphing** — AI mimics real browser patterns (anti-ML censorship)
- **PLGames DNS** — encrypted DNS bypass (DoH, Germany)
- **Linux + Android** — multi-platform support
- **Telegram bot** — manage remotely

### 🔮 Future
- AI vs AI: real-time adaptation against ML-powered censorship (2026+)
- Huma-style HTTP/2 tunneling
- Community dashboard with live bypass map

---

## 💰 Support the Project

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | 0 | Full bypass + AI 1x/day |
| **Supporter** | 300 RUB | AI every 2h + priority strategies |
| **Pro** | 600 RUB | DeepSeek V3 AI + PLGames DNS |

**[→ Donate on DonatePay](https://new.donatepay.ru/@lenya)**

Your donation keeps the servers running and the AI learning.

---

## ⚠️ Internet Broken?

If winws2 crashed and your internet stopped:

```
fix_internet.bat
```

Kills winws2, unloads WinDivert, flushes DNS, resets network stack.

---

## 📄 License

MIT — use freely, contribute back.

<div align="center">

**Made with 🧬 by PLGames**

</div>
