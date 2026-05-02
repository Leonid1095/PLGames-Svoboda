# PLGames Svoboda — Roadmap

## Бизнес-модель: Freemium через DonatePay

### FREE (все пользователи)
- GA эволюция стратегий (полный функционал)
- Автоматический watchdog — переэволюция при падении
- Обмен стратегиями через сервер (анонимно)
- AI: **plgames-ai** (наша модель, бесплатно) — **10 раз в день**
- Telegram-канал обновлений

### SUPPORTER (донат от 300 руб)
- Все из FREE
- AI: **plgames-ai** — проверка **каждые 2 часа**
- AI автотестирование — AI сам запускает тесты и переключает стратегию
- Приоритетные стратегии с сервера (получает первым)
- Благодарность в приложении

### PRO (донат от 600 руб)
- Все из SUPPORTER
- AI: **DeepSeek V3** — мощная коммерческая модель
- AI анализ **каждые 30 минут**
- Персональная оптимизация под ISP + регион
- AI предсказание блокировок (анализ паттернов ТСПУ)
- VPS-прокси PLGames (SOCKS5-over-TLS) для IP-блокировок
- Ранний доступ к новым версиям

---

## Фазы разработки

### Фаза 0: Фундамент ✅
**Статус: 100% готово**

- [x] Генетический алгоритм (Geneva-inspired)
- [x] Mock fitness function для тестирования
- [x] SQLite аналитика (6 таблиц)
- [x] AI Advisor (plgames-ai интеграция)
- [x] Server sync (клиентская часть)
- [x] DonatePay интеграция
- [x] Telegram updater
- [x] Shadow mode (run_shadow.py — непрерывный)
- [x] Windows launcher (run.bat)
- [x] Review script (review_data.py)
- [x] Deploy server API на VPS
- [x] SOCKS5 прокси на VPS (microsocks :1080, user_proxy для клиентов)

### Фаза 1: Реальное тестирование [ТЕКУЩАЯ]
**Статус: 80% готово**

- [x] Развернуть API сервер на VPS (deploy_server.sh)
- [x] ProxyRouter — умная маршрутизация (zapret2 / WARP / user_proxy / byedpi)
- [x] BlockClassifier — определение типа блокировки (SNI/IP/DNS/throttle)
- [x] WARP интеграция (warp.py) — fallback для IP-блокировок
- [x] Discovery модуль — автоопределение доступных инструментов
- [x] Geneva-style стратегии (geneva.py)
- [x] ECH (Encrypted Client Hello) поддержка (ech.py)
- [x] Gost TLS-туннель (gost_tunnel.py) — SOCKS5-over-TLS на порт 443
- [x] Streamer mode (--streamer) — минимальный фильтр, без стриминг-CDN
- [x] Early start validation с fallback на top-5 стратегий
- [ ] Скачать/собрать zapret2 бинарники (winws2.exe, nfqws2)
- [ ] Тест shadow-mode с реальным zapret2 (через curl)
- [ ] Тест на российском IP (VPN или реальный пользователь)
- [ ] Отладка реальной fitness-функции
- [ ] Валидация что GA находит рабочие стратегии

### Фаза 2: Тиер-система и AI расписание ✅
**Статус: 100% готово**

- [x] Модуль лицензирования (tier.py + серверная проверка через DonatePay API)
  - Кеширование статуса донатера
  - Маппинг: имя донатера → install_id
  - Тиеры: free / supporter (300+) / pro (600+)
- [x] AI Scheduler — расписание AI проверок по тиеру
  - FREE: 10 вызовов/день
  - SUPPORTER: каждые 2 часа
  - PRO: каждые 30 минут
- [x] AI auto-test для SUPPORTER+
- [x] Выбор AI модели по тиеру (plgames-ai / DeepSeek V3)
- [x] UI уведомления о тиере в консоли
- [x] VPS-прокси (PRO/owner): proxy_url из license response

### Фаза 3: Серверная аналитика и инфраструктура (1-2 недели)
**Цель: Умный сервер + надёжная прокси-инфраструктура**

- [x] Серверная телеметрия: ISP×host×strategy матрица
- [x] API голосования за стратегии (report_host_strategy, vote_strategy)
- [x] Recommended strategies endpoint (по ISP/региону)
- [x] Telegram прокси-сервисы на VPS:
  - [x] MTProto proxy (mtg :2095)
  - [x] SOCKS5 с per-user auth (tg-proxy :41080)
  - [x] TLS-терминация через stunnel (:7445)
  - [x] nginx SNI-routing на порт 443
  - [x] PBKDF2 хеширование паролей с солью (миграция с SHA256)
  - [x] Защита от brute-force (бан-трекер с автоочисткой)
- [x] VPN-бот Telegram (webhook mode)
- [x] Безопасность: UFW, fail2ban, rate limiting, sysctl hardening
- [ ] Серверный AI анализ: агрегация данных от всех клиентов
  - Топ стратегий по ISP/региону
  - Тренды (какие стратегии перестали работать)
  - Детекция обновлений ТСПУ (массовое падение fitness)
- [ ] Smart strategy distribution
  - Новый пользователь получает проверенную стратегию для своего ISP
  - Не тратит время на первую эволюцию
- [ ] Dashboard (веб-панель для нас)
- [ ] AI обучение на реальных данных

### Фаза 4: GUI и публичный релиз (2-3 недели)
**Цель: Массовый пользователь может скачать и использовать**

- [ ] Electron / PyQt GUI
  - Статус подключения (работает/не работает)
  - Текущая стратегия + fitness
  - Кнопка "Переоптимизировать"
  - Настройки (тестовые хосты, интервалы)
  - Страница доната
  - Тиер-статус
- [ ] Автообновление приложения
- [ ] Инсталлятор для Windows (.exe)
- [ ] Документация для пользователей
- [ ] Landing page

### Фаза 5: Мультиплатформа (2-4 недели)
**Цель: Работает везде**

#### Linux (Desktop / VPS)
- [ ] .deb пакет (Ubuntu/Debian)
- [ ] .AppImage (универсальный)
- [ ] systemd сервис (headless на серверах)
- [ ] nfqws2 уже поддерживается (nfqueue)

#### Android
- [ ] Kotlin/Java приложение
- [ ] Локальный VPN-режим (TUN интерфейс) — не требует root
  - Перехват трафика через VpnService API
  - Применение десинк-стратегий на лету
- [ ] Root-режим (опционально): прямая интеграция с iptables + nfqws2
- [ ] Интеграция с AI тиерами (через Google Play или DonatePay)
- [ ] Фоновый сервис с уведомлениями

#### iOS
- [ ] Swift приложение
- [ ] NetworkExtension framework (Packet Tunnel Provider)
  - Локальный VPN для перехвата трафика
  - Реализация десинк-логики в Swift/C
- [ ] Ограничения AppStore: возможно TestFlight/AltStore
- [ ] Интеграция с серверными стратегиями

#### Роутеры
- [ ] OpenWrt пакет (.ipk)
  - nfqws2 + brain на Python/microPython
  - LuCI веб-интерфейс для управления
  - Защищает все устройства в сети автоматически
- [ ] Keenetic (OPKG / Entware)
  - Адаптация под MIPS/ARM архитектуры
  - Легковесный brain без AI (стратегии с сервера)
- [ ] Mikrotik (скриптовая интеграция)
- [ ] Raspberry Pi (полная версия, как на Linux)

#### Приоритет платформ:
```
Windows → Linux → Android → Роутеры (OpenWrt) → iOS
  [1]      [2]      [3]          [4]              [5]
```

### Фаза 6: Масштабирование (ongoing)
**Цель: Устойчивый проект с растущей базой**

- [x] DNS-over-HTTPS/TLS интеграция (ech.py — Cloudflare DoH)
- [x] Telegram бот для продажи прокси (vpn-bot)
- [ ] Cloudflare Worker relay (план готов)
- [ ] API для сторонних интеграций
- [ ] A/B тестирование стратегий на сервере
- [ ] AI предсказание блокировок (pro-фича)
- [ ] Реферальная система (пригласи друга → +7 дней supporter)
- [ ] Партнерство с VPN-сервисами
- [ ] Поддержка протоколов: QUIC, Wireguard обфускация

---

## AI Pipeline

```
Фаза 0-1 (сейчас):
  FREE/SUPPORTER: plgames-ai (своя модель, бесплатно)
    - Советник, предлагает seed-стратегии для GA
    - Анализирует провалы (fitness < 0.6)
  PRO: DeepSeek V3 ($0.14/$0.28 за 1M токенов)
    - Более глубокий анализ, лучше понимает контекст
    - Персональные рекомендации на основе истории юзера

Фаза 3:
  Серверный AI: агрегирует данные от ВСЕХ пользователей
  "Для Ростелеком МСК disorder2+ttl=5 работает у 87% клиентов"
  DeepSeek анализирует паттерны ТСПУ-обновлений

Фаза 4-5:
  Fine-tuned plgames-ai на реальной телеметрии
  Предсказывает стратегию по ISP+region без эволюции
  PRO: DeepSeek R1 (reasoning) — предсказание блокировок
```

---

## Тиер-система: техническая реализация

```
Пользователь делает донат 300+ руб на DonatePay
         │
         ▼
DonatePay API → наш сервер проверяет транзакции
         │
         ▼
Маппинг: имя/email донатера → install_id клиента
(пользователь вводит свой код в приложении)
         │
         ▼
Сервер выдает лицензию: {tier: "supporter" | "pro", until: "2026-04-15"}
         │
         ▼
Клиент получает лицензию при sync → включает расширенные фичи
```

```
AI расписание:

FREE:       [----24h----|scan]--24h--|scan]--...
SUPPORTER:  [--2h--|scan|--2h--|scan|--2h--|scan|--...
PRO:        [-30m-|scan|-30m-|scan|-30m-|scan|--...

"scan" = AI анализирует текущую стратегию + автотест
```

---

## Экономика

### AI модели
| Модель | Используется | Цена input | Цена output | Наш расход |
|--------|-------------|------------|-------------|------------|
| plgames-ai | FREE + SUPPORTER | бесплатно (свой сервер) | бесплатно | 0 |
| DeepSeek V3 | PRO | $0.14/1M | $0.28/1M | ~20 руб/мес на юзера |

### Тиеры
| Тиер | Цена | AI частота | Модель | Расход AI/мес |
|------|------|------------|--------|---------------|
| FREE | 0 | 1/день | plgames-ai | **0 руб** |
| SUPPORTER | 300 руб | 12/день | plgames-ai | **0 руб** |
| PRO | 600 руб | 48/день | DeepSeek V3 | **~20 руб** |

### Расчет на 1 вызов DeepSeek V3
```
Input:  ~600 токенов × $0.14/1M = $0.000084
Output: ~300 токенов × $0.28/1M = $0.000084
Итого:  $0.000168 = 0.014 руб за вызов
PRO (48 вызовов/день × 30 дней): ~20 руб/мес
```

### Сценарии (в месяц)
| Сценарий | Free | Supporter | Pro | Доход | DeepSeek | Сервер | **Профит** |
|----------|------|-----------|-----|-------|----------|--------|------------|
| Старт | 500 | 20 | 5 | 9,000 | 102 | 500 | **+8,398** |
| Рост | 2,000 | 100 | 20 | 42,000 | 408 | 500 | **+41,092** |
| Зрелый | 5,000 | 300 | 50 | 120,000 | 1,020 | 500 | **+118,480** |

FREE и SUPPORTER не стоят ничего в AI (своя модель).
Платим только за PRO через DeepSeek API.
Маржинальность: **97%+**

---

## Ближайшие действия

1. **Zapret2 бинарники** — собрать/скачать winws2.exe и nfqws2
2. **Реальный тест в РФ** — shadow-mode с настоящим zapret2 на российском IP
3. **Отладка fitness** — убедиться что GA находит рабочие стратегии
4. **Cloudflare Worker relay** — развернуть для дополнительного обхода
5. **Dashboard** — веб-панель для мониторинга пользователей и стратегий

## Последние исправления (2026-03-26)

### Сервер (api.py)
- Fix: `datetime.utcnow()` → `datetime.now(timezone.utc)` (deprecated Python 3.12+)
- Fix: AI proxy — error handling для сетевых ошибок и невалидных ответов
- Fix: Negative vote penalty 0.0 → 0.2 (не убивает рейтинг стратегии)
- Cleanup: убраны неиспользуемые импорты

### Клиент
- Fix: `tier.current_tier_name` → `tier.tier` (несуществующий атрибут)
- Fix: socket leak в block_classifier при ошибке TLS wrap
- Fix: hardcoded "Ethernet" → автодетект сетевого интерфейса (ech.py DoH)

### Прокси-инфраструктура (tg-proxy)
- Security: SHA256 → PBKDF2-SHA256 (100k итераций + соль) для паролей
- Security: поддержка `--stdin-pass` в proxy_ctl.py (пароль не виден в ps)
- Fix: `_fail_tracker` dict — лимит 10k + периодическая очистка
- Fix: DB connection leak — все пути обёрнуты в try-finally
- Migration: автомиграция БД (колонка salt), обратная совместимость с legacy хешами

---

## Последние исправления (2026-04-24) — Autonomy audit & fixes

### Глубокий аудит автономной работы
Три параллельных аудита (discovery pipeline, fallback transports, orchestration) выявили:
- **Discovery**: GA получал мусорный сигнал (1 trial, 6s timeout) — эволюционировал стратегии, которые проходят тест, но фейлят в реале (Discord throttled 8s засчитывался как pass)
- **Fallbacks**: WARP installer блочит TSPU (`exit=28`), Telemost asyncio умирает через 10с + требует живого звонка, ECH неприменим (сайты не публикуют ключи). Работающих 24/7 fallback — **0**
- **Orchestration**: watchdog-loop правильный, но без watcher на winws2-процесс — 5 мин blackout при падении

### Реализованные фиксы

**NaiveProxy — умный fallback-слой** (приоритет 1.5 между user_proxy и WARP)
- Новый модуль: `brain/naive_proxy.py` (~290 строк)
- Wired в `brain/proxy_router.py`: активируется ТОЛЬКО для IP-blocked/HTTP2_STREAM_KILL хостов через PAC. 99% трафика остаётся на zapret2 с нативной скоростью — не VPN, а targeted escalation.
- Автоскачивание бинаря `naive.exe` с GitHub releases (~30 MB в `bin/`) с fallback на known version
- Config: `naive_proxy_url` + `naive_proxy_socks_port` (default 1084, чтобы не конфликтовать с gost на 1082 / telemost на 1083)
- Credentials — только в локальном `config.json` (в `.gitignore`)

**GA fitness signal** (`brain/tester.py:113-120`)
- `_evo_trials` 1 → 3 (ловит jitter, меньше ложных "прошло один раз повезло")
- `_evo_timeout` 6s → 10s (TSPU throttle ~8s теперь виден в evo как медленный success, не aborted curl)
- Результат: GA перестаёт плодить стратегии "работает в тесте, фейлит в жизни"

**winws2 health monitor** (`run_real.py:1104` в `_unified_watchdog`)
- Daemon-thread опрашивает `_active_process.poll()` каждые 10с
- При крахе winws2 → автореспавн через `_start_permanent_zapret` с текущей стратегией
- Exponential backoff 2s→60s если респавн не удаётся
- Было: 5 мин blackout до следующего watchdog-тика. Стало: ~10с

### Константы ограничения (для памяти)
- **Telemost** нельзя ставить 24/7 fallback — требует активного звонка пользователя. Оставлен как break-glass (manual).
- **WARP** мёртв на TSPU — installer блокируется на скачивании. Оставлен в цепочке последним (работает на не-TSPU ISP).
- **ECH** неприменим для youtube/discord — сайты не публикуют ECH keys в DNS.

### Cleanup веток
Удалены заброшенные эксперименты конца марта:
- `claude/elegant-mclaren` (точный дубликат `claude/awesome-feynman`)
- `claude/elated-feynman` (содержала uncommitted SOCKS5→SOCKS PAC-fix, не перенесён)
Оставлены: `main`, `claude/awesome-feynman` (4 коммита, не смержена — есть потенциально ценные фиксы Discord/YouTube).

**Profile-aware TTL в GA** (`brain/genetic.py`)
- `StrategyGene.__init__` принимает `recommended_ttl` (из TSPU-профайлера, обычно 2-5 для er-telecom/Rostelecom)
- Новый хелпер `_pick_ttl(lo, hi)`: 70% мутаций в `[rec-1, rec+1]`, 20% в `[rec-2, rec+2]`, 10% полный диапазон
- Все 5 точек генерации TTL переведены на хелпер: `fake/fakedsplit` (2 места), `pktmod`, `send`, `add_param mutation`, compound pattern `duplicate_tamper`
- `run_real.py _run_evolution` принимает и пробрасывает `recommended_ttl=_tspu_recommended_ttl`
- **Верификация**: smoke-тест 1000 итераций → 859 попаданий в `[rec-1..rec+1]` c recommended_ttl=3 vs 184 у рандома — **4.7× эффективнее**
- Было: 93% мутаций TTL ≥ 6 никогда не достигали TSPU (middlebox на hop=3). Стало: GA концентрируется на реально рабочем окне.

**Phase A: H2 downgrade primitive** (`lua/svoboda_h2_downgrade.lua`, `brain/enumerator.py`)
- Новый custom lua-desync `alpn_strip` — модифицирует TLS ClientHello in-place, удаляя h2/h2c из ALPN extension. Сервер падает на HTTP/1.1, TSPU не убивает h2 stream (потому что его нет).
- 4 новые стратегии в enumerator (Tier 0.5, между nofake и community):
  `h2downgrade_alpn_only`, `h2downgrade_split568`, `h2downgrade_split4096`, `h2downgrade_disorder_seqovl5`
- `tester.py` и `run_real.py` загружают все `lua/svoboda_*.lua` через `--lua-init` после zapret-antidpi
- Целевой эффект: Discord перестаёт throttle'иться (HTTP2_STREAM_KILL обходится без туннеля)
- Per-host solver автоматически дойдёт до alpn_strip для хостов где Tier 0 не пробил — без явного wiring блок-классификатора (стратегии в правильной приоритетной позиции)

### Оставшиеся пункты аудита (приоритет)
- [ ] **№4b Enumerator ISP-prioritization** — сортировать 62+ стратегий по рейтингу успеха для данной ISP (данные с сервера или локально накопленные)
- [ ] **№5 Network change → force re-enum** — при смене IP сбрасывать `_wd_flags`, не только TTL
- [ ] **№6 AI получает block classification + ISP profile** — сейчас только `isp + middlebox_type`, без HTTP2_STREAM_KILL / latency pattern
- [ ] **№7 p95 latency check в watchdog** — ловить throttling до того как streak_fail сработает
- [ ] Bonus: byedpi в escalation cascade (локальный SOCKS5, полностью авто)
- [ ] Bonus: восстановить `svoboda_tray.py` из `awesome-feynman` (run.bat option [1] сейчас сломан в main)
