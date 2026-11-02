<div align="center">

# 🛡️ Универсальный сканер безопасности PHP и полные патчи EOL (PHP 5.2–8.1)

### Комплексная защита от уязвимостей CVE-2026-109618, CVE-2026-109619 и CVE-2026-115560 («PHP2Shell»)

[![Language: English](https://img.shields.io/badge/Language-English%20(Default)-007ec6?style=for-the-badge)](README.md)
[![Language: Russian](https://img.shields.io/badge/%D0%AF%D0%B7%D1%8B%D0%BA-%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B0%D1%8F%20%D0%B4%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D0%B8%D1%8F-2ea44f?style=for-the-badge)](README.ru.md)

[![PHP Versions](https://img.shields.io/badge/PHP-5.2%20to%208.1%20EOL-777bb4?style=flat-square&logo=php&logoColor=white)](#)
[![Scanner Version](https://img.shields.io/badge/Scanner-v1.4%20(Strictly%20Read--Only)-brightgreen?style=flat-square)](#)
[![Patch Architecture](https://img.shields.io/badge/Patch%20Architecture-Full%20Soft--OOM%20(Not%20Minimal)-blue?style=flat-square)](#)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Bash)-orange?style=flat-square)](#)

[![Panels](https://img.shields.io/badge/Panels-FastPanel%20%7C%20ISPmanager%20%7C%20cPanel%20%7C%20Plesk%20%7C%20aaPanel%20%7C%20BrainyCP%20%7C%20CWP%20%7C%20RunCloud%20%7C%20HestiaCP%20%7C%20DirectAdmin%20%7C%20CloudLinux-4c1?style=flat-square)](#)

[![License: MIT](https://img.shields.io/badge/License-MIT-007ec6?style=flat-square)](LICENSE)

</div>

## 📌 О проекте и предыстория

В конце октября 2026 года в ядре PHP была раскрыта цепочка критических уязвимостей (обобщённо названная **«PHP2Shell»**), позволяющая осуществить удалённое выполнение произвольного кода (**RCE**) через специально сформированные HTTP-запросы multipart/form-data и исчерпание лимита оперативной памяти (memory_limit).

Официальная группа разработчиков PHP Group выпустила исправления **только для актуальных веток** (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+), оставив все устаревшие ветки (**PHP 5.2 – 8.1**) полностью без официальных обновлений безопасности. Подавляющее большинство вендоров панелей управления хостингом и репозиториев либо затянули с реакцией, либо выпустили «минимальные отсекающие заплатки», которые приводят к падению воркеров по SIGKILL (502 Bad Gateway).

### Что представляет собой этот репозиторий:

1. 🌍 **Универсальные ПОЛНЫЕ патчи безопасности (PHP 5.2 — 8.1):**  
   Это **не урезанные минимальные заплатки**, а **полноценные архитектурные патчи двухфазного Soft-OOM аллокатора** для C-ядра Zend Engine. Патчи платформо-независимы: они подходят для любого Linux-дистрибутива (Debian, Ubuntu, AlmaLinux, Rocky, CentOS), любой панели управления (FastPanel, ISPmanager, cPanel, Plesk, HestiaCP, DirectAdmin и др.) или изолированных Docker-контейнеров.
2. 🔍 **Универсальный Read-Only сканер (check_php_cve.sh v1.4):**  
   Абсолютно безопасный скрипт без единой операции записи на диск. Находит любые бинарники PHP в системе (включая активные процессы в /proc) и безошибочно различает уязвимые версии, минимальные вендорские заплатки (Zero-1 / Minimal Panic) и полноценную защиту (Full Soft-OOM).
3. 🔬 **Академический технический аудит каждого патча:**  
   Все 12 версий PHP (от 8.1 до 5.2) прошли пофайловый аудит C-кода, проверку наложения на чистые дистрибутивы PHP и верификацию сохранения бинарного ABI структур zend_globals.h.
4. 🛠️ **Боевой практический кейс автора (Reference Implementation):**  
   Автор проекта пропатчил свои рабочие серверы **ещё до появления официальных обновлений от разработчиков FastPanel**. Поскольку продакшен-инфраструктура автора построена на связке **Debian 11 (Bullseye) + FastPanel**, в репозитории представлены **проверенные в бою пошаговые инструкции, скрипты сборки deb-пакетов и готовые бинарные сборки** для этого стека как эталонный практический пример развёртывания.

---

## 🔒 Описание уязвимостей («PHP2Shell»)

- **CVE-2026-109618 (RCE via ZendMM OOM `longjmp` memory corruption):**  
  Превышение лимита оперативной памяти (`memory_limit`) в стандартном PHP приводило к немедленному вызову `zend_bailout()` (`longjmp`) прямо из аллокатора памяти `ZendMM` посередине незавершённых операций (парсинг `POST`/`GET`/`COOKIE`, `multipart/form-data`, десериализация, манипуляции с `HashTable`). Это оставляло внутренние структуры Zend Engine с повреждёнными указателями и позволяло выполнить произвольный код (Remote Code Execution) на этапе `shutdown` или в следующем запросе воркера.
- **CVE-2026-109619 (RCE via stale executor & error-handler state across FPM requests):**  
  Сохранение повреждённого глобального состояния исполнителя Zend VM (`EG(user_error_handler)`, `CG`/`BG`-состояний) между запросами внутри долгоживущих воркеров `php-fpm` / `mod_fcgid` / `lsphp`.
- **CVE-2026-115560 & Session Upload Progress Deserialization Gaps (`Zero 1`):**  
  Небезопасная десериализация данных прогресса загрузки (`PHP_SESSION_UPLOAD_PROGRESS`) до инициализации скрипта, ведущая к PHP Object Injection при использовании `session.upload_progress.enabled = 1` (особенно в сочетании с `session.serialize_handler = php_serialize`).

Upstream PHP Group официально выпустила исправления только для веток **8.2.35+**, **8.3.36+**, **8.4.27+** и **8.5.12+**, оставив все EOL-ветки (**PHP 5.2 – 8.1**) без официальных обновлений.

---

## 🚀 Универсальный Read-Only аудит сервера (`check_php_cve.sh` v1.4)

Скрипт работает **строго в режиме чтения (`Zero Disk Writes`)**: не изменяет `php.ini`, не устанавливает пакеты в систему и не создаёт ни одного временного файла на диске (даже сетевые проверки выполняются полностью в оперативной памяти).

### Быстрый запуск одной командой:
```bash
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash
```

### Дополнительные режимы запуска (CLI-ключи):
```bash
# Глубокий поиск всех кастомных и архивных бинарников PHP по файловой системе (/opt, /www, /usr/local, /home, /var, /usr/src):
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash -s -- --all

# Машиночитаемый JSON-отчёт для систем мониторинга, Ansible и CI/CD:
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash -s -- --json

# Удалённая неразрушающая HTTP/HTTPS-проверка заголовков, WAF и multipart-ответа (100% в памяти, без записи на диск):
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash -s -- --url https://example.com
```

---

## 🧠 Как работает `check_php_cve.sh` и чем он отличается от аналогов

Большинство сторонних сканеров для проверки `PHP2Shell` совершают критические методологические ошибки, используя косвенные или исторически «загрязнённые» строки из бинарников PHP, что приводит к **ложноположительным (`False Positive`) вердиктам «Пропатчено» на 100% уязвимых серверах**.

### Ключевые архитектурные отличия нашего сканера:

| Критерий / Механизм проверки | Сторонние сканеры (конкуренты) | Наш сканер `check_php_cve.sh` (v1.4) |
|---|---|---|
| **Чистота сигнатур ELF-бинарников (защита от False Positives)** | ❌ Ищут строку `"Actual POST length does not match Content-Length"` (существует в `main/SAPI.c` с **2004 года** в каждом непатченном PHP!) или директиву `max_multipart_body_parts` (добавлена в **феврале 2023 года** для `CVE-2023-0662` в PHP 8.0.28 / 8.1.16, присутствует в уязвимых PHP 8.0.30 и 8.1.29). | ✅ Использует **исключительно символы ядра октября 2026 года**, которых физически не существовало ни в одной сборке PHP до выхода патчей: `zend_handle_delayed_oom` (Zend 2), `memory_hard_limit_percent` (Zend 3/4), `zend_mm_safe_error_ex`, `__PHP_Incomplete_Class_Serialized`. **Вероятность ложноположительного срабатывания = 0%.** |
| **Различение архитектуры патча (`Soft-OOM` vs `Minimal` vs `Partial`)** | ⚠️ Сваливают любые совпадения в общий статус «Patched» или путаются на EOL-ветках PHP 5.x/7.x. | ✅ Чётко классифицирует 4 типа патчей:<br>1. **`Full Soft-OOM Patch`** (отложенный OOM, воркер PHP-FPM остаётся жив, `shutdown`-функции работают безопасно);<br>2. **`Enhanced Patch`** (`_exit(1)` при OOM + `incomplete_classes_only`);<br>3. **`Minimal Vendor Patch`** (аварийный `_exit(1)` из аллокатора, убивающий воркер FPM с `502 Bad Gateway`, + вырезанный `upload_progress`);<br>4. **`Partial Patch`** (затронут только `rfc1867`/`session`, но аллокатор `ZendMM` остался уязвим!). |
| **Комплексная проверка всей связки SAPI (`CLI` + `CGI` + `FPM` + `LSPHP`)** | ⚠️ Зачастую проверяют только один найденный `php` CLI-бинарник, не замечая, что в памяти крутится непропатченный `php-fpm`, `php-cgi` или `lsphp`. | ✅ Проверяет **все 4 бинарника каждой установки** (`bin/php`, `bin/php-cgi`, `sbin/php-fpm`, `bin/lsphp`), определяет активные процессы `php-fpm` в памяти и выносит вердикт `SAFE` **только если защищены все SAPI**. |
| **Глубокий аудит `session.upload_progress` и `Zero 1`** | ⚠️ Проверяют только `ini_get('session.upload_progress.enabled')` и ошибочно помечают непатченный бинарник с `Off` как «безопасный» (забывая, что `CVE-2026-109618` пробивается без `upload_progress` обычным POST/GET OOM). | ✅ Различает 5 состояний:<br>• `N/A in PHP 5.2/5.3` (механизм появился в 5.4);<br>• `HARD-DISABLED in binary (\|\| 1)` (код мёртво вырезан компилятором в `minimal`-патчах ISPmanager/FastPanel);<br>• `ENABLED & ISOLATED` (защищён через `__PHP_Incomplete_Class_Serialized`);<br>• `DISABLED in php.ini` (митигирует `CVE-2026-115560` и `Zero 1`, но бинарник помечается как **`[UNPATCHED BINARY]`**, так как OOM RCE остаётся открытым!);<br>• Выводит текущий `session.serialize_handler` (`php` / `php_serialize`). |
| **Контроль работоспособности OpenSSL (`ssl://` и `tls://`)** | ❌ Не проверяют (после ручной пересборки старых PHP 5.x/7.x на современных ОС администраторы часто получают сломанный HTTPS/cURL/SMTP без `ssl://`). | ✅ Автоматически тестирует `stream_get_transports()` в каждой найденной версии PHP и предупреждает, если транспорты `ssl://` и `tls://` отсутствуют. |
| **Гарантия безопасности (`100% Read-Only`)** | ⚠️ Могут модифицировать боевые конфиги или создавать временные файлы в `/tmp`. | ✅ **Строго `Read-Only`:** ноль записей на диск, ноль временных файлов (`mktemp`), ноль изменений пакетов и конфигов. Работает даже без `binutils` (автоматический фолбэк со `strings` на `grep -a`). |
| **Охват панелей управления и живых процессов (`/proc`)** | 5–6 базовых путей (`aaPanel`, `Hestia`, `Plesk`, `cPanel`, `Remi`). | **17+ панелей, репозиториев и автопоиск живых SAPI через `/proc/<pid>/exe`:** `FastPanel` (включая `/opt/fphp`), `ISPmanager`, `aaPanel/Baota`, `Plesk` (вкл. `lsphp`), `cPanel/EA4` (вкл. `lsphp` и внутренний `3rdparty/php`), `CloudLinux` (`alt-php`, `alt-php-fpm`, `alt-php-internal`), `DirectAdmin`, `CyberPanel/OpenLiteSpeed`, `BrainyCP` (`/usr/bin/phpXX/bin/*` и внутренний `compiled/php5`), `CWP (Control WebPanel)`, `RunCloud` (`/RunCloud/Packages/php*rc`), `KeyHelp`, `HestiaCP`, `VestaCP`, `CloudPanel`, `ISPConfig`, `Remi/RHSCL`, системные PHP + автоматический перехват любых запущенных в памяти нестандартных `php-fpm`/`php-cgi`/`lsphp` через `/proc`. |

---

## ⚖️ Сравнение двух подходов к патчингу: наш `Full Soft-OOM` vs вендорский `Minimal Patch`

Многие вендоры панелей управления (например, ISPmanager в `isp-php54..81` и FastPanel в отдельных пакетах `php54`/`php71`) применили урезанный 7-функциональный `minimal`-патч вместо полноценного бэкпорта архитектуры `Soft-OOM` из PHP 8.2.35:

| Характеристика | Вендорский `Minimal Patch` (`zend_mm_safe_error_ex`) | Наш `Full Soft-OOM Patch` (`avego/php2shell`) |
|---|---|---|
| **Поведение при `memory_limit` (OOM)** | Немедленно убивает весь процесс через `_exit(1)` прямо внутри аллокатора. | Ставит флаг отложенного OOM (`delayed_oom` / `memory_hard_limit_percent`), возвращает безопасный fallback и штатно завершает скрипт в безопасной точке VM. |
| **Стабильность воркеров PHP-FPM / Nginx** | ⚠️ Убитый воркер обрывает соединение с веб-сервером (`502 Bad Gateway`), сбрасывает локальные кэши и заставляет мастер-процесс форкать новый воркер. | ✅ Воркер PHP-FPM **остаётся жив**, корректно освобождает память запроса и продолжает обслуживать соединения. |
| **Работа `register_shutdown_function()` и логгеров CMS** | ❌ **Сломана при OOM** — ни один `shutdown`-обработчик или фреймворк-логгер не выполняется. | ✅ **Работает штатно и безопасно** после контролируемой раскрутки стека. |
| **Работа `session.upload_progress`** | ❌ **Намертво вырезана из бинарника** условием `if (!PS(rfc1867_enabled) \|\| 1)` — прогресс-бары загрузки файлов перестают работать даже при `enabled = On`. | ✅ **Сохранена и изолирована** через `incomplete_classes_only` (`__PHP_Incomplete_Class_Serialized`) + раннюю очистку `php_rinit_session_globals()`. |

---

## 🛠️ Протестированные версии PHP и мануалы (Кейс автора: Debian 11 & FastPanel)

> 💡 **Эталонный боевой стенд автора (Debian 11 & FastPanel):**  
> Сами патчи и сканер в этом проекте **абсолютно универсальны** и подходят для любых дистрибутивов Linux, любых панелей управления (ISPmanager, cPanel, Plesk, HestiaCP и др.) и Docker-контейнеров. Однако приведенные ниже пошаговые руководства отражают **реальный боевой опыт автора по развёртыванию на Debian 11 (Bullseye) и FastPanel**, где автор защитил свои продакшен-серверы ещё до выхода официальных патчей от разработчиков FastPanel. Вы можете использовать их напрямую для FastPanel/Debian 11 или как проверенный образец для адаптации под вашу панель.

| Версия PHP | Расположение | Архитектура защиты | Статус | Пошаговое руководство |
|---|---|---|---|---|
| **PHP 5.2.17 – 5.4.45** | Исходники / Панели | Бэкпорт Zend Engine 2 (`zend_handle_delayed_oom`) | ✅ Патчи в `patch/` | Универсальные `.patch` |
| **PHP 5.6.40** | FastPanel `/opt/php56` | Бэкпорт Zend Engine 2 (`zend_handle_delayed_oom`) + OpenSSL 1.1 | ✅ Защищён | [Мануал PHP 5.6](manuals/FASTPANEL_PHP5.6_PATCHING_MANUAL.md) |
| **PHP 7.0.33 – 7.3.33** | FastPanel `/opt/php71` и др. | Бэкпорт Zend Engine 3 (`memory_hard_limit_percent`) | ✅ Защищён | [Мануал PHP 7.1](manuals/FASTPANEL_PHP7.1_PATCHING_MANUAL.md) |
| **PHP 7.3.33 (`fphp`)** | FastPanel `/opt/fphp` | Внутренний PHP самой панели (`fastpanel2-apps`) | ✅ Защищён | [Мануал fphp 7.3](manuals/FASTPANEL_FPHP7.3_PATCHING_MANUAL.md) |
| **PHP 7.4.33** | Системный Debian 11 | Нативные `.deb` пакеты (`dpkg-buildpackage`) | ✅ Защищён | [Мануал PHP 7.4 Debian](manuals/FASTPANEL_PHP7.4_DEBIAN11_MANUAL.md) |
| **PHP 8.0.30 – 8.1.34** | FastPanel `/opt/php81` | Бэкпорт Zend Engine 4 (`memory_hard_limit_percent` + OPcache fix) | ✅ Защищён | [Мануал PHP 8.1](manuals/FASTPANEL_PHP8.1_PATCHING_MANUAL.md) |
| **PHP 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+** | FastPanel `/opt/php84`, `/opt/php85` | Официальный апстрим PHP Group (`Soft-OOM`) | ✅ Защищён из коробки | Встроен в официальный релиз |

---

## 📁 Структура репозитория

```text
├── patch/                                                     # Патчи безопасности Soft-OOM и совместимости
│   ├── php56-openssl11/                                       # Адаптированные исходники OpenSSL 1.1 для PHP 5.6
│   │   ├── openssl.c
│   │   ├── xp_ssl.c
│   │   └── php_openssl.h
│   ├── php-5.6-openssl-1.1.patch                              # Unified diff совместимости OpenSSL 1.1 для PHP 5.6
│   ├── php-5.2.17-cve-2026-109618-109619.patch
│   ├── php-5.3.29-cve-2026-109618-109619.patch
│   ├── php-5.4.45-cve-2026-109618-109619.patch
│   ├── php-5.6.40-cve-2026-109618-109619.patch
│   ├── php-7.0.33-cve-2026-109618-109619.patch
│   ├── php-7.1.33-cve-2026-109618-109619.patch
│   ├── php-7.2.34-cve-2026-109618-109619.patch
│   ├── php-7.3.33-cve-2026-109618-109619.patch
│   ├── php-7.4.33-cve-2026-109618-109619.patch                # Для чистого upstream tar.gz
│   ├── php-7.4.33-debian11-cve-2026-109618-109619.patch       # Эталонный diff для dpkg Debian 11
│   ├── php-8.0.30-cve-2026-109618-109619.patch
│   ├── php-8.1.29-cve-2026-109618-109619.patch
│   └── php-8.1.34-cve-2026-109618-109619.patch
├── manuals/                                                   # Эталонные мануалы автора (FastPanel & Debian 11)
│   ├── FASTPANEL_PHP5.6_PATCHING_MANUAL.md                    # Инструкция: FastPanel /opt/php56
│   ├── FASTPANEL_PHP7.1_PATCHING_MANUAL.md                    # Инструкция: FastPanel /opt/php71
│   ├── FASTPANEL_FPHP7.3_PATCHING_MANUAL.md                   # Инструкция: FastPanel /opt/fphp (панель)
│   ├── FASTPANEL_PHP7.4_DEBIAN11_MANUAL.md                    # Инструкция: Debian 11 нативные deb
│   └── FASTPANEL_PHP8.1_PATCHING_MANUAL.md                    # Инструкция: FastPanel /opt/php81
├── analysis/                                                  # Отчёты академического технического аудита (RU и EN)
│   ├── PHP-5.2-PATCH-ANALYSIS.md / .en.md
│   ├── ...
│   └── PHP-8.1-PATCH-ANALYSIS.md / .en.md
├── check_php_cve.sh                                           # Универсальный Read-Only сканер безопасности v1.4
├── README.md                                                  # Документация на английском (по умолчанию)
└── README.ru.md                                               # Документация на русском языке
```

---

## ⚡ Ключевые принципы совместимости при сборке для FastPanel

1. **Предварительное снятие конфигурации:**
   Перед сборкой всегда проверяются точная подверсия и оригинальные флаги `Configure Command`:
   ```bash
   /opt/phpXX/bin/php -v
   /opt/phpXX/bin/php -i | grep -i "configure command"
   ```

2. **Сохранение ABI модулей СУБД (`shared,mysqlnd`) и OpenSSL (`ssl://`, `tls://`):**
   FastPanel загружает расширения БД (`mysqli.so`, `pdo_mysql.so`) как **динамические внешние модули (`shared`)** из `/opt/phpXX/conf.d/*.ini`.
   - Ядро компилируется со встроенным движком `mysqlnd` и OpenSSL (`--with-openssl`), а драйверы БД — как разделяемые:
     ```bash
     --with-openssl \
     --enable-mysqlnd \
     --with-mysqli=shared,mysqlnd \
     --with-pdo-mysql=shared,mysqlnd \
     --with-mysql-sock=/var/run/mysqld/mysqld.sock
     ```
     *(Для ветки PHP 5.6 дополнительно используется `--with-mysql=shared,mysqlnd` и наш патч совместимости с OpenSSL 1.1 `patch/php-5.6-openssl-1.1.patch`)*.

3. **Атомарная установка бинарников (`install -m 755`):**
   Для исключения ошибки `Text file busy` на живых воркерах замена выполняется атомарно через `install`:
   ```bash
   install -m 755 sapi/cli/php /opt/phpXX/bin/php
   install -m 755 sapi/cgi/php-cgi /opt/phpXX/bin/php-cgi
   [ -f sapi/fpm/php-fpm ] && install -m 755 sapi/fpm/php-fpm /opt/phpXX/sbin/php-fpm 2>/dev/null || true
   ```

---

## 🔍 Ручная проверка бинарников (Верификация)

### Для PHP 7.0 – 8.1 (Zend Engine 3 и 4):
```bash
/opt/phpXX/bin/php -i | grep memory_hard_limit_percent
strings /opt/phpXX/bin/php | grep -E "memory_hard_limit_percent|zend_mm_safe_error_ex"
```

### Для PHP 5.2 – 5.6 (Zend Engine 2):
```bash
strings /opt/php56/bin/php | grep -E "zend_handle_delayed_oom|ZEND_OOM_STATE|zend_mm_safe_error_ex"
```

---

## 🛡️ Процедура мгновенного отката (Rollback)

```bash
install -m 755 /opt/phpXX.bak/bin/php /opt/phpXX/bin/php
[ -f /opt/phpXX.bak/bin/php-cgi ] && install -m 755 /opt/phpXX.bak/bin/php-cgi /opt/phpXX/bin/php-cgi 2>/dev/null || true
[ -f /opt/phpXX.bak/sbin/php-fpm ] && install -m 755 /opt/phpXX.bak/sbin/php-fpm /opt/phpXX/sbin/php-fpm 2>/dev/null || true

killall -9 php-cgi 2>/dev/null || true
systemctl restart apache2 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true
systemctl restart fp2-phpXX-fpm 2>/dev/null || systemctl restart phpXX-fpm 2>/dev/null || true
```

---

---

## 🛡️ Патчи безопасности и детальные технические аудиты

В репозитории поддерживается верифицированный набор патчей безопасности, бэкпортирующих **двухуровневый Soft-OOM аллокатор** и **укрепление парсера RFC 1867 / связных списков Zend** (устраняющих CVE-2026-109618 и CVE-2026-109619) для всех устаревших версий PHP (с PHP 8.1 до PHP 5.2).

Каждый патч прошёл строгий академический аудит, проверку наложения (dry-run) на чистые официальные дистрибутивы PHP и верификацию контрольных символов в исходном коде.

| Ветка PHP | Архитектура ядра | Файл патча | Чистота наложения | Технический аудит |
|:---:|:---:|:---|:---:|:---:|
| **PHP 8.1** | Zend Engine 4.1 | [php-8.1.34-*.patch](patch/php-8.1.34-cve-2026-109618-109619.patch) <br> [php-8.1.29-*.patch](patch/php-8.1.29-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-8.1-PATCH-ANALYSIS.md) / [English](analysis/PHP-8.1-PATCH-ANALYSIS.en.md) |
| **PHP 8.0** | Zend Engine 4.0 | [php-8.0.30-*.patch](patch/php-8.0.30-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-8.0-PATCH-ANALYSIS.md) / [English](analysis/PHP-8.0-PATCH-ANALYSIS.en.md) |
| **PHP 7.4** | Zend Engine 3.4 | [php-7.4.33-*.patch](patch/php-7.4.33-cve-2026-109618-109619.patch) <br> [php-7.4.33-debian11-*.patch](patch/php-7.4.33-debian11-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-7.4-PATCH-ANALYSIS.md) / [English](analysis/PHP-7.4-PATCH-ANALYSIS.en.md) |
| **PHP 7.3** | Zend Engine 3.3 | [php-7.3.33-*.patch](patch/php-7.3.33-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-7.3-PATCH-ANALYSIS.md) / [English](analysis/PHP-7.3-PATCH-ANALYSIS.en.md) |
| **PHP 7.2** | Zend Engine 3.2 | [php-7.2.34-*.patch](patch/php-7.2.34-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-7.2-PATCH-ANALYSIS.md) / [English](analysis/PHP-7.2-PATCH-ANALYSIS.en.md) |
| **PHP 7.1** | Zend Engine 3.1 | [php-7.1.33-*.patch](patch/php-7.1.33-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-7.1-PATCH-ANALYSIS.md) / [English](analysis/PHP-7.1-PATCH-ANALYSIS.en.md) |
| **PHP 7.0** | Zend Engine 3.0 | [php-7.0.33-*.patch](patch/php-7.0.33-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-7.0-PATCH-ANALYSIS.md) / [English](analysis/PHP-7.0-PATCH-ANALYSIS.en.md) |
| **PHP 5.6** | Zend Engine 2.6 | [php-5.6.40-*.patch](patch/php-5.6.40-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-5.6-PATCH-ANALYSIS.md) / [English](analysis/PHP-5.6-PATCH-ANALYSIS.en.md) |
| **PHP 5.5** | Zend Engine 2.5 | [php-5.5.38-*.patch](patch/php-5.5.38-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-5.5-PATCH-ANALYSIS.md) / [English](analysis/PHP-5.5-PATCH-ANALYSIS.en.md) |
| **PHP 5.4** | Zend Engine 2.4 | [php-5.4.45-*.patch](patch/php-5.4.45-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-5.4-PATCH-ANALYSIS.md) / [English](analysis/PHP-5.4-PATCH-ANALYSIS.en.md) |
| **PHP 5.3** | Zend Engine 2.3 | [php-5.3.29-*.patch](patch/php-5.3.29-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-5.3-PATCH-ANALYSIS.md) / [English](analysis/PHP-5.3-PATCH-ANALYSIS.en.md) |
| **PHP 5.2** | Zend Engine 2.2 | [php-5.2.17-*.patch](patch/php-5.2.17-cve-2026-109618-109619.patch) | Чисто (100%) | [Русский](analysis/PHP-5.2-PATCH-ANALYSIS.md) / [English](analysis/PHP-5.2-PATCH-ANALYSIS.en.md) |

## 📄 Лицензия

[![License: MIT](https://img.shields.io/badge/License-MIT-007ec6?style=for-the-badge)](LICENSE)

Проект распространяется под свободной лицензией [MIT](LICENSE).

---

## 👥 Благодарности и авторство (Credits & Provenance)

- **Оригинальное исправление в upstream PHP (`php-src`):**
  - **Автор механизма ядра:** **Arnaud Le Blanc** (`arnaud.lb@gmail.com`), upstream commit `01a40e89fb` (*"Avoid state corruption via bailout"*), официально включённый в PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+.
  - **Идентификаторы безопасности:** CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp).
- **Бэкпорт архитектуры `Soft-OOM` для EOL-веток PHP (5.2 – 8.1):**
  - Сообщество мейнтейнеров **docker-php** и разработчик **realhidden** ([gist.github.com/realhidden](https://gist.github.com/realhidden)).
- **Разработка универсального Read-Only сканера `check_php_cve.sh` и адаптация под FastPanel / Debian 11:**
  - **Репозиторий:** [avego/php2shell](https://github.com/avego/php2shell).
