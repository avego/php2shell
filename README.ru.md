# Universal PHP2Shell Security Scanner & Soft-OOM Patches (CVE-2026-109618, CVE-2026-109619 & CVE-2026-115560)

> 🌐 **Language / Язык:** [**English (Default)**](README.md) | **Русский**

Репозиторий содержит:
1. **Универсальный строго Read-Only сканер безопасности `check_php_cve.sh` (v1.3)** для аудита любых Linux-серверов и панелей управления хостингом (**FastPanel, ISPmanager, aaPanel/Baota, HestiaCP, VestaCP, Plesk, cPanel/EasyApache, CloudLinux alt-php, DirectAdmin, CyberPanel/OpenLiteSpeed, BrainyCP, KeyHelp, Remi/RHSCL**, а также системных сборок Debian/Ubuntu/RHEL/Alpine/Arch).
2. **Полные архитектурные бэкпорты патчей безопасности `Soft-OOM` (PHP 5.2 – 8.1)** и пошаговые руководства по нативной компиляции с 100% сохранением ABI-совместимости модулей **FastPanel** и поддержкой **OpenSSL 1.1+ (`ssl://`, `tls://`)**.

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

## 🚀 Универсальный Read-Only аудит сервера (`check_php_cve.sh` v1.3)

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

| Критерий / Механизм проверки | Сторонние сканеры (конкуренты) | Наш сканер `check_php_cve.sh` (v1.3) |
|---|---|---|
| **Чистота сигнатур ELF-бинарников (защита от False Positives)** | ❌ Ищут строку `"Actual POST length does not match Content-Length"` (существует в `main/SAPI.c` с **2004 года** в каждом непатченном PHP!) или директиву `max_multipart_body_parts` (добавлена в **феврале 2023 года** для `CVE-2023-0662` в PHP 8.0.28 / 8.1.16, присутствует в уязвимых PHP 8.0.30 и 8.1.29). | ✅ Использует **исключительно символы ядра октября 2026 года**, которых физически не существовало ни в одной сборке PHP до выхода патчей: `zend_handle_delayed_oom` (Zend 2), `memory_hard_limit_percent` (Zend 3/4), `zend_mm_safe_error_ex`, `__PHP_Incomplete_Class_Serialized`. **Вероятность ложноположительного срабатывания = 0%.** |
| **Различение архитектуры патча (`Soft-OOM` vs `Minimal` vs `Partial`)** | ⚠️ Сваливают любые совпадения в общий статус «Patched» или путаются на EOL-ветках PHP 5.x/7.x. | ✅ Чётко классифицирует 4 типа патчей:<br>1. **`Full Soft-OOM Patch`** (отложенный OOM, воркер PHP-FPM остаётся жив, `shutdown`-функции работают безопасно);<br>2. **`Enhanced Patch`** (`_exit(1)` при OOM + `incomplete_classes_only`);<br>3. **`Minimal Vendor Patch`** (аварийный `_exit(1)` из аллокатора, убивающий воркер FPM с `502 Bad Gateway`, + вырезанный `upload_progress`);<br>4. **`Partial Patch`** (затронут только `rfc1867`/`session`, но аллокатор `ZendMM` остался уязвим!). |
| **Комплексная проверка всей связки SAPI (`CLI` + `CGI` + `FPM` + `LSPHP`)** | ⚠️ Зачастую проверяют только один найденный `php` CLI-бинарник, не замечая, что в памяти крутится непропатченный `php-fpm`, `php-cgi` или `lsphp`. | ✅ Проверяет **все 4 бинарника каждой установки** (`bin/php`, `bin/php-cgi`, `sbin/php-fpm`, `bin/lsphp`), определяет активные процессы `php-fpm` в памяти и выносит вердикт `SAFE` **только если защищены все SAPI**. |
| **Глубокий аудит `session.upload_progress` и `Zero 1`** | ⚠️ Проверяют только `ini_get('session.upload_progress.enabled')` и ошибочно помечают непатченный бинарник с `Off` как «безопасный» (забывая, что `CVE-2026-109618` пробивается без `upload_progress` обычным POST/GET OOM). | ✅ Различает 5 состояний:<br>• `N/A in PHP 5.2/5.3` (механизм появился в 5.4);<br>• `HARD-DISABLED in binary (\|\| 1)` (код мёртво вырезан компилятором в `minimal`-патчах ISPmanager/FastPanel);<br>• `ENABLED & ISOLATED` (защищён через `__PHP_Incomplete_Class_Serialized`);<br>• `DISABLED in php.ini` (митигирует `CVE-2026-115560` и `Zero 1`, но бинарник помечается как **`[UNPATCHED BINARY]`**, так как OOM RCE остаётся открытым!);<br>• Выводит текущий `session.serialize_handler` (`php` / `php_serialize`). |
| **Контроль работоспособности OpenSSL (`ssl://` и `tls://`)** | ❌ Не проверяют (после ручной пересборки старых PHP 5.x/7.x на современных ОС администраторы часто получают сломанный HTTPS/cURL/SMTP без `ssl://`). | ✅ Автоматически тестирует `stream_get_transports()` в каждой найденной версии PHP и предупреждает, если транспорты `ssl://` и `tls://` отсутствуют. |
| **Гарантия безопасности (`100% Read-Only`)** | ⚠️ Могут модифицировать боевые конфиги или создавать временные файлы в `/tmp`. | ✅ **Строго `Read-Only`:** ноль записей на диск, ноль временных файлов (`mktemp`), ноль изменений пакетов и конфигов. Работает даже без `binutils` (автоматический фолбэк со `strings` на `grep -a`). |
| **Охват панелей управления** | 5–6 базовых путей (`aaPanel`, `Hestia`, `Plesk`, `cPanel`, `Remi`). | **13+ панелей и репозиториев:** `FastPanel` (включая внутренний `/opt/fphp`), `ISPmanager`, `aaPanel/Baota`, `Plesk`, `cPanel/EA4`, `CloudLinux alt-php`, `DirectAdmin`, `CyberPanel/OpenLiteSpeed`, `HestiaCP`, `VestaCP`, `BrainyCP`, `KeyHelp`, `Remi/RHSCL`, системные PHP. |

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

## 📊 Матрица протестированных версий и руководств (FastPanel & Debian 11)

| Версия PHP | Расположение | Архитектура защиты | Статус | Пошаговое руководство |
|---|---|---|---|---|
| **PHP 5.2.17 – 5.4.45** | Исходники / Панели | Бэкпорт Zend Engine 2 (`zend_handle_delayed_oom`) | ✅ Патчи в `patch/` | Универсальные `.patch` |
| **PHP 5.6.40** | FastPanel `/opt/php56` | Бэкпорт Zend Engine 2 (`zend_handle_delayed_oom`) + OpenSSL 1.1 | ✅ Защищён | [Мануал PHP 5.6](FASTPANEL_PHP5.6_PATCHING_MANUAL.md) |
| **PHP 7.0.33 – 7.3.33** | FastPanel `/opt/php71` и др. | Бэкпорт Zend Engine 3 (`memory_hard_limit_percent`) | ✅ Защищён | [Мануал PHP 7.1](FASTPANEL_PHP7.1_PATCHING_MANUAL.md) |
| **PHP 7.3.33 (`fphp`)** | FastPanel `/opt/fphp` | Внутренний PHP самой панели (`fastpanel2-apps`) | ✅ Защищён | [Мануал fphp 7.3](FASTPANEL_FPHP7.3_PATCHING_MANUAL.md) |
| **PHP 7.4.33** | Системный Debian 11 | Нативные `.deb` пакеты (`dpkg-buildpackage`) | ✅ Защищён | [Мануал PHP 7.4 Debian](FASTPANEL_PHP7.4_DEBIAN11_MANUAL.md) |
| **PHP 8.0.30 – 8.1.34** | FastPanel `/opt/php81` | Бэкпорт Zend Engine 4 (`memory_hard_limit_percent` + OPcache fix) | ✅ Защищён | [Мануал PHP 8.1](FASTPANEL_PHP8.1_PATCHING_MANUAL.md) |
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
├── FASTPANEL_PHP5.6_PATCHING_MANUAL.md                        # Инструкция: FastPanel /opt/php56
├── FASTPANEL_PHP7.1_PATCHING_MANUAL.md                        # Инструкция: FastPanel /opt/php71
├── FASTPANEL_FPHP7.3_PATCHING_MANUAL.md                       # Инструкция: FastPanel /opt/fphp (панель)
├── FASTPANEL_PHP7.4_DEBIAN11_MANUAL.md                        # Инструкция: Debian 11 нативные deb
├── FASTPANEL_PHP8.1_PATCHING_MANUAL.md                        # Инструкция: FastPanel /opt/php81
├── check_php_cve.sh                                           # Универсальный Read-Only сканер безопасности v1.3
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

## 👥 Благодарности и авторство (Credits & Provenance)

- **Оригинальное исправление в upstream PHP (`php-src`):**
  - **Автор механизма ядра:** **Arnaud Le Blanc** (`arnaud.lb@gmail.com`), upstream commit `01a40e89fb` (*"Avoid state corruption via bailout"*), официально включённый в PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+.
  - **Идентификаторы безопасности:** CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp).
- **Бэкпорт архитектуры `Soft-OOM` для EOL-веток PHP (5.2 – 8.1):**
  - Сообщество мейнтейнеров **docker-php** и разработчик **realhidden** ([gist.github.com/realhidden](https://gist.github.com/realhidden)).
- **Разработка универсального Read-Only сканера `check_php_cve.sh` и адаптация под FastPanel / Debian 11:**
  - **Репозиторий:** [avego/php2shell](https://github.com/avego/php2shell).
