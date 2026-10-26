# FastPanel PHP Security Patching (CVE-2026-109618 & CVE-2026-109619)

Репозиторий содержит проверенные патчи безопасности, адаптированные бэкпорты и подробные пошаговые руководства по нативной компиляции и устранению критических уязвимостей ядра Zend Engine (**CVE-2026-109618** и **CVE-2026-109619**) для всех версий PHP в панели управления **FastPanel** и операционной системе **Debian 11 (Bullseye) x86_64** (Apache `mod_fcgid`, PHP-FPM, системный FPM-сервис самой панели).

---

## 🔒 Описание уязвимостей

- **CVE-2026-109618 (RCE via OOM memory corruption):**  
  Превышение лимита оперативной памяти (`memory_limit`) в стандартном PHP приводило к вызову `longjmp` непосредственно из аллокатора памяти во время незавершённых операций (парсинг `multipart/form-data`, `url-encoded`, десериализация, чтение потоков). Это вызывало разрушение внутренних структур ядра Zend VM, повреждение хэш-таблиц и указателей на деструкторы, что позволяло злоумышленнику удалённо выполнить произвольный код (Remote Code Execution) через специально сформированный HTTP-запрос.
- **CVE-2026-109619 (RCE via stale global state):**  
  Уязвимость разрушения глобального состояния исполнителя Zend Engine, обработчиков ошибок и парсера прогресса загрузки сессий (`session.upload_progress`).

Upstream PHP Group официально исправила эти проблемы только в активных ветках: **8.2.28+**, **8.3.18+**, **8.4.5+** и **8.5+**, оставив все EOL-версии (**PHP 5.2 – 8.1**) уязвимыми. Данный репозиторий закрывает эту брешь.

---

## 🚀 Быстрый аудит сервера (One-line Scanner)

Для автоматической проверки всех установленных версий PHP (включая `/opt/php*`, `/opt/fphp`, системные `/usr/bin/php*` и FPM-демоны) запустите официальный скрипт проверки:

```bash
curl -sSL "https://raw.githubusercontent.com/avego/php3shell/main/check_php_cve.sh" | bash
```

Скрипт автоматически определяет архитектуру ядра:
- **PHP 5.x (Zend Engine 2):** производит аудит по сигнатурам отложенного OOM (`zend_handle_delayed_oom` и стейт-машине `ZEND_OOM_STATE_*`).
- **PHP 7.x & 8.x (Zend Engine 3/4):** проверяет наличие защитной директивы `memory_hard_limit_percent` и функций жесткого лимита памяти.
- Проверяет связки бинарников **CLI**, **CGI** (`php-cgi`) и **FPM** (`php-fpm`).
- Выводит подробный отчёт с цветными индикаторами: **`[SAFE / PATCHED]`** или **`[DANGER / ACTION REQUIRED]`**.

---

## 📊 Матрица версий и статус защиты

| Версия PHP | Расположение в FastPanel | Метод защиты | Статус | Руководство |
|---|---|---|---|---|
| **PHP 5.6.40** | `/opt/php56` | Бэкпорт ядра Zend 2 (`zend_handle_delayed_oom`) | ✅ Защищен | [Мануал PHP 5.6](FASTPANEL_PHP5.6_PATCHING_MANUAL.md) |
| **PHP 7.1.33** | `/opt/php71` | Бэкпорт ядра Zend 3 (`memory_hard_limit_percent`) | ✅ Защищен | [Мануал PHP 7.1](FASTPANEL_PHP7.1_PATCHING_MANUAL.md) |
| **PHP 7.3.33** | `/opt/fphp` | Внутренний PHP панели FastPanel (`fastpanel2-apps`) | ✅ Защищен | [Мануал fphp 7.3](FASTPANEL_FPHP7.3_PATCHING_MANUAL.md) |
| **PHP 7.4.33** | Системный Debian 11 | Нативные `.deb` пакеты (`deb-src`, `dpkg-buildpackage`) | ✅ Защищен | [Мануал PHP 7.4 Debian](FASTPANEL_PHP7.4_DEBIAN11_MANUAL.md) |
| **PHP 8.1.29** | `/opt/php81` | Бэкпорт ядра Zend 4 (`memory_hard_limit_percent`) | ✅ Защищен | [Мануал PHP 8.1](FASTPANEL_PHP8.1_PATCHING_MANUAL.md) |
| **PHP 8.4.27** | `/opt/php84` | Официальный апстрим PHP Group (8.4.5+) | ✅ Защищен из коробки | Встроен в релиз FastPanel |
| **PHP 8.5.12** | `/opt/php85` | Официальный апстрим PHP Group (8.5+) | ✅ Защищен из коробки | Встроен в релиз FastPanel |

---

## 📁 Структура репозитория

```text
├── patch/                                                     # Патчи безопасности и совместимости
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
├── check_php_cve.sh                                          # Скрипт автоматического аудита уязвимостей
└── README.md
```

---

## ⚡ Ключевые принципы совместимости с FastPanel

1. **Обязательная предварительная диагностика:**
   Перед скачиванием исходников с сайта php.net обязательно снимается фактическая подверсия и оригинальные флаги конфигурации:
   ```bash
   /opt/phpXX/bin/php -v
   /opt/phpXX/bin/php -i | grep -i "configure command"
   ```

2. **Сохранение модулей СУБД (`shared,mysqlnd`):**
   FastPanel подключает расширения БД (`mysqli.so`, `pdo_mysql.so`) как **динамические внешние модули (`shared`)** через `/opt/phpXX/conf.d/*.ini`.
   - Нельзя компилировать `mysqli` монолитно в ядро — это приведёт к конфликту повторной загрузки (`Module 'mysqli' already loaded in Unknown`) и ошибке `Couldn't fetch mysqli`.
   - Нельзя отключать MySQL при сборке (`--without-mysql`) — ядро лишится движка `mysqlnd`, и штатные модули FastPanel упадут с фатальной ошибкой `Class 'mysqli' not found`.
   - **Правильное решение (100% совместимость):**
     Ядро компилируется с встроенным движком `mysqlnd`, а драйверы — как разделяемые:
     ```bash
     --enable-mysqlnd \
     --with-mysqli=shared,mysqlnd \
     --with-pdo-mysql=shared,mysqlnd \
     --with-mysql-sock=/var/run/mysqld/mysqld.sock
     ```
     *(Для ветки PHP 5.6 также добавляется `--with-mysql=shared,mysqlnd`)*.

3. **Атомарная установка бинарников (`install -m 755`):**
   Для исключения ошибки `Text file busy` и сбоев работающих веб-воркеров Apache (`mod_fcgid`) замена скомпилированных файлов производится через утилиту `install`:
   ```bash
   install -m 755 sapi/cli/php /opt/phpXX/bin/php
   install -m 755 sapi/cgi/php-cgi /opt/phpXX/bin/php-cgi
   [ -f sapi/fpm/php-fpm ] && install -m 755 sapi/fpm/php-fpm /opt/phpXX/sbin/php-fpm 2>/dev/null || true
   ```

---

## 🔍 Контроль применения патча безопасности (Верификация)

После установки обновлённых бинарников **обязательно** проводится проверка внедрения защитных механизмов:

### Для PHP 7.1, 7.3, 7.4, 8.1 (Zend Engine 3 и 4):
```bash
# 1. Проверка регистрации ядром новой директивы:
/opt/phpXX/bin/php -i | grep memory_hard_limit_percent
# Ожидаемый вывод:
# memory_hard_limit_percent => no value => no value

# 2. Проверка символов ядра в бинарниках:
strings /opt/phpXX/bin/php | grep memory_hard_limit_percent
# Ожидаемый вывод:
# zend_set_memory_hard_limit_percent
# memory_hard_limit_percent
# memory_hard_limit_percent must be >= 100, or -1
```

### Для PHP 5.6 (Zend Engine 2):
```bash
# В ядре 5.6 защита реализована через zend_handle_delayed_oom и стейт-машину ZEND_OOM_STATE_*:
strings /opt/php56/bin/php | grep zend_handle_delayed_oom
# Ожидаемый вывод:
# zend_handle_delayed_oom

strings /opt/php56/bin/php | grep ZEND_OOM_STATE
# Ожидаемый вывод:
# ZEND_OOM_STATE_NONE
# ZEND_OOM_STATE_HANDLING
# ZEND_OOM_STATE_HANDLED
# ZEND_OOM_STATE_PENDING
```

---

## 🛡️ Процедура отката (Rollback)

В случае любых непредвиденных проблем возврат к оригинальной рабочей версии производится мгновенно из сохранённого бэкапа:

```bash
install -m 755 /opt/phpXX.bak/bin/php /opt/phpXX/bin/php
[ -f /opt/phpXX.bak/bin/php-cgi ] && install -m 755 /opt/phpXX.bak/bin/php-cgi /opt/phpXX/bin/php-cgi 2>/dev/null || true
[ -f /opt/phpXX.bak/sbin/php-fpm ] && install -m 755 /opt/phpXX.bak/sbin/php-fpm /opt/phpXX/sbin/php-fpm 2>/dev/null || true

killall -9 php-cgi 2>/dev/null || true
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
systemctl restart phpXX-fpm 2>/dev/null || true
```

---

## 👥 Благодарности и авторство (Credits & Provenance)

- **Оригинальное исправление в upstream PHP (php-src):**
  - **Автор механизма ядра:** **Arnaud Le Blanc** (`arnaud.lb@gmail.com`).
  - **Upstream commit:** `01a40e89fb` (*"Avoid state corruption via bailout"*), официально включённый в PHP 8.2.28+, 8.3.18+, 8.4.5+.
  - **Идентификаторы безопасности:** GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp.

- **Бэкпорт патчей для EOL-версий PHP (5.2 – 8.1):**
  - **Разработка бэкпортов:** Сообщество мейнтейнеров **docker-php**.
  - **Подготовка и публикация автономных патчей:** Разработчик **realhidden** ([gists/realhidden](https://gist.github.com/realhidden)), выполнивший генерацию чистых патчей и регенерацию зависимостей (`zend_vm_execute.h`, `re2c`, `bison`).

- **Адаптация для FastPanel и Debian 11:**
  - **Репозиторий:** [avego/php3shell](https://github.com/avego/php3shell).
  - Адаптация ABI-совместимости модулей FastPanel (динамический `mysqli.so` / `pdo_mysql.so` поверх `mysqlnd`).
  - Разработка эталонного патча и процедуры нативной сборки `.deb` пакетов для системного PHP 7.4 в Debian 11 Bullseye.
  - Адаптация и сборка защищённого окружения для внутренней службы FastPanel `/opt/fphp` (`fastpanel2-apps.service`).
