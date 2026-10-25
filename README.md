# FastPanel PHP Security Patching (CVE-2026-109618 & CVE-2026-109619)

Репозиторий содержит патчи безопасности и пошаговые руководства по компиляции и устранению критических уязвимостей **CVE-2026-109618** и **CVE-2026-109619** в устаревших (EOL) и актуальных версиях PHP, работающих под управлением панели управления **FastPanel** (Debian 11 x86_64, Apache `mod_fcgid`, PHP-FPM).

---

## 🔒 Описание уязвимостей

- **CVE-2026-109618 (RCE via OOM corruption):** Превышение лимита оперативной памяти (`memory_limit`) приводило к вызову `longjmp` внутри аллокатора памяти, разрушая структуры данных ядра PHP и позволяя злоумышленнику удаленно выполнить произвольный код через специально сформированный запрос (multipart, x-www-form-urlencoded).
- **CVE-2026-109619 (RCE via stale global state):** Уязвимость, связанная с разрушением глобального состояния исполнителя Zend Engine и парсеров сессий (`session.upload_progress`).

Upstream PHP исправил эти проблемы начиная с версий **8.2.35+**, оставив ветки **PHP 5.2 – 8.1** уязвимыми (EOL). Данный репозиторий содержит портированные бэкпорты официального исправления ядра для всех версий.

---

## 📁 Структура репозитория

```text
├── patch/                                        # Патчи безопасности
│   ├── php-5.2.17-cve-2026-109618-109619.patch
│   ├── php-5.3.29-cve-2026-109618-109619.patch
│   ├── php-5.4.45-cve-2026-109618-109619.patch
│   ├── php-5.6.40-cve-2026-109618-109619.patch
│   ├── php-7.0.33-cve-2026-109618-109619.patch
│   ├── php-7.1.33-cve-2026-109618-109619.patch
│   ├── php-7.2.34-cve-2026-109618-109619.patch
│   ├── php-7.3.33-cve-2026-109618-109619.patch
│   ├── php-7.4.33-cve-2026-109618-109619.patch
│   ├── php-8.0.30-cve-2026-109618-109619.patch
│   └── php-8.1.34-cve-2026-109618-109619.patch
├── FASTPANEL_PHP5.6_PATCHING_MANUAL.md           # Руководство для PHP 5.6
├── FASTPANEL_PHP7.1_PATCHING_MANUAL.md           # Руководство для PHP 7.1
└── README.md
```

---

## ⚡ Ключевой принцип совместимости с FastPanel

FastPanel компилирует расширения СУБД (`mysqli.so`, `pdo_mysql.so`) как **динамические внешние модули (`shared`)**, подключаемые через каталог `/opt/phpXX/conf.d/`.

1. **Нельзя компилировать `mysqli` монолитно в ядро:** это вызовет конфликт повторной загрузки (`Module 'mysqli' already loaded in Unknown`) и фатальную ошибку `mysqli::query(): Couldn't fetch mysqli`.
2. **Нельзя полностью отключать MySQL при сборке ядра (`--without-mysql`):** ядро лишится драйвера `mysqlnd`, и штатные модули FastPanel упадут с ошибкой `Fatal error: Class 'mysqli' not found`.
3. **Решение со 100% совместимостью:**
   Ядро собирается с встроенным движком `mysqlnd` и модулями как `shared`:
   ```bash
   --enable-mysqlnd \
   --with-mysqli=shared,mysqlnd \
   --with-pdo-mysql=shared,mysqlnd \
   --with-mysql-sock=/var/run/mysqld/mysqld.sock
   ```
   *(Для версий PHP 5.x также добавляется `--with-mysql=shared,mysqlnd`)*.

---

## 🚀 Быстрый старт (Общий алгоритм)

### 1. Подготовка окружения
```bash
apt-get update
apt-get install -y build-essential autoconf automake libtool bison re2c libxml2-dev zlib1g-dev psmisc wget curl
```

### 2. Резервное копирование
```bash
cp -a /opt/phpXX /opt/phpXX.bak
```

### 3. Сборка и наложение патча
```bash
cd /usr/src
# Скачиваем архив исходников соответствующей версии
wget https://museum.php.net/phpX/php-X.X.XX.tar.gz
tar -xzf php-X.X.XX.tar.gz
cd php-X.X.XX

# Применяем патч из репозитория:
wget -O cve.patch https://raw.githubusercontent.com/avego/php3shell/main/patch/php-X.X.XX-cve-2026-109618-109619.patch
patch -p1 < cve.patch

# Конфигурация и компиляция SAPI:
./configure --prefix=/opt/phpXX ...
make -j$(nproc) sapi/cgi/php-cgi sapi/cli/php sapi/fpm/php-fpm
```

### 4. Атомарная замена и перезапуск
```bash
install -m 755 sapi/cli/php /opt/phpXX/bin/php
install -m 755 sapi/cgi/php-cgi /opt/phpXX/bin/php-cgi
[ -f sapi/fpm/php-fpm ] && install -m 755 sapi/fpm/php-fpm /opt/phpXX/sbin/php-fpm 2>/dev/null || true

killall -9 php-cgi 2>/dev/null || true
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
```

---

## 📖 Подробные инструкции по версиям

- [Инструкция для PHP 5.6.40](FASTPANEL_PHP5.6_PATCHING_MANUAL.md)
- [Инструкция для PHP 7.1.33](FASTPANEL_PHP7.1_PATCHING_MANUAL.md)
- [Инструкция для PHP 8.1.29](FASTPANEL_PHP8.1_PATCHING_MANUAL.md)

---

## 🛡️ Откат к оригинальным бинарникам

В случае непредвиденных проблем возврат к оригинальной версии осуществляется мгновенно:

```bash
install -m 755 /opt/phpXX.bak/bin/php /opt/phpXX/bin/php
install -m 755 /opt/phpXX.bak/bin/php-cgi /opt/phpXX/bin/php-cgi
[ -f /opt/phpXX.bak/sbin/php-fpm ] && install -m 755 /opt/phpXX.bak/sbin/php-fpm /opt/phpXX/sbin/php-fpm 2>/dev/null || true
killall -9 php-cgi 2>/dev/null || true
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
```

---

## 👥 Благодарности и авторство (Credits & Provenance)

- **Оригинальное исправление в upstream PHP (php-src):**
  - **Автор механизма ядра:** **Arnaud Le Blanc** (`arnaud.lb@gmail.com`).
  - **Upstream commit:** `01a40e89fb` (*"Avoid state corruption via bailout"*), официально вошедший в PHP 8.2.35+, 8.3.18+, 8.4.5+.
  - **Идентификаторы безопасности:** GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp.

- **Бэкпорт патчей для EOL-версий PHP (5.2 – 8.1):**
  - **Разработка бэкпортов:** Сообщество мейнтейнеров **docker-php**.
  - **Подготовка и публикация автономных патчей:** Разработчик **realhidden** ([gists/realhidden](https://gist.github.com/realhidden)), подготовивший чистые диффы и регенерацию заголовков/парсеров (`zend_vm_execute.h`, `re2c`, `bison`).

- **Адаптация для FastPanel:**
  - **Репозиторий:** [avego/php3shell](https://github.com/avego/php3shell).
  - Решение проблемы ABI-совместимости модулей FastPanel (сохранение динамической загрузки `mysqli.so` / `pdo_mysql.so` поверх ядра с включенным `mysqlnd`).

