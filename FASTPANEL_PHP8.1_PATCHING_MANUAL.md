# Инструкция по пропатчиванию и пересборке PHP 8.1 в FastPanel (Debian 11 x86_64)

Данная инструкция описывает процесс закрытия критических уязвимостей **CVE-2026-109618** и **CVE-2026-109619** (RCE через memory_limit bailout / повреждение глобального состояния) для **PHP 8.1** в **FastPanel** с сохранением 100% совместимости с модулями FastPanel (`OPcache`, `mysqli.so`, `pdo_mysql.so`, `redis.so` и др.).

---

## Важные особенности PHP 8.1

1. **Исходный код:**
   - В FastPanel установлена версия PHP 8.1.29.
   - Мы скачиваем исходники `php-8.1.29.tar.gz` (или последнюю версию ветки `php-8.1.34.tar.gz` — патч чистый и применяется без сбоев к обеим).
2. **Конфигурация MySQL в FastPanel:**
   - Движок `mysqlnd` вшит в ядро: `--enable-mysqlnd`
   - Модули СУБД скомпилированы как динамические разделяемые библиотеки:
     `--with-mysqli=shared,mysqlnd`
     `--with-pdo-mysql=shared,mysqlnd`
     `--with-mysql-sock=/var/run/mysqld/mysqld.sock`
3. **Отличия опций сборки PHP 8.x:**
   - В PHP 8.x флаг `--with-libxml-dir` устарел и заменен автоматическим поиском через `pkg-config`.
   - Включается поддержка JIT: `--with-pcre-jit`.

---

## 1. Необходимые пакеты

Убедитесь, что установлены пакеты для сборки:

```bash
apt-get update
apt-get install -y build-essential autoconf automake libtool bison re2c libxml2-dev zlib1g-dev pkg-config psmisc wget curl
```

---

## 2. Проверка установленной версии и создание резервной копии

Перед загрузкой исходников с php.net **обязательно** проверяем точную версию установленного в FastPanel PHP и параметры сборки:

```bash
# 1. Проверяем точную установленную версию PHP:
/opt/php81/bin/php -v
/opt/php81/sbin/php-fpm -v 2>/dev/null || true

# 2. Проверяем оригинальные флаги конфигурации FastPanel:
/opt/php81/bin/php -i | grep -i "configure command"

# 3. Делаем полный бэкап рабочей директории:
cp -a /opt/php81 /opt/php81.bak
```

---

## 3. Загрузка исходников PHP 8.1 и наложение патча

```bash
cd /usr/src
wget https://museum.php.net/php8/php-8.1.29.tar.gz
tar -xzf php-8.1.29.tar.gz
cd php-8.1.29

# Скачиваем патч безопасности для PHP 8.1 из репозитория avego/php3shell
wget -O cve-8.1.patch https://raw.githubusercontent.com/avego/php3shell/main/patch/php-8.1.29-cve-2026-109618-109619.patch
patch -p1 < cve-8.1.patch
```
> **Важное примечание по выводу утилиты `patch`:**
> 
> Успешное применение патча сопровождается сообщениями:
> - `patching file ...`
> - `Hunk #... succeeded at ... (offset ... lines)` или `with fuzz ...` — это **нормально и считается успешным применением** (утилита автоматически сопоставила контекст строк).
> 
> **Критическая ошибка — это появление строк `FAILED` или создание файлов `*.rej`:**
> - Если в выводе есть `Hunk #... FAILED at ...` — патч **НЕ применился** корректно. Компилировать в таком случае нельзя!
> - Проверить отсутствие ошибок после наложения можно командой:
>   ```bash
>   find . -name "*.rej"
>   ```
>   *(Команда должна вернуть пустой вывод)*.


---

## 4. Конфигурация для сборки (FastPanel ABI)

```bash
./configure \
  --prefix=/opt/php81 \
  --with-config-file-path=/opt/php81/etc/ \
  --with-config-file-scan-dir=/opt/php81/conf.d \
  --with-mysql-sock=/var/run/mysqld/mysqld.sock \
  --enable-cgi \
  --enable-cli \
  --enable-fpm \
  --disable-rpath \
  --disable-debug \
  --without-sqlite3 \
  --without-pdo-sqlite \
  --enable-mysqlnd \
  --with-mysqli=shared,mysqlnd \
  --with-pdo-mysql=shared,mysqlnd \
  --with-zlib \
  --with-pcre-jit
```

---

## 5. Компиляция целевых SAPI

Компилируем три исполняемых файла ядра (`php-cgi` для Apache mod_fcgid, `php` для CLI, `php-fpm`):

```bash
make -j$(nproc) sapi/cgi/php-cgi sapi/cli/php sapi/fpm/php-fpm
```

---

## 6. Атомарная замена бинарников и перезапуск веб-серверов

```bash
# 1. Заменяем бинарники через install (избегаем Text file busy)
install -m 755 sapi/cli/php /opt/php81/bin/php
install -m 755 sapi/cgi/php-cgi /opt/php81/bin/php-cgi
[ -f sapi/fpm/php-fpm ] && install -m 755 sapi/fpm/php-fpm /opt/php81/sbin/php-fpm 2>/dev/null || true

# 2. Убиваем зависшие старые воркеры php-cgi
killall -9 php-cgi 2>/dev/null || true

# 3. Перезапускаем веб-серверы и PHP-FPM
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
systemctl restart php81-fpm 2>/dev/null || true
```

---

## 7. Проверка работоспособности

```bash
# 1. Проверяем версию и дату сборки (должен подхватиться OPcache):
/opt/php81/bin/php -v

# 2. Проверяем модули MySQL:
/opt/php81/bin/php -m | grep -i mysql
# Ожидаемый вывод:
#   mysqli
#   mysqlnd
#   pdo_mysql

# 3. Проверяем доступность класса mysqli:
/opt/php81/bin/php -r "var_dump(class_exists('mysqli'));"
# Ожидаемый вывод: bool(true)
```

Откройте в браузере сайты, использующие PHP 8.1, и проверьте их работу.

---

## 8. Откат изменений в случае непредвиденных проблем

```bash
install -m 755 /opt/php81.bak/bin/php /opt/php81/bin/php
install -m 755 /opt/php81.bak/bin/php-cgi /opt/php81/bin/php-cgi
[ -f /opt/php81.bak/sbin/php-fpm ] && install -m 755 /opt/php81.bak/sbin/php-fpm /opt/php81/sbin/php-fpm 2>/dev/null || true
killall -9 php-cgi 2>/dev/null || true
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
systemctl restart php81-fpm 2>/dev/null || true
```

---

## 👥 Благодарности и авторство (Credits & Provenance)

- **Оригинальное исправление в upstream PHP (php-src):**
  - **Автор механизма ядра:** **Arnaud Le Blanc** (`arnaud.lb@gmail.com`).
  - **Upstream commit:** `01a40e89fb` (*"Avoid state corruption via bailout"*), официально вошедший в PHP 8.2.35+, 8.3.18+, 8.4.5+.
  - **Идентификаторы безопасности:** GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp.

- **Бэкпорт патчей для EOL-версий PHP (5.2 – 8.1):**
  - **Разработка бэкпортов:** Сообщество мейнтейнеров **docker-php**.
  - **Подготовка и публикация автономных патчей:** Разработчик **realhidden** (https://gist.github.com/realhidden), подготовивший чистые диффы и регенерацию заголовков/парсеров (`zend_vm_execute.h`, `re2c`, `bison`).

- **Адаптация для FastPanel:**
  - **Репозиторий:** [avego/php3shell](https://github.com/avego/php3shell).
  - Решение проблемы ABI-совместимости модулей FastPanel (сохранение динамической загрузки `mysqli.so` / `pdo_mysql.so` поверх ядра с включенным `mysqlnd`).

