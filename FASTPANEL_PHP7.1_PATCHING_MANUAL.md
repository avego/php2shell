# Инструкция по пропатчиванию и пересборке PHP 7.1.33 в FastPanel (Debian 11 x86_64)

Данная инструкция описывает закрытие критических уязвимостей **CVE-2026-109618** и **CVE-2026-109619** (RCE через memory_limit bailout / повреждение глобального состояния) для **PHP 7.1.33** в **FastPanel** с сохранением 100% совместимости с модулями FastPanel (`ionCube Loader`, `OPcache`, `mysqli.so`, `pdo_mysql.so` и др.).

---

## Важные особенности PHP 7.1

1. Патч для PHP 7.1 модифицирует лексеры/парсеры:
   - Включает регенерированный `Zend/zend_vm_execute.h`.
   - Требует генерации файлов через `re2c`: `ext/standard/var_unserializer.c` и `ext/standard/url_scanner_ex.c`.
   - Если `re2c` установлен (`apt-get install -y re2c`), система автоматически их обновит или скомпилирует без сбоев.
2. Конфигурация MySQL в точности как у FastPanel:
   - `--enable-mysqlnd`
   - `--with-mysqli=shared,mysqlnd`
   - `--with-pdo-mysql=shared,mysqlnd`
   - `--with-mysql-sock=/var/run/mysqld/mysqld.sock`
   *(Заметьте: в ветке PHP 7.x устаревшее расширение `ext/mysql` уже удалено из ядра PHP, используются только `mysqli` и `pdo_mysql`).*

---

## 1. Необходимые пакеты

Убедитесь, что установлены пакеты для сборки:

```bash
apt-get update
apt-get install -y build-essential autoconf automake libtool bison re2c libxml2-dev zlib1g-dev psmisc wget curl
```

---

## 2. Проверка установленной версии и создание резервной копии

Перед загрузкой исходников с php.net **обязательно** проверяем точную версию установленного в FastPanel PHP и параметры сборки:

```bash
# 1. Проверяем точную установленную версию PHP:
/opt/php71/bin/php -v
/opt/php71/sbin/php-fpm -v 2>/dev/null || true

# 2. Проверяем оригинальные флаги конфигурации FastPanel:
/opt/php71/bin/php -i | grep -i "configure command"

# 3. Делаем полный бэкап рабочей директории:
cp -a /opt/php71 /opt/php71.bak
```

---

## 3. Загрузка исходников PHP 7.1.33 и наложение патча

```bash
cd /usr/src
wget https://museum.php.net/php7/php-7.1.33.tar.gz
tar -xzf php-7.1.33.tar.gz
cd php-7.1.33

# Скачиваем патч для PHP 7.1.33
wget -O cve-7.1.patch https://raw.githubusercontent.com/avego/php3shell/main/patch/php-7.1.33-cve-2026-109618-109619.patch
patch -p1 < cve-7.1.patch
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
make clean

./configure \
  --prefix=/opt/php71 \
  --with-config-file-path=/opt/php71/etc \
  --with-config-file-scan-dir=/opt/php71/conf.d \
  --with-mysql-sock=/var/run/mysqld/mysqld.sock \
  --enable-cgi \
  --enable-cli \
  --enable-fpm \
  --disable-rpath \
  --disable-debug \
  --disable-phar \
  --enable-mysqlnd \
  --with-mysqli=shared,mysqlnd \
  --with-pdo-mysql=shared,mysqlnd \
  --with-openssl \
  --with-zlib \
  --with-libxml-dir=/usr
```

---

## 5. Компиляция целевых SAPI

Компилируем исполняемые файлы ядра (`php-cgi` для Apache mod_fcgid, `php` для CLI, `php-fpm`):

```bash
make -j$(nproc) sapi/cgi/php-cgi sapi/cli/php sapi/fpm/php-fpm
```

---

## 6. Атомарная замена бинарников и перезапуск веб-серверов

```bash
# 1. Заменяем бинарники через install (избегаем Text file busy)
install -m 755 sapi/cli/php /opt/php71/bin/php
install -m 755 sapi/cgi/php-cgi /opt/php71/bin/php-cgi
[ -f sapi/fpm/php-fpm ] && install -m 755 sapi/fpm/php-fpm /opt/php71/sbin/php-fpm 2>/dev/null || true

# 2. Убиваем зависшие старые воркеры mod_fcgid
killall -9 php-cgi 2>/dev/null || true

# 3. Перезапускаем веб-серверы и службы
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
systemctl restart php71-fpm 2>/dev/null || true
```

---

## 7. Проверка применения патча безопасности (CVE) и работоспособности

### 1. Проверка применения патча безопасности (защита от CVE-2026-109618 / CVE-2026-109619):
```bash
# 1. Проверяем наличие защитной директивы в ядре PHP:
/opt/php71/bin/php -i | grep memory_hard_limit_percent
/opt/php71/bin/php-cgi -i | grep memory_hard_limit_percent

# Ожидаемый вывод:
# memory_hard_limit_percent => no value => no value

# 2. Проверяем наличие защитных функций ядра в скомпилированных бинарниках:
strings /opt/php71/bin/php | grep memory_hard_limit_percent
strings /opt/php71/bin/php-cgi | grep memory_hard_limit_percent
[ -f /opt/php71/sbin/php-fpm ] && strings /opt/php71/sbin/php-fpm | grep memory_hard_limit_percent || true

# Ожидаемый вывод:
# zend_set_memory_hard_limit_percent
# memory_hard_limit_percent
```

### 2. Проверка работоспособности модулей, OpenSSL и сайтов:
```bash
# 1. Проверяем версию и дату сборки (должен подхватиться ionCube и OPcache):
/opt/php71/bin/php -v

# 2. Проверяем модули MySQL и OpenSSL:
/opt/php71/bin/php -m | grep -E "mysql|openssl"
# Ожидаемый вывод:
#   mysqli
#   mysqlnd
#   openssl
#   pdo_mysql

# 3. Проверяем доступность класса mysqli:
/opt/php71/bin/php -r "var_dump(class_exists('mysqli'));"
# Ожидаемый вывод: bool(true)

# 4. Проверяем сокетные транспорты SSL/TLS:
/opt/php71/bin/php -r "var_dump(stream_get_transports());"
# Должно содержать 'ssl' и 'tls'
```

После этого проверьте в браузере сайты, работающие на PHP 7.1.

---

## 8. Откат изменений в случае сбоя

```bash
install -m 755 /opt/php71.bak/bin/php /opt/php71/bin/php
install -m 755 /opt/php71.bak/bin/php-cgi /opt/php71/bin/php-cgi
[ -f /opt/php71.bak/sbin/php-fpm ] && install -m 755 /opt/php71.bak/sbin/php-fpm /opt/php71/sbin/php-fpm 2>/dev/null || true
killall -9 php-cgi 2>/dev/null || true
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
systemctl restart php71-fpm 2>/dev/null || true
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
