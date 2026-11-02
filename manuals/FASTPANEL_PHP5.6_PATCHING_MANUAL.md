# Инструкция по пропатчиванию и пересборке PHP в FastPanel (Debian 11 x86_64)

Данная инструкция описывает процесс закрытия критических уязвимостей (включая **CVE-2026-109618** и **CVE-2026-109619**) в устаревших версиях PHP (5.3, 5.4, 5.6 и других) в окружении **FastPanel** без потери совместимости со штатными модулями, расширениями и энкодерами (`ionCube Loader`, `Zend Guard Loader`, `Zend OPcache`, `mysqli`, `pdo_mysql` и др.).

---

## 1. Архитектура PHP в FastPanel и суть проблемы

1. **Расположение:**
   - Префикс: `/opt/phpXX` (например, `/opt/php56`).
   - Конфигурация: `/opt/phpXX/etc/php.ini` и `/opt/phpXX/conf.d/*.ini`.
   - Модули (`.so`): `/opt/phpXX/lib/php/extensions/no-debug-non-zts-XXXXXXXX/`.
   - Исполняемые файлы: `/opt/phpXX/bin/php`, `/opt/phpXX/bin/php-cgi`, `/opt/phpXX/sbin/php-fpm`.

2. **Особенности FastPanel:**
   - Веб-сервер Apache запускает скрипты сайтов через **`mod_fcgid`**, вызывая бинарник `/opt/phpXX/bin/php-cgi`.
   - Модули баз данных (`mysql.so`, `mysqli.so`, `pdo_mysql.so`) в FastPanel подключаются **динамически** как `shared` через ini-файлы в каталоге `/opt/phpXX/conf.d/`.
   - Если скомпилировать PHP с жестко вшитым `mysqli` в ядро, возникает конфликт двойной загрузки:
     `PHP Warning: Module 'mysqli' already loaded in Unknown on line 0` и `Couldn't fetch mysqli`.
   - Если же отключить MySQL вообще (`--without-mysql --without-mysqli`), из ядра вырезается движок `mysqlnd`, и штатные модули FastPanel не могут запуститься:
     `PHP Fatal error: Class 'mysqli' not found`.

3. **Правильное решение (100% совместимость):**
   - Включаем встроенный движок **`mysqlnd`** в ядре: `--enable-mysqlnd`.
   - Драйверы указываем как разделяемые: `--with-mysql=shared,mysqlnd --with-mysqli=shared,mysqlnd --with-pdo-mysql=shared,mysqlnd`.
   - Используем флаги путей FastPanel: `--prefix=/opt/phpXX --with-config-file-path=/opt/phpXX/etc --with-config-file-scan-dir=/opt/phpXX/conf.d`.
   - Заменяем скомпилированные бинарники (`php`, `php-cgi`, `php-fpm`) через утилиту `install` (чтобы избежать ошибки `Text file busy` от работающих процессов Apache).

---

## 2. Необходимые пакеты для сборки

Перед началом сборки убедитесь, что на сервере установлены базовые библиотеки:

```bash
apt-get update
apt-get install -y build-essential autoconf libxml2-dev zlib1g-dev libssl-dev re2c psmisc wget curl
```

---

## 3. Пошаговый алгоритм на примере PHP 5.6.40

### Шаг 1. Проверка установленной версии и создание резервной копии

Перед скачиванием исходников с php.net **обязательно** проверяем точную версию установленного в FastPanel PHP и флаги сборки:

```bash
# 1. Проверяем точную установленную версию PHP:
/opt/php56/bin/php -v
/opt/php56/sbin/php-fpm -v 2>/dev/null || true

# 2. Проверяем оригинальные флаги конфигурации FastPanel:
/opt/php56/bin/php -i | grep -i "configure command"

# 3. Делаем полный бэкап рабочей директории:
cp -a /opt/php56 /opt/php56.bak
```

### Шаг 2. Загрузка и распаковка исходников

```bash
cd /usr/src
wget https://museum.php.net/php5/php-5.6.40.tar.gz
tar -xzf php-5.6.40.tar.gz
cd php-5.6.40
```

### Шаг 3. Применение патча безопасности (CVE) и совместимости с OpenSSL 1.1

1. **Скачиваем и накладываем патч безопасности от уязвимостей CVE-2026-109618 и CVE-2026-109619:**
```bash
wget -O cve.patch https://raw.githubusercontent.com/avego/php2shell/main/patch/php-5.6.40-cve-2026-109618-109619.patch
patch -p1 < cve.patch
```

2. **Совместимость с OpenSSL 1.1 (Debian 11 / FastPanel):**
> **Важнейшая особенность сборки PHP 5.6 на современных дистрибутивах (Debian 10/11):**  
> Исходный PHP 5.6 разрабатывался во времена OpenSSL 1.0. На Debian 11 установлена системная библиотека OpenSSL 1.1.1, в которой внутренние структуры (`EVP_PKEY`, `RSA`, `DSA`, `DH`) стали непрозрачными (opaque).  
> Без адаптации `ext/openssl` компиляция завершится ошибкой: `invalid use of incomplete typedef 'EVP_PKEY'` и `storage size of 'md_ctx' isn't known`, а если собрать без `--with-openssl`, в PHP 5.6 пропадут сокетные транспорты `ssl://` и `tls://` (перестанет работать отправка почты по SSL/TLS на порт 465/587 и исходящие HTTPS-запросы: `stream_socket_client(): unable to connect to ssl://...`).  
> В репозитории FastPanel используется официальный бэкпорт OpenSSL 1.1.

Загружаем обновленные файлы расширения `openssl` из нашего репозитория:
```bash
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/patch/php56-openssl11/openssl.c" -o ext/openssl/openssl.c
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/patch/php56-openssl11/xp_ssl.c" -o ext/openssl/xp_ssl.c
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/patch/php56-openssl11/php_openssl.h" -o ext/openssl/php_openssl.h
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


### Шаг 4. Конфигурирование с флагами FastPanel

Очищаем дерево исходников и запускаем `./configure` со всеми необходимыми опциями ядра FastPanel (включая OpenSSL и zlib):

```bash
make clean

./configure \
  --prefix=/opt/php56 \
  --with-config-file-path=/opt/php56/etc \
  --with-config-file-scan-dir=/opt/php56/conf.d \
  --with-mysql-sock=/var/run/mysqld/mysqld.sock \
  --enable-cgi \
  --enable-cli \
  --enable-fpm \
  --disable-rpath \
  --disable-debug \
  --disable-phar \
  --enable-mysqlnd \
  --with-mysql=shared,mysqlnd \
  --with-mysqli=shared,mysqlnd \
  --with-pdo-mysql=shared,mysqlnd \
  --with-openssl \
  --with-zlib \
  --with-libxml-dir=/usr
```

### Шаг 5. Компиляция только необходимых бинарников

Компилируем три целевых SAPI:

```bash
make -j$(nproc) sapi/cgi/php-cgi sapi/cli/php sapi/fpm/php-fpm
```

### Шаг 6. Атомарная установка и перезапуск сервисов

Чтобы веб-сервер не выдал ошибку `Text file busy`, бинарники копируются с помощью утилиты `install`:

```bash
# 1. Установка скомпилированных бинарников на место:
install -m 755 sapi/cli/php /opt/php56/bin/php
install -m 755 sapi/cgi/php-cgi /opt/php56/bin/php-cgi
[ -f sapi/fpm/php-fpm ] && install -m 755 sapi/fpm/php-fpm /opt/php56/sbin/php-fpm 2>/dev/null || true

# 2. Остановка зависших процессов FastCGI:
killall -9 php-cgi 2>/dev/null || true

# 3. Перезапуск веб-серверов:
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
systemctl restart php56-fpm 2>/dev/null || true
```

### Шаг 7. Проверка применения патча безопасности (CVE) и работоспособности

#### 1. Проверка применения патча безопасности (защита от CVE-2026-109618 / CVE-2026-109619):

> **Особенность архитектуры PHP 5.6 (Zend Engine 2):**  
> В ядре PHP 5.6 защита от повреждения памяти при OOM реализована через механизм отложенного перехвата **`zend_handle_delayed_oom`** и стейт-машину **`ZEND_OOM_STATE_*`** с автоматическим жестким лимитом памяти (200% или +1G). Поэтому проверка производится по символам отложенного OOM:

```bash
# Проверяем наличие защитного механизма zend_handle_delayed_oom в бинарниках:
strings /opt/php56/bin/php | grep zend_handle_delayed_oom
strings /opt/php56/bin/php-cgi | grep zend_handle_delayed_oom
[ -f /opt/php56/sbin/php-fpm ] && strings /opt/php56/sbin/php-fpm | grep zend_handle_delayed_oom || true

# Ожидаемый вывод:
# zend_handle_delayed_oom
```

Дополнительно можно проверить стейт-машину ядра:
```bash
strings /opt/php56/bin/php | grep ZEND_OOM_STATE
# Ожидаемый вывод:
# ZEND_OOM_STATE_NONE
# ZEND_OOM_STATE_HANDLING
# ZEND_OOM_STATE_HANDLED
# ZEND_OOM_STATE_PENDING
```

#### 2. Проверка работоспособности модулей, SSL-транспортов и сайтов:
```bash
# 1. Проверка даты сборки и загрузки энкодеров (ionCube, OPcache, Zend Guard):
/opt/php56/bin/php -v

# 2. Проверка подключения модулей MySQL и OpenSSL:
/opt/php56/bin/php -m | grep -E "mysql|openssl"
# Должно вывести:
#   mysql
#   mysqli
#   mysqlnd
#   openssl
#   pdo_mysql

# 3. Проверка доступности класса mysqli:
/opt/php56/bin/php -r "var_dump(class_exists('mysqli'));"
# Должно вернуть: bool(true)

# 4. Проверка доступности потоковых транспортов SSL/TLS:
/opt/php56/bin/php -r "var_dump(stream_get_transports());"
# Должно содержать элементы 'ssl', 'tls', 'tlsv1.0'...'tlsv1.3'
```

Откройте в браузере сайты, использующие данную версию PHP, и убедитесь, что страницы открываются быстро и без ошибок базы данных.

---

## 4. Откат изменений в случае непредвиденных проблем

Если возникли неполадки, возврат к оригинальной версии выполняется одной командой:

```bash
install -m 755 /opt/php56.bak/bin/php /opt/php56/bin/php
install -m 755 /opt/php56.bak/bin/php-cgi /opt/php56/bin/php-cgi
[ -f /opt/php56.bak/sbin/php-fpm ] && install -m 755 /opt/php56.bak/sbin/php-fpm /opt/php56/sbin/php-fpm 2>/dev/null || true
killall -9 php-cgi 2>/dev/null || true
systemctl restart apache2
systemctl restart nginx 2>/dev/null || true
systemctl restart php56-fpm 2>/dev/null || true
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
  - **Репозиторий:** [avego/php2shell](https://github.com/avego/php2shell).
  - Решение проблемы ABI-совместимости модулей FastPanel (сохранение динамической загрузки `mysqli.so` / `pdo_mysql.so` поверх ядра с включенным `mysqlnd`).
