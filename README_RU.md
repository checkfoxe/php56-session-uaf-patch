# Бэкпорт безопасности для PHP 5.6 — CVE-2026-109618 / CVE-2026-109619

[English version](README.md) | Русский

В этом репозитории собраны бэкпорт-патчи ядра, технический анализ и практические меры защиты для серверов на **PHP 5.6.x** в связи с публикацией критических уязвимостей от 21 октября 2026 года:

* **CVE-2026-109619** (CVSS 9.2): Сохранение несброшенного глобального состояния (stale global state) и Use-After-Free между последовательными запросами долгоживущего рабочего процесса (подтверждённый вектор воспроизведения — `session.upload_progress`).
* **CVE-2026-109618** (CVSS 9.2): Повреждение внутренних структур аллокатора кучи Zend Engine при аварийной нехватке памяти (OOM / `zend_bailout`).

> [!IMPORTANT]
> **Статус EOL и область применения:** Официальная поддержка ветки PHP 5.6 прекращена сообществом в декабре 2018 года (End-of-Life). Разработчики upstream PHP не выпускают официальных обновлений для 5.6. Этот репозиторий представляет собой бэкпорт upstream-исправлений, адаптированный для архитектуры Zend Engine 2. Единственным фундаментальным решением остаётся плановый переход на поддерживаемые версии (**PHP 8.2+ / 8.3+**).

---

## Архитектура и механика уязвимостей

### CVE-2026-109619: Несброшенное состояние воркера и межзапросный UAF

Первопричина CVE-2026-109619 заключается в жизненном цикле глобальных структур в долгоживущих процессах веб-сервера (`php-fpm`, Apache `mod_php`/`prefork`):

```text
Данные запроса (request-owned) -> Воркер-глобальный указатель -> Аварийный bailout ->
Освобождение кучи запроса -> Висячий указатель сохраняется в воркере ->
Тот же воркер получает следующий запрос -> Разыменование адреса освобождённой памяти ->
Состояние Use-After-Free / повреждение памяти
```

1. **Инициализация парсера:** При обработке входящего запроса `multipart/form-data` с полем `PHP_SESSION_UPLOAD_PROGRESS`, функция `php_session_rfc1867_callback` (`ext/session/session.c`) выделяет структуру отслеживания в куче текущего запроса и сохраняет её адрес в глобальной переменной модуля `PS(rfc1867_progress)`.
2. **Аварийный сброс (Bailout):** При исчерпании лимита памяти, таймауте выполнения или обрыве сетевого соединения ядро выполняет `zend_bailout()` (`longjmp`), минуя стандартные завершающие события парсера (`MULTIPART_EVENT_END`).
3. **Сохранение висячего указателя:** Поскольку явный сброс указателя `PS(rfc1867_progress)` отсутствовал как на старте запроса (`RINIT`), так и в обработчике аварийного завершения (`RSHUTDOWN`), рабочий процесс воркера сохраняет указатель на уже освобождённую память.
4. **Межзапросное разыменование:** При поступлении следующего клиентского запроса в этот же воркер обработка формы или закрытие сессии обращается по невалидному адресу, вызывая Use-After-Free.

### CVE-2026-109618: Повреждение списков аллокатора кучи при OOM

При исчерпании `memory_limit` глубоко внутри операций выделения памяти ядро Zend Engine 2 производило прямой вызов `zend_bailout()`. Резкий раскрут стека прерывал обновление связных списков и корзин свободных блоков аллокатора `zend_alloc.c`, приводя к порче внутренних структур управления кучей для последующих операций в этом процессе.

---

## Иерархия решений

### Уровень 1: Полное обновление (Рекомендуется)
Миграция на поддерживаемую ветку (**PHP 8.2+ / 8.3+**), содержащую официальные исправления от команды PHP. Это единственный способ устранить обе уязвимости на корневом уровне.

### Уровень 2: Бэкпорт-патч и пересборка (Для legacy PHP 5.6)
Применение C-патча к исходному коду PHP 5.6 и перекомпиляция:

| Файл патча | Назначение | Затрагиваемые компоненты | Для каких задач |
| :--- | :--- | :--- | :--- |
| **`patches/php-5.6.x-full-cve-2026-109618-109619.patch`** *(Рекомендуемый)* | Полный бэкпорт ядра | 13 файлов: `zend_alloc.c` (`zend_mm_safe_error_ex`), `SAPI.c`, `main.c`, `rfc1867.c`, `session.c` | Боевые серверы, требующие комплексной защиты как от повреждения кучи при OOM, так и от несброшенных состояний воркера. |
| **`patches/php-5.6.x-session-upload-progress-uaf.patch`** | Точечный патч сессий | `ext/session/session.c` | Минимальное вмешательство; изолирует жизненный цикл `session.upload_progress` и добавляет NULL guards. |

#### Стратегия Upstream EOL в сравнении с данным бэкпортом
В официальной mitigation-стратегии для EOL-версий механизм `session.upload_progress` отключается, что устраняет соответствующий путь выполнения в сессиях, в то время как изменения для CVE-2026-109618 адресованы небезопасной обработке OOM/bailout в менеджере памяти Zend. Представленный бэкпорт сохраняет функциональность `session.upload_progress` за счёт явного управления состояниями жизненного цикла (`RINIT`, `RSHUTDOWN`, `GINIT`) и проверок `if (!progress) break;`, одновременно перенося исправления безопасности в PHP 5.6.

### Уровень 3: Конфигурационная мера (Без пересборки / Без root)
Отключение механизма отслеживания загрузки на уровне настроек веб-сервера.

> [!WARNING]
> **Область действия Уровня 3:**
> Отключение директивы `session.upload_progress` нейтрализует подтверждённый вектор воспроизведения для **CVE-2026-109619**.  
> Это **НЕ исправляет** повреждение аллокатора при OOM (**CVE-2026-109618**). Настройку следует рассматривать как экстренную меру снижения рисков на период подготовки сборки или миграции.

---

## Настройка конфигурационной защиты (Уровень 3)

### PHP-FPM (Рекомендуется при использовании FastCGI)

В конфигурационном файле пула PHP-FPM (например, `/etc/php/5.6/fpm/pool.d/www.conf`):

```ini
; Отключение уязвимого механизма отслеживания прогресса загрузки
php_admin_flag[session.upload_progress.enabled] = off
```

Перезагрузка пула:
```bash
systemctl reload php5.6-fpm
```

### Apache (`.htaccess` / `httpd.conf`)

```apache
# 1. Отключение уязвимой директивы в модуле PHP
<IfModule mod_php5.c>
    php_flag session.upload_progress.enabled off
</IfModule>

# 2. Фильтрация подозрительных запросов на уровне стартовой строки и query string
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{THE_REQUEST} (PHP_SESSION_UPLOAD_PROGRESS|upload_progress) [NC,OR]
    RewriteCond %{QUERY_STRING} (PHP_SESSION_UPLOAD_PROGRESS|upload_progress) [NC]
    RewriteRule .* - [F,L]
</IfModule>
```

> [!NOTE]
> `RewriteCond %{THE_REQUEST}` инспектирует только строку запроса и параметры URL. Тело POST-запроса формата `multipart/form-data` модуль mod_rewrite не разбирает. Поэтому решающей мерой является именно `session.upload_progress.enabled = off`, а правила mod_rewrite служат эвристическим внешним барьером.

### Nginx

```nginx
location ~ \.php$ {
    include fastcgi_params;
    fastcgi_param PHP_VALUE "session.upload_progress.enabled=off";
}

# Блокировка попыток передачи сигнатур через query string
if ($query_string ~* "PHP_SESSION_UPLOAD_PROGRESS|upload_progress") {
    return 403;
}
```

> **Примечание о стандартных загрузках:** Стандартная обработка файлов через формы (`$_FILES`, загрузка изображений, документов, каталогов, CSV/Excel) не задействует `session.upload_progress` и продолжает функционировать штатно.

---

## Сборка из исходников (Уровень 2)

### Ручное наложение патча

```bash
cd php-5.6.40
# Применение комплексного патча (или точечного патча сессий)
patch -p1 < patches/php-5.6.x-full-cve-2026-109618-109619.patch

./configure --enable-fpm --enable-session [ваши_параметры]
make -j$(nproc)
make test TESTS="ext/session/tests/"
make install
```

### Сборка через Docker (Ubuntu / PHP-FPM)

В папке `build/` размещён воспроизводимый [Dockerfile](build/Dockerfile):

```bash
docker build -t php56-patched -f build/Dockerfile .
```

### Регламент сборки и обновления для Debian 8 (Jessie) / Apache mod_php

Для legacy-систем на базе Debian 8 (Jessie) с модулем Apache `libapache2-mod-php5` используйте следующий пошаговый регламент, исключающий риск даунтайма.

#### 1. Обязательный бэкап перед началом
Перед любыми действиями зафиксируйте текущее рабочее состояние:
```bash
mkdir -p /root/php5_backup_$(date +%Y%m%d)
cd /root/php5_backup_$(date +%Y%m%d)

# Сохранение списка текущих пакетов
dpkg -l | grep -E "php5|libapache2-mod-php5" > installed_packages.txt

# Бэкап рабочего бинарного модуля и конфигов
cp -a /usr/lib/apache2/modules/libphp5.so ./libphp5.so.orig
cp -a /etc/php5 ./etc_php5_backup
cp -a /etc/apache2 ./etc_apache2_backup
```

#### 2. Сборка пропатченных пакетов Debian

**Способ А: Изолированная сборка через Docker (Рекомендуется — без компиляторов на бою)**  
Сборка выполняется на любой машине с Docker через [build/Dockerfile.debian8-modphp](build/Dockerfile.debian8-modphp):
```bash
# Сборка пакетов внутри изолированного контейнера Debian 8
docker build -t php5-deb8-builder -f build/Dockerfile.debian8-modphp .

# Выгрузка готовых .deb пакетов в локальную папку ./dist
mkdir -p dist
docker run --rm -v $(pwd)/dist:/output php5-deb8-builder
```
Полученные пакеты `libapache2-mod-php5_*.deb`, `php5-common_*.deb`, `php5-cli_*.deb` из папки `dist/` переносятся на целевой сервер.

**Способ Б: Сборка непосредственно на сервере Debian 8**
```bash
# 1. Подключение архивных репозиториев исходников в /etc/apt/sources.list
echo "deb-src http://archive.debian.org/debian jessie main" >> /etc/apt/sources.list
echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until

# 2. Установка сборочных утилит и зависимостей
apt-get update
apt-get install -y --force-yes build-essential fakeroot dpkg-dev quilt
apt-get build-dep -y --force-yes php5

mkdir -p /usr/src/php5-build && cd /usr/src/php5-build
apt-get source php5
cd php5-5.6.*

# 3. Регистрация патча в системе quilt
cp /path/to/php-5.6.x-full-cve-2026-109618-109619.patch debian/patches/cve-2026-109618-109619.patch
echo "cve-2026-109618-109619.patch" >> debian/patches/series

# 4. Компиляция deb-пакетов
dpkg-buildpackage -us -uc -b -nc -j$(nproc)
```

#### 3. Безопасная установка и валидация
```bash
# Установка собранных пакетов
dpkg -i libapache2-mod-php5_*.deb php5-common_*.deb php5-cli_*.deb

# КРИТИЧЕСКИ ВАЖНО: Проверка синтаксиса Apache ДО перезагрузки
apache2ctl configtest
# В выводе ОБЯЗАТЕЛЬНО должно быть: Syntax OK

# Мягкий перезапуск (без обрыва активных соединений пользователей)
service apache2 graceful
```

Проверка статуса:
```bash
tail -n 50 /var/log/apache2/error.log
curl -s -I http://localhost/
```

#### 4. План мгновенного отката (10 секунд)
При выявлении любых нештатных ошибок возврат к оригинальному модулю выполняется мгновенно:
```bash
cp /root/php5_backup_*/libphp5.so.orig /usr/lib/apache2/modules/libphp5.so
service apache2 graceful
```

---

## Регрессионная верификация и стресс-тестирование

Для проверки стабильности воркера и изоляции памяти в условиях долгоживущих процессов веб-сервера без перезапусков было выполнено FastCGI-тестирование на пуле с одним статическим воркером (`pm = static`, `pm.max_children = 1`):

* **Протокол стресс-теста:** 50 последовательных multipart-запросов с активным `PHP_SESSION_UPLOAD_PROGRESS` направлялись строго в один и тот же рабочий PID процесса.
* **Результаты:**
  * Успешных запросов: **50 / 50 (100%)**
  * Падений процесса / аварийных сбоев (SIGSEGV): **0**
  * Смена / перезапуск PID воркера: **0 (один и тот же PID обработал всю серию)**
  * Наблюдаемый рост RSS / утечка памяти: **не выявлено** (потребление памяти воркера стабильно зафиксировано на baseline ~221 КБ)
  * Суперглобалы (`$_POST`, `$_FILES`): полностью очищаются между последовательными запросами

---

## Скомпилированные бинарники и контрольные суммы

Пакеты собраны и размещены в папке [`releases/`](releases/) и во вкладке GitHub Releases.

### Параметры сборки (Provenance)
* **Базовый исходный код:** PHP 5.6.40 (`php5.6_5.6.40-104+ubuntu24.04.1+deb.sury.org+1`)
* **ОС сборки:** Ubuntu 24.04 LTS (x86_64, Linux 6.8.0, glibc 2.39)
* **Компилятор:** `gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0`
* **Флаги компиляции:** `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`

### Контрольные суммы SHA256

```text
688e235dface62e88c14941a50969223d6633d60b779448597bcf4e9f6d16d4c  php-fpm5.6-bin-x86_64.tar.gz
e9193946a6e94daa51bc29054647328f1939c8ea53fc915840ba1b63e52896a3  php5.6-fpm_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
506bd4f97d9de494593e1c0dcb268a84abe69113cd829012a05d9bee563e83ba  php5.6-cli_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
a686d6ecb2885a93c1fddae7901d90d153b01cdfee7837e1d16e2b8a965e64bc  php5.6-common_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
```

### Проверка перед установкой
```bash
sha256sum -c << 'EOF'
688e235dface62e88c14941a50969223d6633d60b779448597bcf4e9f6d16d4c  php-fpm5.6-bin-x86_64.tar.gz
e9193946a6e94daa51bc29054647328f1939c8ea53fc915840ba1b63e52896a3  php5.6-fpm_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
EOF
```

---

## Автор

Viktor Zarbashev ([@checkfoxe](https://github.com/checkfoxe))

## Лицензия

PHP License v3.01.
