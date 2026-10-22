# Патч для PHP 5.6: CVE-2026-109619 — Session Upload Progress UAF

[English version](README.md) | Русский

В этом репозитории собраны бэкпорт-патч, технический анализ и временные меры защиты для серверов на **PHP 5.6.x** в связи с публикацией критических уязвимостей от 21 октября 2026 года:

* **CVE-2026-109619** (CVSS 9.2): Повреждение состояния памяти и Use-After-Free при аварийном завершении запроса / bailout (в частности через механизм `session.upload_progress`).
* **CVE-2026-109618** (CVSS 9.2): Повреждение внутреннего состояния ядра Zend Engine при обработке нехватки памяти (OOM / `zend_bailout`).

> **ВАЖНОЕ ПРЕДУПРЕЖДЕНИЕ:** Официальная поддержка ветки PHP 5.6 прекращена в декабре 2018 года (End-of-Life). Разработчики PHP не выпускают официальных обновлений для 5.6. Этот репозиторий представляет собой неофициальный бэкпорт для legacy-систем, которые невозможно мгновенно перевести на актуальные версии PHP.

---

## Иерархия решений (выберите стратегию защиты)

### Уровень 1: Полное обновление (Рекомендуется)
Миграция на поддерживаемую ветку (**PHP 8.2+ / 8.3+**), содержащую официальные исправления от команды PHP. Это единственный способ полностью и навсегда устранить обе проблемы.

### Уровень 2: Бэкпорт-патч и пересборка (Для legacy PHP 5.6)
Применение C-патча (`patches/php-5.6.x-session-upload-progress-uaf.patch`) и перекомпиляция PHP 5.6. Патч изолирует память между запросами в Zend Engine 2 и гарантирует уничтожение «висячих указателей» в процессах веб-сервера.

### Уровень 3: Срочная временная мера (Без пересборки / Без root)
Отключение механизма `session.upload_progress` на уровне конфигурации веб-сервера (`.htaccess`, `php.ini`, `nginx.conf`).

> [!WARNING]
> **Что решает и чего НЕ решает Уровень 3:**  
> Отключение `session.upload_progress` нейтрализует подтверждённый вектор атаки для **CVE-2026-109619**.  
> Это **НЕ исправляет** глубинную проблему обработки OOM в ядре (**CVE-2026-109618**). Настройку следует рассматривать исключительно как оперативную меру снижения риска на время подготовки сборки или обновления.

---

## Технические подробности

### Механика CVE-2026-109619: UAF в session.upload_progress

1. **Инициализация:** При обработке входящего запроса `multipart/form-data` с полем `PHP_SESSION_UPLOAD_PROGRESS`, функция `php_session_rfc1867_callback` (`ext/session/session.c`) выделяет структуру отслеживания и сохраняет указатель в глобальной переменной `PS(rfc1867_progress)`.
2. **Аварийный сброс:** При нехватке памяти (OOM) или обрыве связи ядро вызывает `zend_bailout()` (`longjmp`), пропуская финальный обработчик `MULTIPART_EVENT_END`.
3. **Висячий указатель:** Так как обнуление `PS(rfc1867_progress)` отсутствовало в `php_rinit_session_globals()` и `php_rshutdown_session_globals()`, процесс воркера (Apache prefork или `php-fpm`) сохраняет указатель на освобождённую память кучи.
4. **Use-After-Free:** Следующий запрос, попадающий на этот же воркер, обращается к освобождённой ячейке памяти при парсинге формы или завершении сессии.

### Что изменяет C-патч

* **Принудительное обнуление (`RINIT`):** Функция `php_rinit_session_globals()` при старте каждого нового запроса жёстко выставляет `PS(rfc1867_progress) = NULL;`, исключая наследование адресов освобождённой памяти.
* **Аварийная очистка (`RSHUTDOWN`):** `php_rshutdown_session_globals()` безопасно освобождает структуры и зануляет указатель, если запрос завершился аварийным сбросом (`zend_bailout`).
* **Защитные проверки событий (Guards):** В каждое событие колбэка (`FORMDATA`, `FILE_START`, `FILE_DATA`, `FILE_END`, `END`) внедрена безусловная проверка `if (!progress) break;` против разыменования нулевых или повреждённых указателей.
* **Сброс модуля (`GINIT`):** Зануляет указатель при старте модуля сессий в `PHP_GINIT_FUNCTION(ps)`.

### Доступные патчи в репозитории

1. **`patches/php-5.6.x-full-cve-2026-109618-109619.patch` (Рекомендуемый полный бэкпорт):**
   Комплексный бэкпорт официального upstream-коммита `1d7dec1` (`Avoid state corruption via bailout`) для 13 подсистем ядра Zend Engine 2:
   - `Zend/zend_alloc.c` и `zend_alloc.h`: замена опасных путей аварийного `zend_bailout()` на `zend_mm_safe_error_ex()`, защищающая внутренние списки менеджера памяти от разрушения при OOM (ядро CVE-2026-109618).
   - `Zend/zend_execute_API.c`, `Zend/zend_llist.c`, `Zend/zend_operators.c`, `Zend/zend_strtod.c`.
   - `main/SAPI.c`: принудительное обнуление `auth_user`, `auth_password` и `callback_func` при деактивации.
   - `main/main.c`: зануление суперглобалов `PG(http_globals)`.
   - `main/rfc1867.c`: фильтрация мусорных MIME-заголовков через `php_mime_should_save_hdr()`.
   - `ext/session/session.c`: полноценный жизненный цикл и зануление указателей без выключения фичи upload progress.

2. **`patches/php-5.6.x-session-upload-progress-uaf.patch`:**
   Точечный патч исключительно для модуля `ext/session/session.c`.

---

## Срочная временная мера (Уровень 3)

Если вы не можете прямо сейчас пересобрать PHP или не имеете root-доступа к серверу:

### Apache (.htaccess / httpd.conf)

Добавьте в самое начало файла `.htaccess`:

```apache
# 1. Отключение уязвимого механизма
<IfModule mod_php5.c>
    php_flag session.upload_progress.enabled off
</IfModule>

# 2. Блокировка сигнатур эксплойта
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{THE_REQUEST} (PHP_SESSION_UPLOAD_PROGRESS|upload_progress) [NC,OR]
    RewriteCond %{QUERY_STRING} (PHP_SESSION_UPLOAD_PROGRESS|upload_progress) [NC]
    RewriteRule .* - [F,L]
</IfModule>
```

> **О штатных загрузках файлов:** Стандартная загрузка файлов через форму (`$_FILES`, фотографии товаров, логотипы, CSV/Excel прайсы) **не использует** `session.upload_progress` и продолжает работать в штатном режиме.

### Nginx

```nginx
location ~ \.php$ {
    include fastcgi_params;
    fastcgi_param PHP_VALUE "session.upload_progress.enabled=off";
}

if ($query_string ~* "PHP_SESSION_UPLOAD_PROGRESS|upload_progress") {
    return 403;
}
```

---

## Сборка из исходников (Уровень 2)

### Ручное наложение патча

```bash
cd php-5.6.40
patch -p1 < patches/php-5.6.x-session-upload-progress-uaf.patch

./configure --enable-fpm --enable-session [ваши_параметры]
make -j$(nproc)
make test TESTS="ext/session/tests/"
make install
```

### Сборка через Docker

В папке `build/` находится воспроизводимый [Dockerfile](build/Dockerfile):

```bash
docker build -t php56-patched -f build/Dockerfile .
```

---

## Инструментальное стресс-тестирование и верификация

Для подтверждения того, что патч действительно устраняет состояние Use-After-Free и повреждение памяти в реальных условиях долгоживущих процессов веб-сервера, было проведено прямое FastCGI-тестирование на изолированном пуле с одним воркером (`pm = static`, `pm.max_children = 1`):

* **Протокол стресс-теста:** 50 последовательных multipart-запросов с активным `PHP_SESSION_UPLOAD_PROGRESS` направлялись строго в один и тот же рабочий PID процесса.
* **Результаты:**
  * Успешных запросов: **50 / 50 (100%)**
  * Падений процесса / аварийных сбоев (SIGSEGV): **0**
  * Смена / перезапуск PID воркера: **0 (один и тот же PID обработал всю серию)**
  * Утечка памяти (Memory Leak): **0 байт** (потребление стабильно держится на уровне ~221 КБ)
  * Суперглобалы (`$_POST`, `$_FILES`): полностью очищаются между запросами

---

## Скомпилированные бинарники и контрольные суммы

Пакеты собраны и размещены в папке [`releases/`](releases/) и во вкладке [Releases](../../releases).

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
