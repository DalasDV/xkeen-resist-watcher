#!/bin/sh
set -eu
umask 077

PATH="${PATH:-/bin:/usr/bin}:/opt/bin:/opt/sbin:/bin:/sbin:/usr/bin:/usr/sbin"
export PATH

REPO=DalasDV/xkeen-watcher-json
RELEASE_URL="https://github.com/$REPO/releases/latest/download"
INSTALL_DIR=/opt/sbin
WATCHER="$INSTALL_DIR/xkeen-subscription-watcher"
BACKUP_ROOT=/opt/etc/xkeen-subscription-watcher/backups

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

detect_arch() {
    machine=$(uname -m)
    case "$machine" in
        aarch64|arm64) echo arm64 ;;
        armv7l|armv7) echo armv7 ;;
        mipsel|mipsle) echo mipsel ;;
        mips)
            elf_byte=$(dd if=/bin/sh bs=1 skip=5 count=1 2>/dev/null | od -b | awk 'NR == 1 {print $2}')
            case "$elf_byte" in
                001) echo mipsel ;;
                002) echo mips ;;
                *) fail 'Не удалось определить порядок байтов MIPS.' ;;
            esac
            ;;
        *) fail "Неподдерживаемая архитектура: $machine." ;;
    esac
}

cleanup() {
    stop_download_progress
    rm -rf "$STAGE"
}

stop_download_progress() {
    if [ -n "$progress_pid" ]; then
        kill "$progress_pid" 2>/dev/null || :
        wait "$progress_pid" 2>/dev/null || :
        progress_pid=
    fi
}

download_progress_line() {
    received=0
    if [ -f "$1" ]; then
        received=$(wc -c <"$1")
    fi
    awk -v received="$received" -v complete="$3" '
        { sub(/\r$/, "") }
        /^HTTP\// { status = $2; length_bytes = 0; range_bytes = 0 }
        tolower($1) == "content-length:" && status == 200 { length_bytes = $2 + 0 }
        tolower($1) == "content-range:" && status == 206 {
            split($3, range, "/"); range_bytes = range[2] + 0
        }
        END {
            total = range_bytes ? range_bytes : length_bytes
            if (complete) total = received
            if (total <= 0) {
                printf "Загружено %.2f МБ", received / 1000000
                exit
            }
            ratio = received / total
            if (ratio > 1) ratio = 1
            printf "["
            for (i = 1; i <= 24; i++) printf "%s", (i <= int(24 * ratio) ? "#" : "-")
            printf "] %5.1f%%  %.2f / %.2f МБ", 100 * ratio, received / 1000000, total / 1000000
        }
    ' "$2"
}

show_download_progress() {
    while :; do
        printf '\r'
        download_progress_line "$1" "$2" 0
        printf '\033[K'
        sleep 1
    done >&2
}

download_asset() {
    asset=$1
    target="$STAGE/$asset"
    headers="$STAGE/response-headers"
    errors="$STAGE/curl-errors"
    echo "Скачиваю $asset с GitHub…"
    for attempt in 1 2 3; do
        : >"$headers"
        if [ -t 2 ]; then
            show_download_progress "$target" "$headers" &
            progress_pid=$!
        fi
        status=0
        curl --fail --silent --show-error --location --continue-at - --dump-header "$headers" \
            "$RELEASE_URL/$asset" -o "$target" 2>"$errors" || status=$?
        stop_download_progress
        if [ -t 2 ]; then printf '\r\033[K' >&2; fi
        if [ "$status" -eq 0 ]; then
            download_progress_line "$target" "$headers" 1
            printf '\n'
            return
        fi
        cat "$errors" >&2
        case "$status" in
            60|77) fail 'Не удалось проверить TLS. Проверьте часы роутера и пакет ca-certificates.' ;;
        esac
        [ "$attempt" -lt 3 ] || break
        case "$status" in
            33) rm -f "$target" ;;
            5|6|7|18|22|28|52|55|56) ;;
            *) break ;;
        esac
        echo "Повторяю загрузку $asset (попытка $((attempt + 1)) из 3)…"
    done
    fail "Не удалось скачать $asset. Проверьте доступ роутера к GitHub и повторите установку."
}

[ "$#" -eq 0 ] || fail "Использование: sh install.sh"

command -v curl >/dev/null 2>&1 || fail 'Нет curl. В Entware выполните: opkg update && opkg install curl ca-certificates'
if command -v sha256sum >/dev/null 2>&1; then
    checksum() { sha256sum "$1"; }
elif command -v busybox >/dev/null 2>&1 && busybox sha256sum </dev/null >/dev/null 2>&1; then
    checksum() { busybox sha256sum "$1"; }
else
    fail 'Нет sha256sum. В Entware выполните: opkg update && opkg install coreutils-sha256sum'
fi
for command_name in awk cat chmod cp dd mkdir mktemp mv od rm sleep uname wc; do
    command -v "$command_name" >/dev/null 2>&1 || fail "Нет системной утилиты $command_name. Проверьте PATH и установку BusyBox/Entware."
done
[ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ] || fail "Каталог $INSTALL_DIR недоступен для записи. Запустите из Entware."
[ ! -d "$WATCHER" ] || fail "Путь $WATCHER занят каталогом."

ARCH=$(detect_arch)
ASSET="xkeen-subscription-watcher-linux-$ARCH"
if [ -e "$WATCHER" ] || [ -L "$WATCHER" ]; then
    echo "Обновление существующего watcher в $WATCHER."
else
    echo "Чистая установка watcher в $WATCHER."
fi
echo "Архитектура: $ARCH."

STAGE=$(mktemp -d "$INSTALL_DIR/.xkeen-watcher.XXXXXX")
progress_pid=
trap cleanup 0
trap 'exit 1' HUP INT TERM
download_asset SHA256SUMS
download_asset "$ASSET"

echo "Проверяю контрольную сумму $ASSET."
EXPECTED=$(awk -v name="$ASSET" '$2 == name { print $1 }' "$STAGE/SHA256SUMS")
ACTUAL=$(checksum "$STAGE/$ASSET")
ACTUAL=${ACTUAL%% *}
[ "${#EXPECTED}" -eq 64 ] && [ "$EXPECTED" = "$ACTUAL" ] || fail 'Контрольная сумма сборки не совпала.'

chmod 755 "$STAGE/$ASSET"
echo "Проверяю, что новая сборка запускается."
VERSION=$("$STAGE/$ASSET" version 2>&1) || fail 'Новый бинарник не запустился. Проверьте архитектуру и версию Entware.'
[ -n "$VERSION" ] || fail 'Новый бинарник не сообщил версию.'

set --
if [ -e "$WATCHER" ] || [ -L "$WATCHER" ]; then
    set -- "$@" "$WATCHER"
fi
if command -v crontab >/dev/null 2>&1 && crontab -l >"$STAGE/crontab" 2>/dev/null &&
   awk '/^[[:space:]]*#/ {next} /xkeen-subscription-watcher/ {found=1} END {exit !found}' "$STAGE/crontab"; then
    set -- "$@" "$STAGE/crontab"
fi

if [ "$#" -gt 0 ]; then
    mkdir -p "$BACKUP_ROOT"
    BACKUP=$(mktemp -d "$BACKUP_ROOT/upgrade.XXXXXX")
    cp -p "$@" "$BACKUP/"
    echo "Копия прежних файлов: $BACKUP."
fi

mv -f "$STAGE/$ASSET" "$WATCHER"
echo "Установлен $WATCHER ($VERSION)."
if [ -t 0 ]; then
    if command -v crontab >/dev/null 2>&1; then
        "$WATCHER" setup
    else
        echo "Для мастера нужен cron. В Entware выполните: opkg update && opkg install cron"
        echo "Затем запустите $WATCHER setup"
    fi
else
    echo "Чтобы настроить или заменить подписку, запустите $WATCHER setup"
fi
