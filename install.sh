#!/bin/sh
set -eu
umask 077

REPO=DalasDV/xkeen-resist-watcher
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
    rm -rf "$STAGE"
}

[ "$#" -eq 0 ] || fail "Использование: sh install.sh"

for command_name in curl sha256sum awk mktemp; do
    command -v "$command_name" >/dev/null 2>&1 || fail "На роутере нужна команда $command_name."
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
trap cleanup 0
trap 'exit 1' HUP INT TERM
curl -fsSL --retry 2 "$RELEASE_URL/SHA256SUMS" -o "$STAGE/SHA256SUMS" ||
    fail 'Не удалось скачать контрольные суммы из последнего публичного релиза.'
curl -fsSL --retry 2 "$RELEASE_URL/$ASSET" -o "$STAGE/$ASSET" ||
    fail "Не удалось скачать сборку $ASSET."

EXPECTED=$(awk -v name="$ASSET" '$2 == name { print $1 }' "$STAGE/SHA256SUMS")
ACTUAL=$(sha256sum "$STAGE/$ASSET")
ACTUAL=${ACTUAL%% *}
[ "${#EXPECTED}" -eq 64 ] && [ "$EXPECTED" = "$ACTUAL" ] || fail 'Контрольная сумма сборки не совпала.'

chmod 755 "$STAGE/$ASSET"
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
    "$WATCHER" setup
else
    echo "Чтобы настроить или заменить подписку, запустите $WATCHER setup"
fi
