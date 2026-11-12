#!/bin/sh
set -eu
umask 077

REPO=DalasDV/xkeen-resist-watcher
RELEASE_URL="https://github.com/$REPO/releases/latest/download"
API_URL="https://api.github.com/repos/$REPO"
INSTALL_DIR=/opt/sbin
WATCHER="$INSTALL_DIR/xkeen-subscription-watcher"
CONFIG_DIR=/opt/etc/xray/configs
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

github_api() {
    printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" |
        curl -fsSL --retry 2 --config - -H 'X-GitHub-Api-Version: 2022-11-28' "$@"
}

download_private_asset() {
    asset_name=$1
    asset_id=$(jq -er --arg name "$asset_name" '.assets[] | select(.name == $name) | .id' "$STAGE/release.json") ||
        fail "В релизе отсутствует $asset_name."
    case "$asset_id" in
        ''|*[!0-9]*) fail "Некорректный идентификатор файла $asset_name." ;;
    esac
    github_api -H 'Accept: application/octet-stream' "$API_URL/releases/assets/$asset_id" -o "$STAGE/$asset_name"
}

cleanup() {
    if [ -n "$TTY_SETTINGS" ]; then
        stty "$TTY_SETTINGS" </dev/tty || :
    fi
    rm -rf "$STAGE"
}

print_setup() {
    cat <<'SETUP'

   Если watcher уже запускается по расписанию, временно закомментируйте
   его строку в crontab на время правок маршрутизации.

1. Remnawave → Subscription Response Rules
   Перед общим правилом выдачи добавьте правило:
     user-agent EQUALS XKeen-Subscription-Watcher
     responseType: XRAY_JSON

2. /opt/etc/xray/configs/05_routing.json
   В routing.balancers замените запись с тегом proxy двумя записями.
   Остальные записи массива сохраните.

   [
     {
       "tag": "proxy",
       "selector": ["resist--hy2"],
       "strategy": { "type": "leastPing" },
       "fallbackTag": "to-resist-xhttp"
     },
     {
       "tag": "proxy-xhttp",
       "selector": ["resist--xhttp"],
       "strategy": { "type": "leastPing" }
     }
   ]

   В routing.rules первым добавьте правило:

   {
     "type": "field",
     "inboundTag": ["resist-xhttp-fallback"],
     "balancerTag": "proxy-xhttp"
   }

   Правила для трафика, который должен идти через VPN, направьте на
   "balancerTag": "proxy". Если они уже ссылаются на этот балансировщик,
   достаточно оставить их на месте.

   В корне 05_routing.json добавьте burstObservatory, если его ещё нет:

   {
     "burstObservatory": {
       "subjectSelector": ["resist"],
       "pingConfig": {
         "destination": "https://connectivitycheck.gstatic.com/generate_204",
         "interval": "20s",
         "sampling": 1,
         "timeout": "5s"
       }
     }
   }

   Если burstObservatory уже настроен, добавьте "resist" в его subjectSelector.

3. /opt/etc/xray/configs/04_outbounds.json
   В ручной массив outbounds добавьте этот выход:

   {
     "tag": "to-resist-xhttp",
     "protocol": "loopback",
     "settings": { "inboundTag": "resist-xhttp-fallback" }
   }

4. Подставьте ссылку подписки после resist= и сгенерируйте выходы:

   /opt/sbin/xkeen-subscription-watcher --protocol-tags --no-restart 'resist=<URL_ПОДПИСКИ>' &&
     xray run -test -confdir /opt/etc/xray/configs &&
     xkeen -restart

   Продолжайте после успешной проверки Xray. Watcher должен сообщить
   «Подписка "resist": Xray JSON.» и записать 04_outbounds.resist.json.

5. Для обновления по расписанию откройте crontab -e. Если watcher уже
   запускался из cron, отредактируйте и включите прежнюю строку. Для чистой установки
   добавьте строку:

   0 * * * * /opt/sbin/xkeen-subscription-watcher --protocol-tags 'resist=<URL_ПОДПИСКИ>'

   Для двух групп уберите --single-proxy из строки watcher, если он был.
   Если используете своё имя подписки или --output-dir, подставьте их
   в команды и селекторы вместо resist и стандартного каталога.
SETUP
}

case "${1:-}" in
    '') PRIVATE=0 ;;
    --private) PRIVATE=1 ;;
    *) fail "Использование: sh install.sh [--private]" ;;
esac
[ "$#" -le 1 ] || fail "Использование: sh install.sh [--private]"

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
TTY_SETTINGS=''
trap cleanup 0
trap 'exit 1' HUP INT TERM
if [ "$PRIVATE" -eq 1 ]; then
    command -v jq >/dev/null 2>&1 || fail 'Для приватного релиза нужна команда jq.'
    TOKEN=${XKEEN_GITHUB_TOKEN:-}
    unset XKEEN_GITHUB_TOKEN
    if [ -z "$TOKEN" ]; then
        TTY_SETTINGS=$(stty -g </dev/tty) || fail 'Запустите установщик в терминале или передайте XKEEN_GITHUB_TOKEN.'
        printf 'GitHub token с доступом Contents: Read: ' >/dev/tty
        stty -echo </dev/tty
        IFS= read -r TOKEN </dev/tty || fail 'Не удалось прочитать токен.'
        stty "$TTY_SETTINGS" </dev/tty
        TTY_SETTINGS=''
        printf '\n' >/dev/tty
    fi
    case "$TOKEN" in
        ''|*[!a-zA-Z0-9_-]*) fail 'Некорректный формат GitHub token.' ;;
    esac
    github_api -H 'Accept: application/vnd.github+json' "$API_URL/releases/latest" -o "$STAGE/release.json"
    download_private_asset SHA256SUMS
    download_private_asset "$ASSET"
    unset TOKEN
else
    curl -fsSL --retry 2 "$RELEASE_URL/SHA256SUMS" -o "$STAGE/SHA256SUMS" ||
        fail 'Не удалось скачать релиз. Для приватного репозитория запустите sh install.sh --private.'
    curl -fsSL --retry 2 "$RELEASE_URL/$ASSET" -o "$STAGE/$ASSET"
fi

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
for config_file in "$CONFIG_DIR"/04_outbounds.json "$CONFIG_DIR"/04_outbounds.*.json "$CONFIG_DIR"/05_routing.json; do
    if [ -f "$config_file" ]; then
        set -- "$@" "$config_file"
    fi
done
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
print_setup
