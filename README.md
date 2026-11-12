# XKeen Resist Watcher

[![Test](https://github.com/DalasDV/xkeen-resist-watcher/actions/workflows/test.yml/badge.svg)](https://github.com/DalasDV/xkeen-resist-watcher/actions/workflows/test.yml)

На основе [xkeen-subscription-watcher](https://github.com/tkukushkin/xkeen-subscription-watcher).

## Использование

```bash
xkeen-subscription-watcher <tag>=<url>
```

Можно передать несколько пар `<tag>=<url>`

Скрипт получает из переданных подписок прокси, генерирует конфиги `04_outbounds.<tag>.json`.

Если конфиги изменились, выполняется `xkeen -restart`.

### Xray JSON из Remnawave

Watcher автоматически распознаёт массив профилей Xray или один объект с
`outbounds`. Он переносит серверные выходы со всеми вложенными параметрами,
префиксует их теги именем подписки и по возможности использует `remarks` как
имя сервера. DNS, inbounds, routing и служебные выходы профиля остаются на
стороне подписки. Если серверный выход ссылается на другие выходы по тегу,
эти ссылки должны разрешаться в конфигурации роутера.

Для Remnawave добавьте правило выдачи `XRAY_JSON` по User-Agent
`XKeen-Subscription-Watcher` выше общего fallback. Выдача списков ссылок и
Base64 также поддерживается. Для `hysteria2://` и `hy2://` доступны SNI,
пин сертификата, ECH, Salamander/Gecko и диапазоны портов. Версия ядра Xray
определяет, какие поля оно сможет применить. Пустой или некорректный ответ
не заменяет существующий файл.

### Поддерживаемые протоколы

- `vless` (reality / tls / none; транспорты `tcp`, `raw`, `ws`, `grpc`, `xhttp`)
- `vmess` (формат `vmess://base64(JSON)`)
- `trojan`
- `shadowsocks` (`ss`)
- `hysteria2`

Для `vmess` и `trojan` поддерживаются транспорты `tcp`, `raw`, `ws`, `grpc`.
Узлы с транспортами, которые удалены из актуального Xray (`h2`/`http`, `quic`,
`kcp` и т.п.), пропускаются с предупреждением в логе — чтобы один такой узел не
ломал весь конфиг.

### Флаги

- `--output-dir <path>` — каталог для конфигов (по умолчанию `/opt/etc/xray/configs`)
- `--no-restart` — не перезапускать XKeen после обновления
- `--single-proxy` — брать только первый прокси из подписки
- `--protocol-tags` — добавлять к тегам выходов `--hy2`, `--xhttp` или `--other` для отдельных селекторов балансировщика
- `--reality-fingerprint <fp>` — переопределить fingerprint для Reality
- `--dialer-proxies=<proxy1>,<proxy2>` — dialer proxies через запятую

## Установка

Запускайте в оболочке Entware на роутере. Установщик определяет архитектуру,
скачивает сборку из последнего релиза, сверяет SHA-256 и ставит её в
`/opt/sbin/xkeen-subscription-watcher`. При обновлении прежний бинарник,
конфиги Xray и запись расписания можно восстановить из указанной папки
резервной копии. Рабочие файлы выходов обновляет сам watcher при первом
успешном чтении подписки.

### Запуск на роутере

В терминале Entware:

```shell
curl -fsSL https://github.com/DalasDV/xkeen-resist-watcher/releases/latest/download/install.sh \
  -o /tmp/xkeen-resist-install.sh &&
  sh /tmp/xkeen-resist-install.sh
```

После установки следуйте шагам в мастере для приоритета Hysteria с
резервом XHTTP. Ниже приведён также вариант для одного общего балансировщика.


### Crontab

```shell
crontab -e
```

Добавляем что-то вроде:

```crontab
0 * * * * /opt/sbin/xkeen-subscription-watcher <tag>=<url>
```

### Настройка Xray

Убираем из `04_outbounds.json` прокси, которые будут теперь генерироваться из подписок,
иначе теги будут конфликтовать, оставляем например такое:

```json
{
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "response": {
        "type": "HTTP"
      }
    }
  ]
}
```

В `05_routing.json` добавляем конфигурацию `balancers` и `burstObservatory` для автоматического выбора лучшего прокси,
далее в `rules` используем `balancerTag` вместо `outboundTag`, например:

```json
{
  "routing": {
    "domainStrategy": "AsIs",
    "balancers": [
      {
        "tag": "proxy",
        "selector": ["<tag>"],
        "strategy": {
          "type": "leastPing"
        }
      }
    ],
    "rules": [
      {
        "inboundTag": ["socks", "http"],
        "balancerTag": "proxy"
      }
    ]
  },
  "burstObservatory": {
    "subjectSelector": ["<tag>"],
    "pingConfig": {}
  }
}
```

Разово запускаем команду из crontab, проверяем, что всё работает.
