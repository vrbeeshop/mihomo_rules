# Mihomo rules

Сборка списков правил для Mihomo: загрузка источников, объединение и удаление
дубликатов. Источники и состав наборов задаются в [rulesets.yaml](rulesets.yaml),
собственные правила — в [rules/](rules/).

Доменные и IP-наборы используют MRS, остальные типы правил — YAML/LIST.
`partition` разделяет общий исходник на доменный набор и дополнение `*_extra`.
Вариант `domain-keyword` выбирает только правила `DOMAIN-KEYWORD` для DNS и iOS.
IP-исключения для прокси хранятся в `rules/vrbee_proxy_ips.list`, процессы — в
`rules/vrbee_proxy_process.list`. Категории GeoSite и сети ASN подключаются
через MRS. Сборка с `allow_global_geodata: false` отклоняет правила, которые
заставили бы клиента загружать полную базу.

`exclude_covered_by` убирает из результата правила, покрытые указанными наборами;
эти наборы нужно использовать вместе. При изменении источников покрытие пересчитывается.

Результаты доступны в [последнем релизе](https://github.com/vrbeeshop/mihomo_rules/releases/latest):
MRS, YAML и LIST. MRS выпускается для `domain` и `ipcidr`; смешанные наборы
`classical` — в YAML и LIST. Определения провайдеров находятся в `providers.yaml`.

Постоянная ссылка на файл:

```text
https://github.com/vrbeeshop/mihomo_rules/releases/latest/download/<имя-набора>.<формат>
```

[GitHub Actions](.github/workflows/build-release.yml) публикует релиз ежедневно
в 03:17 UTC, при push в `main` и при ручном запуске из `main`.
Публикация выполняется только после успешных проверок.

Локальная сборка (Python 3.12+, Linux x86-64 / WSL):

```bash
python3 -m venv .work/venv
.work/venv/bin/python -m pip install -r requirements.txt
.work/venv/bin/python scripts/install_mihomo.py
.work/venv/bin/python -m unittest discover -s tests -v
.work/venv/bin/python scripts/build.py
```

Установщик проверяет SHA256 закреплённой версии Mihomo. Для другого бинарника
укажите `--mihomo /path/to/mihomo`. Повторная сборка из проверенного кэша:
`scripts/build.py --offline`.

Файлы записываются в `dist/`. `manifest.json` содержит источники, хеши и число
правил; `checksums.sha256` — контрольные суммы файлов релиза.

## Часовое обновление зеркала

Нода сама забирает клиентские файлы из GitHub Releases по HTTPS.
Состав задаётся списком `mirror` в `rulesets.yaml`. Сборщик записывает
имена файлов в `manifest.json`. Служба сверяет локальные файлы с SHA256
одного релиза, скачивает изменившиеся во временный каталог и проверяет
их перед заменой. Такой запуск также восстанавливает пропущенные файлы.

На ноде понадобятся Python 3, systemd и локальный пользователь
`rules-publisher` с правом записи в каталог сайта. В командах ниже
укажите каталог на хосте, который читает веб-сервер. Выполняйте их
из корня копии этого репозитория на ноде.

```bash
sudo install -D -m 0644 scripts/sync_mirror.py /usr/local/lib/mihomo-rules/sync_mirror.py
sudo install -m 0644 deploy/mihomo-rules-mirror.{service,timer} /etc/systemd/system/
printf '%s\n' 'MIRROR_DIR=/srv/www/rules' | sudo tee /etc/default/mihomo-rules-mirror >/dev/null
sudo systemctl daemon-reload
sudo systemctl start mihomo-rules-mirror.service && sudo systemctl enable --now mihomo-rules-mirror.timer
```

Первый запуск обновляет файлы сразу. Затем таймер срабатывает каждый час
в `:30` по времени ноды. При пропущенном запуске он сработает после включения.
Проверка расписания и результата последнего запуска:

```bash
systemctl list-timers --all mihomo-rules-mirror.timer
journalctl -u mihomo-rules-mirror.service -n 15 --no-pager
```
