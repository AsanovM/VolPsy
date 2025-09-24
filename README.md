# Volatility 3 Autopsy Ingest Module

## Описание
`Volatility3IngestModule.py` предоставляет модуль обработки источника данных в Autopsy, который запускает выбранные плагины Volatility 3 как внешние процессы. Результаты каждого плагина выводятся в файлы форматов JSONL и TXT, stderr Volatility сохраняется отдельно, а завершённые отчёты регистрируются в кейсе Autopsy.

## Состав проекта
- `Volatility3IngestModule.py` — основной модуль (фабрика, настройки, GUI, исполнение плагинов).
- `resources/config.ini` — конфигурация по умолчанию.
- `resources/icon.png` — опциональная иконка для Autopsy.
- `README.md` — это руководство.

## Требования
- Autopsy 4.19+ (с поддержкой Jython 2.7): https://www.autopsy.com/download/
- Python 3.x: https://www.python.org/downloads/
- Volatility 3 (volatilityfoundation/volatility3): https://github.com/volatilityfoundation/volatility3
- Возможность запуска внешних процессов на узле с Autopsy.

## Подготовка окружения
1. **Установите Python 3**
   - Windows: скачайте установщик с https://www.python.org/downloads/windows/ и при установке отметьте «Add Python to PATH».
   - macOS: можно использовать официальный .pkg или `brew install python`.
   - Linux: `sudo apt install python3 python3-pip` (Debian/Ubuntu) или `sudo dnf install python3` (Fedora/RHEL).
2. **Установите зависимости Volatility 3**
   ```bash
   python3 -m pip install --upgrade pip
   python3 -m pip install volatility3
   ```
   Дополнительные пакеты вроде `yara-python` можно поставить при необходимости (`python3 -m pip install yara-python`).
3. **Получите Volatility 3**
   - Вариант A (pip): `vol.py` будет в папке `.../site-packages/volatility3/cli/vol.py`.
     Узнать путь можно так:
     ```bash
     python3 -c "import volatility3, os; print(os.path.join(os.path.dirname(volatility3.__file__), 'cli', 'vol.py'))"
     ```
   - Вариант B (GitHub):
     ```bash
     git clone https://github.com/volatilityfoundation/volatility3.git
     cd volatility3
     python3 -m pip install -r requirements.txt
     ```
     В этом случае используйте `<путь>/vol.py`.
4. **Проверка**
   ```bash
   python3 /path/to/vol.py --info
   ```
   Убедитесь, что Volatility перечисляет плагины без ошибок.

## Установка модуля в Autopsy
1. Скопируйте папку `autopsy-vol3` на машину с Autopsy.
2. Поместите `Volatility3IngestModule.py` в `<Autopsy>/python_modules/`.
3. Рядом создайте каталог `Volatility3IngestModule` и скопируйте внутрь `resources/`.
4. При необходимости добавьте `resources/icon.png`.
5. Перезапустите Autopsy.

## Конфигурация (`resources/config.ini`)
- `[runtime] python_exe` — путь к Python 3.
- `[runtime] vol_exe` — путь к `vol.py`.
- `[output] reports_root` — базовая папка отчётов (`CASE_MODULE_OUTPUT` → `<Case>/ModuleOutput/Volatility3`).
- `[limits] timeout_sec_per_plugin` — таймаут на плагин.
- `[limits] max_stdout_mb` — лимит stdout (в мегабайтах).
- `[plugins.*] whitelist` — списки плагинов по умолчанию.

GUI-панель для ingest job может переопределять эти значения.

## Настройка в Autopsy
1. Откройте «Tools → Options → Ingest Modules» и убедитесь, что модуль виден.
2. При добавлении источника данных отметьте «Volatility 3 Ingest Module» и нажмите «Settings».
3. Укажите пути к `python_exe`, `vol_exe`, `reports_root` (либо оставьте дефолт).
4. Отметьте необходимые плагины. Кнопка **Refresh plugins** запрашивает `python vol.py --info` и обновляет список.
5. Запустите ingest.

## Работа модуля
- ОС дампа определяется через последовательный запуск `windows.info`, затем `linux.banners`, затем `mac.nt_tasks`.
- Для каждого плагина выполняется JSONL и текстовый прогон с таймаутами.
- stdout/ stderr потоково записываются в файлы, таймауты получают `.timeout.txt`.
- Сводка пишется в Ingest Inbox, отчёт регистрируется в кейсе через `Case.addReport`.

## Структура вывода
- `Volatility3/json/<plugin>.jsonl`
- `Volatility3/txt/<plugin>.txt`
- `Volatility3/logs/<plugin>.stderr.txt`
- `Volatility3/logs/<plugin>.timeout.txt`

## Рекомендации
- Следите за совместимостью `python_exe` и `vol_exe`.
- При необходимости увеличивайте `max_stdout_mb`.
- После обновления Volatility используйте «Refresh plugins».
- Анализируйте stderr-файлы для диагностики проблем.

## Лицензия и ограничения
- Модуль использует Volatility 3 как отдельный процесс; убедитесь, что лицензия Volatility Software License (VSL) соблюдается при распространении.

## Отладка
- Логи пишутся через `org.sleuthkit.autopsy.coreutils.Logger` в `application.log`.
- Ошибки старта Volatility отображаются в GUI и отправляются в Ingest Inbox.

## Быстрый старт
1. Скачать и установить Autopsy: https://www.autopsy.com/download/
2. Установить Python 3: https://www.python.org/downloads/
3. Установить Volatility 3: `python3 -m pip install volatility3` или клонировать https://github.com/volatilityfoundation/volatility3
4. Настроить `config.ini`/GUI и запустить ingest.

