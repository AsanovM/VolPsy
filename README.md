# Volatility 3 Autopsy Ingest Module

## Описание
`Volatility3IngestModule.py` предоставляет модуль обработки источника данных в Autopsy, который запускает выбранные плагины Volatility 3 как внешние процессы. Результаты каждого плагина стримятся в файлы форматов JSONL и TXT, stderr Volatility сохраняется отдельно, а завершённые отчёты регистрируются в кейсе Autopsy.

## Состав проекта
- `Volatility3IngestModule.py` — основной модуль (фабрика, настройки, GUI, исполнение плагинов).
- `resources/config.ini` — конфигурация по умолчанию.
- `resources/icon.png` — опциональная иконка для Autopsy.
- `README.md` — это руководство.

## Требования
- Autopsy 4.19+ (с поддержкой Jython 2.7).
- Python 3.x.
- Volatility 3 (версия `volatility3`).
- Доступ к Python-пакетам Volatility (`pip` либо zip-архив Volatility3).
- Возможность запуска внешних процессов из Autopsy (Windows/Linux/macOS).

## Подготовка окружения
1. **Установите Python 3**
   - Windows: скачайте с https://www.python.org/downloads/windows/ ; при установке отметьте «Add Python to PATH».
   - Linux/macOS: используйте менеджер пакетов (например, `sudo apt install python3 python3-pip`).
2. **Установите зависимости Volatility 3**
   ```bash
   python3 -m pip install --upgrade pip
   python3 -m pip install volatility3
   ```
   Если собираетесь запускать модули, зависящие от дополнительных пакетов (например, yara-python), установите их заранее.
3. **Получите Volatility 3**
   - Вариант A (pip): после установки `volatility3` в папке `$PYTHON/site-packages/volatility3/` находится `vol.py`. Узнайте точный путь командой `python3 -c "import volatility3, os; print(os.path.join(os.path.dirname(volatility3.__file__), 'cli', 'vol.py'))"`.
   - Вариант B (Git):
     ```bash
     git clone https://github.com/volatilityfoundation/volatility3.git
     cd volatility3
     python3 -m pip install -r requirements.txt
     ```
     Путь к `vol.py` — `<репозиторий>/vol.py`.
4. **Проверьте работу**
   ```bash
   python3 /path/to/vol.py --info
   ```
   Убедитесь, что Volatility 3 запускается и перечисляет плагины.

## Установка модуля в Autopsy
1. Скопируйте папку `autopsy-vol3` на машину с Autopsy.
2. Поместите `Volatility3IngestModule.py` в `<Autopsy>/python_modules/`.
3. Рядом создайте каталог `Volatility3IngestModule` (если отсутствует) и скопируйте внутрь папку `resources/`.
4. При желании добавьте `resources/icon.png`.
5. Перезапустите Autopsy.

## Конфигурация (`resources/config.ini`)
- `[runtime] python_exe` — путь к Python 3 (по умолчанию `/usr/bin/python3`).
- `[runtime] vol_exe` — путь к `vol.py` Volatility 3.
- `[output] reports_root` — базовая папка отчётов (`CASE_MODULE_OUTPUT` → `<Case>/ModuleOutput/Volatility3`).
- `[limits] timeout_sec_per_plugin` — таймаут на каждый плагин.
- `[limits] max_stdout_mb` — лимит stdout (MB), при превышении будет запись о truncation.
- `[plugins.*] whitelist` — списки плагинов по ОС по умолчанию.

GUI-настройки (панель модуля) имеют приоритет над значениями конфигурационного файла.

## Настройка в Autopsy
1. Откройте Autopsy → «Tools» → «Options» → «Ingest Modules» и убедитесь, что модуль отображается.
2. При добавлении источника данных отметьте модуль «Volatility 3 Ingest Module» и откройте «Settings».
3. Укажите «Python executable», «Volatility script», «Reports root» (можно оставить значения по умолчанию).
4. Выберите плагины (чекбоксы разнесены по ОС).
5. Нажмите **Refresh plugins**, если хотите запросить список у фактической установки Volatility (`python vol.py --info`).
6. Сохраните настройки и запустите ingest.

## Работа модуля
- Модуль пытается определить ОС образа (`windows.info`, затем `linux.banners`, затем `mac.nt_tasks`).
- Для каждого выбранного плагина запускает два процесса (`--renderer jsonl` и `--renderer text`) с таймаутами.
- stdout стримится в файлы `.jsonl`/`.txt`, stderr собирается в `.stderr.txt`, при таймауте создаётся `.timeout.txt`.
- Сводка по завершению отправляется в Ingest Inbox, а корневая папка передаётся в `Case.addReport()`.

## Структура вывода
- `Volatility3/json/<plugin>.jsonl`
- `Volatility3/txt/<plugin>.txt`
- `Volatility3/logs/<plugin>.stderr.txt`
- `Volatility3/logs/<plugin>.timeout.txt`

## Рекомендации
- Убедитесь, что `python_exe` и `vol_exe` указывают на совместимые версии.
- При необходимости увеличьте `max_stdout_mb` для «шумных» плагинов.
- Повторно обновляйте список плагинов при обновлении Volatility 3.
- Анализируйте stderr, чтобы заметить ошибки исполнения плагинов.

## Лицензия и ограничения
- Модуль запускает Volatility как внешний процесс — на машине должны быть установлены Python и Volatility 3.
- При распространении соблюдайте требования Volatility Software License (VSL).

## Отладка
- Логи модуля пишутся через `Logger` в `application.log` Autopsy.
- Ошибки старта Volatility отображаются во всплывающих предупреждениях и ingest-инбоксе.

## Быстрый старт
1. Установите Python 3 и Volatility 3 (`pip install volatility3`).
2. Найдите путь к `vol.py`.
3. Настройте `config.ini` и/или GUI.
4. Запустите ingest с модулем Volatility 3 и просмотрите отчёты в `ModuleOutput/Volatility3`.
