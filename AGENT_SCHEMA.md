# Forensic Agent — Детальная схема AI-агента

## 1. Общая архитектура проекта

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FORSETI FORENSIC AGENT                          │
│                   Криминалистический анализ образов дисков              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐         ┌──────────────────────────┐              │
│  │  run_agent.py    │         │  run_deep_agent.py        │              │
│  │  (Simple Agent)  │         │  (Deep Forensic Agent)    │              │
│  └────────┬────────┘         └────────────┬─────────────┘              │
│           │                                │                            │
│           ▼                                ▼                            │
│  ┌─────────────────┐         ┌──────────────────────────┐              │
│  │ ForensicAgent    │         │ ForensicDeepAgent         │              │
│  │ (simple_agent.py)│         │ (forensic_deep_agent.py)  │              │
│  │                  │         │                           │              │
│  │ LangGraph:       │         │ LangGraph Orchestrator    │              │
│  │ 5 узлов          │         │ + Deep Agent SDK          │              │
│  │ + GigaChat LLM   │         │ + 4 субагента             │              │
│  └────────┬────────┘         │ + GigaChat LLM            │              │
│           │                  └────────────┬──────────────┘              │
│           │                                │                            │
│           ▼                                ▼                            │
│  ┌──────────────────────────────────────────────────────┐              │
│  │                    TOOLS LAYER                        │              │
│  │  image_tools │ artifact_tools │ analysis_tools        │              │
│  │  filesystem_tools │ investigation_tools               │              │
│  └──────────────────────────┬───────────────────────────┘              │
│                             │                                           │
│                             ▼                                           │
│  ┌──────────────────────────────────────────────────────┐              │
│  │              IMAGE MANAGER (pytsk3)                   │              │
│  │         Доступ к файловой системе образа              │              │
│  └──────────────────────────────────────────────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---


## 2. Deep Forensic Agent — Граф LangGraph с итеративным циклом

**Файл:** `src/agent/forensic_deep_agent.py`  
**Состояние:** `ForensicAgentState` (расширяет `BaseAgentState`)  
**Точка входа:** `run_deep_agent.py`

```
                              ┌─────────┐
                              │  START  │
                              └────┬────┘
                                   │
                                   ▼
                        ┌────────────────────┐
                        │   open_image_node  │
                        └────────┬───────────┘
                                 │
                        ┌────────┴────────┐
                        │ image_open?     │ (route_after_open)
                        ├── Yes ─────┐   │
                        │            │   ├── No ──► END
                        └────────────┘   │
                                         │
                                   ▼     │
                    ┌───────────────────────────┐
                    │  collect_baseline_node     │ ◄── Фаза 1: Детерминированный
                    │                           │     сбор артефактов
                    │  • 12 artifact tools       │
                    │  • triage.yaml конфиг      │
                    │  • analyze_triage_data     │ ◄── Алгоритмический анализ
                    │  • Формирование            │
                    │    recommendations         │
                    └─────────────┬─────────────┘
                                  │
                ┌─────────────────┼──────────────────────┐
                │                 │                       │
                │                 ▼                       │
                │   ┌──────────────────────────┐         │
                │   │   deep_analysis_node     │ ◄───────┤ ИТЕРАТИВНЫЙ
                │   │                          │         │ ЦИКЛ АНАЛИЗА
                │   │  Deep Agent SDK:         │         │
                │   │  • GigaChat-2-Max LLM    │         │ (до max_iterations,
                │   │  • 4 субагента           │         │  по умолчанию 3)
                │   │  • 26 forensic tools     │         │
                │   │                          │         │
                │   │  Fallback (без SDK):     │         │
                │   │  • Прямой LLM-анализ     │         │
                │   │    по 9 секциям          │         │
                │   │                          │         │
                │   │  Синхронизация:           │         │
                │   │  • InvestigationStore →   │         │
                │   │    ForensicAgentState     │         │
                │   └─────────────┬────────────┘         │
                │                 │                       │
                │                 ▼                       │
                │   ┌──────────────────────────┐         │
                │   │  evaluate_analysis_node  │         │
                │   │                          │         │
                │   │  LLM-оценка              │         │
                │   │  достаточности           │         │
                │   │  анализа                 │         │
                │   └─────────┬────────────────┘         │
                │             │                          │
                │    ┌────────┴─────────┐                │
                │    │ verdict?         │                 │
                │    │                  │                 │
                │    ├─ "continue" ─────┼────────────────┘
                │    │                  │  (route_after_evaluation)
                │    ├─ "sufficient" ───┤
                │    │                  │
                │    └──────────────────┘
                │             │
                └─────────────┘
                              │ "sufficient"
                              ▼
                ┌──────────────────────────┐
                │  generate_report_node    │ ◄── Всеобъемлющий HTML-отчёт
                │                          │
                │  • comprehensive_report  │
                │    .html                 │
                │  • report_data.json      │
                │  • triage_data.json      │
                │  • analysis_result.json  │
                └────────────┬─────────────┘
                             │
                    ┌────────┴────────┐
                    │ image_open?     │ (route_after_report)
                    └────────┬────────┘
                             │
                             ▼
                    ┌────────────────────┐
                    │  close_image_node  │
                    └────────┬───────────┘
                             │
                             ▼
                          ┌─────┐
                          │ END │
                          └─────┘
```

---

## 3. Трёхуровневая архитектура Агента

```
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: LangGraph Orchestrator                                        │
│  (ForensicAgentState — граф с 6 узлами)                                 │
│                                                                         │
│  open_image → collect_baseline → deep_analysis ⇄ evaluate_analysis     │
│                                                   → generate_report     │
│                                                     → close_image → END │
├─────────────────────────────────────────────────────────────────────────┤
│  LAYER 2: Deep Agent (deepagents SDK / create_deep_agent)               │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐      │
│  │  Forseti Deep Agent                                           │      │
│  │                                                               │      │
│  │  • LLM: GigaChat-2-Max                                       │      │
│  │  • System Prompt: FORENSIC_SYSTEM_PROMPT (Chain of Thought)   │      │
│  │  • Tools: 26 forensic tools                                   │      │
│  │  • Middleware: TodoList, Filesystem, SubAgent                  │      │
│  │  • Recursion Limit: 100                                       │      │
│  │  • Retry: до 3 попыток при таймаутах                          │      │
│  └────────────────────────┬──────────────────────────────────────┘      │
│                           │                                             │
├───────────────────────────┼─────────────────────────────────────────────┤
│  LAYER 3: Субагенты       │                                             │
│                           ▼                                             │
│  ┌────────────────┐ ┌────────────────┐ ┌─────────────────┐             │
│  │ service_       │ │ file_          │ │ connection_      │             │
│  │ analyzer       │ │ explorer       │ │ analyzer         │             │
│  │                │ │                │ │                  │             │
│  │ Анализ:        │ │ Исследование:  │ │ Анализ:          │             │
│  │ • Сервисы      │ │ • Файловая     │ │ • SSH-подключения│             │
│  │ • Пакеты       │ │   структура    │ │ • Auth-логи      │             │
│  │ • Cron-задачи  │ │ • Скрытые файлы│ │ • Сетевая        │             │
│  │                │ │ • Скрипты      │ │   активность     │             │
│  │ Tools: 8       │ │ • Бинарники    │ │ • IP-адреса      │             │
│  └────────────────┘ │                │ │                  │             │
│                     │ Tools: 8       │ │ Tools: 9         │             │
│  ┌────────────────┐ └────────────────┘ └─────────────────┘             │
│  │ history_       │                                                     │
│  │ analyzer       │                                                     │
│  │                │                                                     │
│  │ Анализ:        │                                                     │
│  │ • История      │                                                     │
│  │   команд       │                                                     │
│  │ • Публичные IP │                                                     │
│  │ • Подозритель- │                                                     │
│  │   ные команды  │                                                     │
│  │                │                                                     │
│  │ Tools: 7       │                                                     │
│  └────────────────┘                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Инструменты (Tools) — полная карта

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FORENSIC TOOLS                                  │
├─────────────┬───────────────────────────────────────────────────────────┤
│             │                                                           │
│  IMAGE      │  open_disk_image          — открыть образ диска           │
│  TOOLS      │  close_disk_image         — закрыть образ                 │
│  (pytsk3)   │  get_os_info              — определить ОС                 │
│             │  read_file_from_image     — прочитать файл из образа      │
│             │  list_directory_in_image  — листинг директории             │
│             │  extract_file_from_image  — извлечь файл                  │
│             │  get_file_metadata_from_image — метаданные файла          │
│             │  search_in_image_files    — поиск по файлам               │
│             │                                                           │
├─────────────┼───────────────────────────────────────────────────────────┤
│             │                                                           │
│  ARTIFACT   │  collect_os_info          — информация об ОС              │
│  TOOLS      │  collect_users_info       — пользователи, shadow, группы  │
│  (сбор      │  collect_command_history  — история команд всех юзеров    │
│  артефактов)│  collect_services_info    — systemd, init.d, rc.d         │
│             │  collect_cron_info        — cron-задачи                   │
│             │  collect_packages_info    — установленные пакеты          │
│             │  collect_docker_info      — Docker контейнеры/образы      │
│             │  collect_ssh_artifacts    — SSH ключи, authorized_keys    │
│             │  collect_network_config   — сетевая конфигурация          │
│             │  collect_auth_logs        — логи авторизации              │
│             │  collect_logs_info        — системные логи                │
│             │  extract_home_files       — файлы из /home/               │
│             │  clean_command_history    — очистка дубликатов            │
│             │  extract_log_file        — извлечение лог-файла          │
│             │  clear_tool_cache        — очистка кэша                  │
│             │                                                           │
├─────────────┼───────────────────────────────────────────────────────────┤
│             │                                                           │
│  ANALYSIS   │  extract_entities_from_text — извлечение IP, доменов,     │
│  TOOLS      │                              хешей из текста              │
│  (анализ)   │  parse_passwd_file        — парсинг /etc/passwd           │
│             │  parse_services_list      — парсинг списка сервисов       │
│             │  generate_file_ioc        — генерация IoC для файла       │
│             │  analyze_triage_data      — алгоритмический анализ        │
│             │  generate_html_report     — генерация HTML-отчёта         │
│             │                                                           │
├─────────────┼───────────────────────────────────────────────────────────┤
│             │                                                           │
│ INVESTIGA-  │  extract_public_ips       — публичные IP из текста        │
│ TION TOOLS  │  parse_ssh_successful_logins — успешные SSH-входы         │
│ (Deep Agent)│  get_investigation_context — текущий контекст             │
│             │  record_finding           — зафиксировать находку         │
│             │  record_explored_path     — отметить путь как проверенный │
│             │                                                           │
├─────────────┼───────────────────────────────────────────────────────────┤
│             │                                                           │
│ FILESYSTEM  │  calculate_file_hashes    — MD5, SHA1, SHA256             │
│ TOOLS       │  get_local_file_metadata  — метаданные локального файла   │
│ (локальная  │  read_local_file          — чтение локального файла       │
│  ФС)        │  write_local_file         — запись в локальный файл       │
│             │  list_local_directory     — листинг локальной директории  │
│             │  search_in_local_files    — поиск в локальных файлах      │
│             │                                                           │
└─────────────┴───────────────────────────────────────────────────────────┘
```

---

## 5. Система промптов

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PROMPT SYSTEM                                    │
│                        (src/agent/prompts.py)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐       │
│  │ FORENSIC_SYSTEM_PROMPT (Deep Agent)                         │       │
│  │                                                             │       │
│  │ Роль: Forensic Agent — AI-эксперт по кибербезопасности      │       │
│  │ Метод: Chain of Thought (Наблюдение → Гипотеза →            │       │
│  │        Проверка → Вывод)                                    │       │
│  │ Фазы: 1) Рекомендации  2) Исследование                      │       │
│  │        3) Корреляция    4) Детальный анализ                 │       │
│  │ Правила: record_finding, record_explored_path,              │       │
│  │          get_investigation_context обязательны              │       │
│  └─────────────────────────────────────────────────────────────┘       │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────┐       │
│  │ Промпты субагентов                                          │       │
│  │                                                             │       │
│  │  SERVICE_ANALYZER_PROMPT    — анализ сервисов, пакетов      │       │
│  │  FILE_EXPLORER_PROMPT       — анализ файловой структуры     │       │
│  │  CONNECTION_ANALYZER_PROMPT — анализ SSH/сети                │       │
│  │  HISTORY_ANALYZER_PROMPT    — анализ истории команд          │       │
│  └─────────────────────────────────────────────────────────────┘       │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐       │
│  │ Промпты для секций отчёта (Fallback LLM-анализ)             │       │
│  │                                                             │       │
│  │  ANALYZE_SERVICES_PROMPT        → JSON: сервисы             │       │
│  │  ANALYZE_CRON_PROMPT            → JSON: cron-задачи         │       │
│  │  ANALYZE_PACKAGES_PROMPT        → JSON: пакеты              │       │
│  │  ANALYZE_WEB_SOFTWARE_PROMPT    → JSON: веб-серверы/ПО      │       │
│  │  SUMMARIZE_USER_COMMANDS_PROMPT → текст: саммари юзера      │       │
│  │  IDENTIFY_NONSTANDARD_FILES_PROMPT → JSON: нестандартные     │       │
│  └─────────────────────────────────────────────────────────────┘       │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐       │
│  │ Управляющие промпты                                         │       │
│  │                                                             │       │
│  │  EVALUATE_ANALYSIS_PROMPT  — оценка достаточности анализа   │       │
│  │  build_deep_agent_task()   — формирование задания для        │       │
│  │                              Deep Agent                     │       │
│  └─────────────────────────────────────────────────────────────┘       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Структура HTML-отчёта

```
┌─────────────────────────────────────────────────────────────────────────┐
│         COMPREHENSIVE FORENSIC REPORT (HTML)                           │
│         (src/agent/report_generator.py)                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 🔍 Общая картина                                                   │
│     ├── Статистика (пользователи, команды, сервисы, аномалии)          │
│     ├── Обнаруженные аномалии (с severity-бейджами)                    │
│     └── Рекомендации                                                   │
│                                                                         │
│  2. 🖥️ Сведения о системе                                              │
│     ├── 2.1 Версия ОС (/etc/os-release)                               │
│     ├── 2.2 Пользователи и хеши паролей (/etc/passwd, /etc/shadow)    │
│     ├── 2.3 Системные сервисы (LLM-анализ нестандартных)               │
│     ├── 2.4 Запланированные задачи cron                                │
│     ├── 2.5 Подозрительные пакеты                                      │
│     ├── 2.6 Веб-серверы и специализированное ПО                        │
│     └── 2.7 Docker (контейнеры, образы)                                │
│                                                                         │
│  3. 📁 Информация о файлах                                              │
│     ├── 3.1 Нестандартные файлы в корне (/)                             │
│     ├── 3.2 Файловая структура /home/                                  │
│     ├── 3.3 Файловая структура /root/                                  │
│     └── 3.4 Нестандартные файлы пользователей                          │
│                                                                         │
│  4. 🌐 Подключения к системе (SSH)                                      │
│     ├── Успешные SSH-входы (таблица)                                   │
│     └── Сводка по IP-адресам                                           │
│                                                                         │
│  5. 👤 Активность пользователей                                         │
│     ├── 5.1 История команд (по пользователям)                          │
│     ├── 5.2 Публичные IP-адреса из команд                              │
│     └── 5.3 LLM-саммари по пользователям                              │
│                                                                         │
│  6. 🚨 Подозрительные находки                                           │
│     └── Все findings с severity, evidence, related_paths               │
│                                                                         │
│  7. 🧠 Экспертное заключение                                            │
│     ├── LLM экспертный анализ                                          │
│     └── Взаимосвязи и хронология (correlation)                         │
│                                                                         │
│  8. 🗺️ Исследованные пути                                               │
│     └── Таблица: путь, описание, подозрительность, время               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Структура файлов проекта

```
forensic_agent_local_fs/
├── run_agent.py                  # Точка входа — Simple Agent
├── run_deep_agent.py             # Точка входа — Deep Forensic Agent
├── requirements.txt              # Зависимости Python
├── configs/
│   └── triage.yaml               # Конфигурация путей артефактов
├── src/
│   ├── __init__.py
│   ├── main.py                   # ForensicPipeline — preprocessing образа
│   ├── agent/
│   │   ├── __init__.py           # Экспорт агентов и состояний
│   │   ├── state.py              # BaseAgentState, AgentState,
│   │   │                         # ForensicAgentState, TriageData,
│   │   │                         # InvestigatedPath, SuspiciousFinding,
│   │   │                         # sync_store_to_state
│   │   ├── simple_agent.py       # ForensicAgent — простой 5-узловой граф
│   │   ├── forensic_deep_agent.py# ForensicDeepAgent — 6-узловой граф
│   │   │                         # с итеративным циклом и Deep Agent SDK
│   │   ├── prompts.py            # Все промпты (system, subagents, report)
│   │   └── report_generator.py   # Генерация comprehensive HTML-отчёта
│   ├── preprocessing/
│   │   ├── __init__.py
│   │   └── image_processor.py    # ImageProcessor — конвертация образов
│   ├── tools/
│   │   ├── __init__.py           # Экспорт всех 40+ tools
│   │   ├── image_manager.py      # ImageManager (pytsk3) — доступ к образу
│   │   ├── image_tools.py        # 8 tools работы с образом
│   │   ├── artifact_tools.py     # 15 tools сбора артефактов
│   │   ├── analysis_tools.py     # 6 tools анализа данных
│   │   ├── investigation_tools.py# 5 tools + InvestigationStore
│   │   ├── filesystem_tools.py   # 6 tools локальной ФС
│   │   └── extract_fs.py         # Выгрузка ФС образа в локальную директорию
│   └── utils/
│       ├── __init__.py
│       ├── logger.py             # Логирование
│       ├── filesystem.py         # FileSystemUtils
│       └── message_history.py    # Callback для перехвата LLM-сообщений
├── output/                       # Выходные данные (отчёты, история сообщений)
├── extracted/                    # Извлечённые файлы
├── image_fs/                     # Выгруженная файловая система образа
└── logs/                         # Логи работы
```

---

## 8. Ключевые технологии и зависимости

| Компонент | Технология | Назначение |
|-----------|-----------|------------|
| Оркестрация | **LangGraph** (StateGraph) | Граф выполнения агента с условными рёбрами |
| LLM | **GigaChat-2-Max** (langchain-gigachat) | Экспертный анализ, оценка, генерация текста |
| Deep Agent | **deepagents SDK** (create_deep_agent) | Автономный агент с субагентами и middleware |
| Доступ к образу | **pytsk3** (The Sleuth Kit) | Чтение файловой системы из RAW-образа диска |
| Preprocessing | **qemu-img** (через subprocess) | Конвертация VMDK/QCOW2/VDI → RAW |
| Конфигурация | **YAML** (configs/triage.yaml) | Пути артефактов для сбора |
| Переменные окружения | **.env** (python-dotenv) | API-ключи GigaChat |
| Tools Framework | **langchain_core.tools** (@tool) | Декораторы инструментов для LLM |
