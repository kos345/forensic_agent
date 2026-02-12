# Forseti — Детальная схема AI-агента

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

## 2. Simple Agent — Граф LangGraph

**Файл:** `src/agent/simple_agent.py`  
**Состояние:** `AgentState` (наследует `BaseAgentState`)  
**Точка входа:** `run_agent.py`

```
                          ┌─────────┐
                          │  START  │
                          └────┬────┘
                               │
                               ▼
                    ┌────────────────────┐
                    │   open_image_node  │ ◄── Открытие образа диска
                    │                    │     через open_disk_image tool
                    └────────┬───────────┘
                             │
                    ┌────────┴────────┐
                    │ image_open?     │ (route_after_open)
                    ├── Yes ──────┐  │
                    │             │  ├── No ──► END
                    └─────────────┘  │
                                     │
                               ▼     │
                ┌──────────────────────────┐
                │  ollect_artifacts_nocde   │ ◄── Последовательный сбор
                │                          │     12 типов артефактов
                │  • collect_os_info       │     по triage.yaml
                │  • collect_users_info    │
                │  • collect_command_history│
                │  • collect_services_info │
                │  • collect_cron_info     │
                │  • collect_packages_info │
                │  • collect_docker_info   │
                │  • collect_ssh_artifacts │
                │  • collect_network_config│
                │  • collect_auth_logs     │
                │  • collect_logs_info     │
                │  • extract_home_files    │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │     analyze_node         │
                │                          │
                │  Шаг 1: Алгоритмический  │ ◄── analyze_triage_data
                │         анализ           │
                │                          │
                │  Шаг 2: LLM-анализ       │ ◄── GigaChat (GigaChatWrapper)
                │         через GigaChat   │     Экспертное заключение
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │  generate_report_node    │ ◄── Генерация HTML-отчёта
                │                          │     + сохранение JSON-данных
                │  • triage_data.json      │
                │  • analysis_result.json  │
                │  • report.html           │
                └────────────┬─────────────┘
                             │
                    ┌────────┴────────┐
                    │ image_open?     │ (route_after_report)
                    ├── Yes ──────┐  │
                    │             │  ├── No ──► END
                    └─────────────┘  │
                                     │
                               ▼     │
                    ┌────────────────────┐
                    │  close_image_node  │ ◄── Закрытие образа
                    └────────┬───────────┘
                             │
                             ▼
                          ┌─────┐
                          │ END │
                          └─────┘
```

---

## 3. Deep Forensic Agent — Граф LangGraph с итеративным циклом

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
                │   │  • 30+ forensic tools    │         │
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

## 4. Трёхуровневая архитектура Deep Agent

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
│  │  • Tools: 30+ forensic tools                                  │      │
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
│  │ Tools: 7       │ │ • Бинарники    │ │ • IP-адреса      │             │
│  └────────────────┘ │                │ │                  │             │
│                     │ Tools: 10      │ │ Tools: 8         │             │
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

## 5. Инструменты (Tools) — полная карта

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

## 6. Управление состоянием

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        STATE MANAGEMENT                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────┐                           │
│  │ BaseAgentState (TypedDict)              │                           │
│  │                                         │                           │
│  │  messages: List[Dict]      ← operator.add (аддитивный reducer)     │
│  │  image_path: str                        │                           │
│  │  image_open: bool                       │                           │
│  │  os_info: Optional[Dict]               │                           │
│  │  triage_data: Optional[Dict]           │                           │
│  │  analysis_result: Optional[Dict]       │                           │
│  │  report_path: Optional[str]            │                           │
│  │  current_step: str                      │                           │
│  │  errors: List[str]                      │                           │
│  └────────────────┬────────────────────────┘                           │
│                   │                                                     │
│          ┌────────┴────────┐                                           │
│          │                 │                                            │
│          ▼                 ▼                                            │
│  ┌──────────────┐  ┌──────────────────────────────────────┐           │
│  │ AgentState   │  │ ForensicAgentState                   │           │
│  │              │  │                                      │           │
│  │ (Simple      │  │ + recommendations: List[str]         │           │
│  │  Agent —     │  │ + investigated_paths: List[Dict]     │ ← add    │
│  │  без         │  │ + suspicious_findings: List[Dict]    │ ← add    │
│  │  дополнений) │  │ + llm_analyses: Dict[str, Any]      │           │
│  │              │  │ + report_data: Dict[str, Any]        │           │
│  └──────────────┘  │ + deep_agent_output: Optional[str]   │           │
│                    │ + analysis_iteration: int             │           │
│                    │ + max_iterations: int                 │           │
│                    └──────────────────────────────────────┘           │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐       │
│  │ Дополнительные модели данных                                │       │
│  │                                                             │       │
│  │  TriageData          — собранные артефакты (12 категорий)   │       │
│  │  InvestigatedPath    — запись об исследованном пути          │       │
│  │  SuspiciousFinding   — запись о подозрительной находке       │       │
│  └─────────────────────────────────────────────────────────────┘       │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐       │
│  │ InvestigationStore (синглтон)                               │       │
│  │                                                             │       │
│  │  Боковой канал данных для Deep Agent:                       │       │
│  │  • investigated_paths: List[InvestigatedPath]               │       │
│  │  • suspicious_findings: List[SuspiciousFinding]             │       │
│  │                                                             │       │
│  │  Дельта-синхронизация с ForensicAgentState:                 │       │
│  │  sync_store_to_state() → get_new_since_last_sync()          │       │
│  │  (водяные метки _synced_*_count)                            │       │
│  └─────────────────────────────────────────────────────────────┘       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Поток данных Deep Forensic Agent (детальная схема)

```
  ┌──────────────┐
  │ Пользователь │
  │ (CLI)        │
  └──────┬───────┘
         │  python run_deep_agent.py --image /path/to/disk.raw
         ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ run_deep_agent.py                                                │
  │                                                                  │
  │  1. Проверка prerequisites (пакеты, .env)                       │
  │  2. ForensicDeepAgent() → build_forensic_graph() → compile()    │
  │  3. app.invoke(initial_state)                                   │
  └──────────────────────┬───────────────────────────────────────────┘
                         │
   ═══════════════════════════════════════════════════════════════════
   ║                LangGraph Execution                              ║
   ═══════════════════════════════════════════════════════════════════
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ УЗЕЛ 1: open_image_node                                          │
  │                                                                  │
  │  open_disk_image(image_path)                                     │
  │       │                                                          │
  │       ▼                                                          │
  │  ImageManager.open_image() → pytsk3.Img_Info() + pytsk3.FS_Info()│
  │       │                                                          │
  │  state.image_open = True                                         │
  └──────────────────────┬───────────────────────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ УЗЕЛ 2: collect_baseline_node                                    │
  │                                                                  │
  │  ┌──────────────────────────────────┐                            │
  │  │ configs/triage.yaml              │ ◄── Пути артефактов        │
  │  │  artifacts:                      │                            │
  │  │    system: [/etc/os-release, ...]│                            │
  │  │    users: [/etc/passwd, ...]     │                            │
  │  │    history: [/home/*/.bash_hist.]│                            │
  │  │    services: [/etc/systemd/...]  │                            │
  │  │    ssh: [/etc/ssh, /home/*/.ssh] │                            │
  │  │    ...                           │                            │
  │  └──────────────────────────────────┘                            │
  │                                                                  │
  │  ┌──────────────────────────────────────────┐                    │
  │  │ Glob Resolution                          │                    │
  │  │ /home/*/.bash_history                    │                    │
  │  │   → list_directory(/home/)               │                    │
  │  │   → [/home/user1/.bash_history,          │                    │
  │  │      /home/user2/.bash_history, ...]     │                    │
  │  └──────────────────────────────────────────┘                    │
  │                                                                  │
  │  12 artifact_tools ──► TriageData (dataclass) ──► triage_data    │
  │                                                                  │
  │  analyze_triage_data(triage_json) ──► analysis_result            │
  │    • summary (статистика)                                        │
  │    • anomalies (аномалии по severity)                            │
  │    • recommendations (рекомендации для Deep Agent)               │
  │                                                                  │
  │  InvestigationStore.reset()                                      │
  └──────────────────────┬───────────────────────────────────────────┘
                         │
   ╔═════════════════════╧═══════════════════════════════════════════╗
   ║           ИТЕРАТИВНЫЙ ЦИКЛ ГЛУБОКОГО АНАЛИЗА                   ║
   ╚═════════════════════╤═══════════════════════════════════════════╝
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ УЗЕЛ 3: deep_analysis_node                                       │
  │                                                                  │
  │  build_deep_agent_task():                                        │
  │    • triage_summary (сводка артефактов)                          │
  │    • analysis_summary (результат алго-анализа)                   │
  │    • recommendations (что проверить)                             │
  │    • investigation_context (при итерации > 0)                    │
  │                                                                  │
  │  ┌────────────────────────────────────────────────────────────┐  │
  │  │ Deep Agent (deepagents SDK)                                │  │
  │  │                                                            │  │
  │  │  LLM: GigaChat-2-Max                                      │  │
  │  │  System Prompt: FORENSIC_SYSTEM_PROMPT                     │  │
  │  │  Метод: Chain of Thought + Reflection                      │  │
  │  │                                                            │  │
  │  │  Фаза 1: Выполнение рекомендаций                           │  │
  │  │    → list_directory_in_image("/")                           │  │
  │  │    → read_file_from_image(...)                              │  │
  │  │    → record_finding(category, severity, ...)               │  │
  │  │    → record_explored_path(path, description)               │  │
  │  │                                                            │  │
  │  │  Фаза 2: Самостоятельное исследование                      │  │
  │  │    → get_investigation_context()                            │  │
  │  │    → Проверка /tmp, /var/tmp, /dev/shm, /opt, /root        │  │
  │  │    → Поиск скрытых файлов, нестандартных директорий         │  │
  │  │                                                            │  │
  │  │  Фаза 3: Корреляция и связи                                │  │
  │  │    → Связывание IP-адресов, файлов, временных меток         │  │
  │  │    → Восстановление хронологии атаки                        │  │
  │  │                                                            │  │
  │  │  Делегирование субагентам:                                  │  │
  │  │    → service_analyzer(сервисы, пакеты, cron)               │  │
  │  │    → file_explorer(файловая структура)                      │  │
  │  │    → connection_analyzer(SSH, сеть)                         │  │
  │  │    → history_analyzer(история команд)                       │  │
  │  └────────────────────────────────────────────────────────────┘  │
  │                                                                  │
  │  Fallback (если deepagents SDK не установлен):                   │
  │  ┌────────────────────────────────────────────────────────────┐  │
  │  │ _fallback_llm_analysis():                                  │  │
  │  │  Прямой LLM-анализ GigaChat по 9 секциям:                  │  │
  │  │  1. Анализ сервисов (ANALYZE_SERVICES_PROMPT)              │  │
  │  │  2. Анализ cron (ANALYZE_CRON_PROMPT)                      │  │
  │  │  3. Анализ пакетов (ANALYZE_PACKAGES_PROMPT)               │  │
  │  │  4. Веб-серверы и ПО (ANALYZE_WEB_SOFTWARE_PROMPT)         │  │
  │  │  5. Саммари по пользователям (SUMMARIZE_USER_COMMANDS)      │  │
  │  │  6. Парсинг SSH-входов (parse_ssh_successful_logins)       │  │
  │  │  7. Извлечение публичных IP (extract_public_ips)           │  │
  │  │  8. Нестандартные файлы (IDENTIFY_NONSTANDARD_FILES)        │  │
  │  │  9. Экспертное заключение (общий промпт)                   │  │
  │  └────────────────────────────────────────────────────────────┘  │
  │                                                                  │
  │  sync_store_to_state(InvestigationStore)                         │
  │    → Дельта: только новые paths и findings                       │
  │    → Merge в ForensicAgentState через operator.add               │
  └──────────────────────┬───────────────────────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ УЗЕЛ 4: evaluate_analysis_node                                   │
  │                                                                  │
  │  EVALUATE_ANALYSIS_PROMPT:                                       │
  │    • Статистика находок (по severity)                            │
  │    • Количество исследованных путей                              │
  │    • Сводка по находкам и рекомендациям                          │
  │                                                                  │
  │  LLM-вердикт (GigaChat):                                        │
  │    {"verdict": "continue", "reason": "..."}                      │
  │    или                                                           │
  │    {"verdict": "sufficient", "reason": "..."}                    │
  │                                                                  │
  │  Правила:                                                        │
  │    • 0 findings → "continue"                                     │
  │    • < 5 paths → "continue"                                      │
  │    • critical/high без related_paths → "continue"                │
  │    • iteration >= max_iterations - 1 → "sufficient" (hard cap)   │
  │                                                                  │
  │  analysis_iteration += 1                                         │
  └──────────────────────┬───────────────────────────────────────────┘
                         │
                ┌────────┴────────┐
                │                 │
      "continue"│                 │"sufficient"
                │                 │
                ▼                 ▼
     ┌──────────────┐   ┌──────────────────┐
     │ deep_analysis │   │  generate_report │
     │ _node (↑)     │   │  _node           │
     │ (повторная    │   │                  │
     │  итерация)    │   │                  │
     └──────────────┘   └────────┬─────────┘
                                  │
   ═══════════════════════════════╧═══════════════════════════════════
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ УЗЕЛ 5: generate_report_node                                     │
  │                                                                  │
  │  Данные для отчёта:                                              │
  │    • triage_data (baseline артефакты)                            │
  │    • analysis_result (алгоритмический анализ)                    │
  │    • llm_analyses (LLM-анализ по секциям)                       │
  │    • investigated_paths (исследованные пути)                     │
  │    • suspicious_findings (подозрительные находки)                │
  │    • deep_agent_output (экспертное заключение)                   │
  │                                                                  │
  │  generate_comprehensive_html_report(report_data)                 │
  │    → 8 секций HTML-отчёта (см. раздел 9)                        │
  │                                                                  │
  │  Файлы: output/<timestamp>/                                      │
  │    • comprehensive_report.html                                   │
  │    • report_data.json                                            │
  │    • triage_data.json                                            │
  │    • analysis_result.json                                        │
  └──────────────────────┬───────────────────────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ УЗЕЛ 6: close_image_node                                         │
  │                                                                  │
  │  close_disk_image()                                              │
  │  state.image_open = False                                        │
  └──────────────────────┬───────────────────────────────────────────┘
                         │
                         ▼
                      ┌─────┐
                      │ END │
                      └─────┘
```

---

## 8. Система промптов

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PROMPT SYSTEM                                    │
│                        (src/agent/prompts.py)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐       │
│  │ FORENSIC_SYSTEM_PROMPT (Deep Agent)                         │       │
│  │                                                             │       │
│  │ Роль: Forseti — AI-агент-эксперт по кибербезопасности       │       │
│  │ Метод: Chain of Thought (Наблюдение → Гипотеза →            │       │
│  │        Проверка → Вывод)                                    │       │
│  │ Фазы: 1) Рекомендации  2) Исследование                     │       │
│  │        3) Корреляция    4) Детальный анализ                 │       │
│  │ Правила: record_finding, record_explored_path,              │       │
│  │          get_investigation_context обязательны              │       │
│  └─────────────────────────────────────────────────────────────┘       │
│                                                                         │
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

## 9. Структура HTML-отчёта

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

## 10. Структура файлов проекта

```
Forseti_cursor/
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
│   │   ├── state.py              # AgentState, ForensicAgentState, TriageData,
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
│   │   ├── __init__.py           # Экспорт всех 35+ tools
│   │   ├── image_manager.py      # ImageManager (pytsk3) — доступ к образу
│   │   ├── image_tools.py        # 8 tools работы с образом
│   │   ├── artifact_tools.py     # 15 tools сбора артефактов
│   │   ├── analysis_tools.py     # 6 tools анализа данных
│   │   ├── investigation_tools.py# 5 tools + InvestigationStore
│   │   └── filesystem_tools.py   # 6 tools локальной ФС
│   └── utils/
│       ├── __init__.py
│       ├── logger.py             # Логирование
│       └── filesystem.py         # FileSystemUtils
├── output/                       # Выходные данные (отчёты)
├── extracted/                    # Извлечённые файлы
└── logs/                         # Логи работы
```

---

## 11. Ключевые технологии и зависимости

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
