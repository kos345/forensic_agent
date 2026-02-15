"""
Forensic Deep Agent — Интеллектуальный AI-агент для криминалистического анализа.

Архитектура:
  Layer 1: LangGraph Orchestrator (ForensicAgentState)
    ├── open_image_node         (детерминированный: открытие образа + извлечение ФС)
    ├── collect_baseline_node   (детерминированный: triage.yaml + analyze_triage_data + log_analyzers)
    ├── deep_analysis_node      (Deep Agent: рекомендации → исследование → корреляция)
    ├── evaluate_analysis_node  (LLM-оценка: продолжить/завершить цикл)
    ├── generate_report_node    (формирование HTML-отчёта)
    └── close_image_node        (детерминированный)

  Layer 2: Deep Agent (create_agent + кастомный middleware)
    - GigaChat-2-Max + forensic tools
    - TodoListMiddleware + SubAgentMiddleware + SummarizationMiddleware + PatchToolCallsMiddleware

  Layer 3: Subagents
    - service_analyzer: анализ сервисов, пакетов, cron
    - file_explorer: исследование файловой структуры
    - connection_analyzer: анализ SSH-подключений
    - history_analyzer: анализ истории команд
    - file_content_analyzer: анализ содержимого файлов на malware

Использует:
  - deepagents (create_agent + middleware) — Deep Agent SDK
  - langgraph (StateGraph) — оркестрация workflow
  - langchain-gigachat (GigaChat-2-Max) — LLM
  - tools проекта: artifact_tools, analysis_tools, log_analyzers, investigation_tools, filesystem_tools
"""

import json
import os
import yaml
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Literal
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END

from src.agent.state import ForensicAgentState, TriageData, sync_store_to_state
from src.agent.prompts import (
    FORENSIC_SYSTEM_PROMPT,
    EVALUATE_ANALYSIS_PROMPT,
    SERVICE_ANALYZER_PROMPT,
    FILE_EXPLORER_PROMPT,
    CONNECTION_ANALYZER_PROMPT,
    HISTORY_ANALYZER_PROMPT,
    FILE_CONTENT_ANALYZER_PROMPT,
    build_deep_agent_task,
)
from src.tools.image_manager import get_image_manager
from src.tools import (
    # Image tools (used only by open/close nodes)
    open_disk_image,
    close_disk_image,
    # Artifact tools
    collect_os_info,
    collect_users_info,
    collect_command_history,
    collect_services_info,
    scan_home_files_for_malware,
    read_home_files_for_analysis,
    collect_cron_info,
    collect_packages_info,
    collect_docker_info,
    collect_ssh_artifacts,
    collect_network_config,
    collect_auth_logs,
    collect_logs_info,
    extract_home_files,
    clear_tool_cache,
    # Analysis tools
    extract_entities_from_text,
    parse_passwd_file,
    parse_services_list,
    analyze_triage_data,
    # Investigation tools
    extract_public_ips,
    parse_ssh_successful_logins,
    get_investigation_context,
    record_finding,
    record_explored_path,
    get_investigation_store,
    # Filesystem tools (used by Deep Agent for image FS analysis)
    calculate_file_hashes,
    get_local_file_metadata,
    read_local_file,
    write_local_file,
    list_local_directory,
    search_in_local_files,
    extract_image_fs,
    # Log analyzers
    analyze_utmp_logs,
    analyze_auth_logs_detailed,
    analyze_lastlog,
    analyze_dpkg_logs,
    analyze_history_commands,
    analyze_alternatives_logs,
    clear_log_analyzer_cache,
)
from src.tools.investigation_tools import is_public_ip
from src.utils.logger import get_logger
from src.utils.filesystem import FileSystemUtils
from src.utils.message_history import get_message_history

# Load environment variables
load_dotenv()

logger = get_logger("ForensicDeepAgent")
fs_utils = FileSystemUtils()


# ==================== CONSOLE OUTPUT ====================

class ConsoleColors:
    """ANSI цвета для консоли."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    SYSTEM = "\033[95m"
    USER = "\033[94m"
    ASSISTANT = "\033[92m"
    TOOL = "\033[93m"
    ERROR = "\033[91m"
    LLM = "\033[96m"
    SUCCESS = "\033[92m"
    WARNING = "\033[93m"
    INFO = "\033[96m"


def print_status(status: str, message: str):
    """Вывести статус операции."""
    symbols = {'success': ('✓', ConsoleColors.SUCCESS), 'error': ('✗', ConsoleColors.ERROR),
               'warning': ('⚠', ConsoleColors.WARNING), 'info': ('→', ConsoleColors.INFO)}
    symbol, color = symbols.get(status, ('→', ConsoleColors.INFO))
    print(f"{color}{symbol} {message}{ConsoleColors.RESET}")


def print_phase(phase: str, description: str):
    """Вывести заголовок фазы."""
    print(f"\n{ConsoleColors.BOLD}{'─'*60}{ConsoleColors.RESET}")
    print(f"{ConsoleColors.LLM}🔬 [{phase}] {description}{ConsoleColors.RESET}")
    print(f"{ConsoleColors.BOLD}{'─'*60}{ConsoleColors.RESET}")


# ==================== GIGACHAT LLM ====================

def create_gigachat_llm():
    """
    Создать экземпляр GigaChat LLM для использования в Deep Agent.
    
    Параметры из .env:
    - GIGACHAT_CREDENTIALS: API ключ (обязательно)
    - GIGACHAT_MODEL: модель (по умолчанию GigaChat-2-Max)
    - GIGACHAT_TEMPERATURE: температура (по умолчанию 0.2)
    - GIGACHAT_MAX_TOKENS: максимум токенов (по умолчанию 8192)
    
    Returns:
        GigaChat BaseChatModel instance
    """
    credentials = os.getenv("GIGACHAT_CREDENTIALS")
    if not credentials:
        raise ValueError(
            "GIGACHAT_CREDENTIALS not found in environment. "
            "Please create .env file with your GigaChat API key."
        )
    
    try:
        from langchain_gigachat import GigaChat
    except ImportError:
        raise RuntimeError(
            "langchain_gigachat is required. Install: pip install langchain-gigachat"
        )
    
    verify_ssl_env = os.getenv("GIGACHAT_VERIFY_SSL", "true").strip().lower()
    verify_ssl = verify_ssl_env not in {"0", "false", "no", "off"}
    
    gigachat_timeout = float(os.getenv("GIGACHAT_TIMEOUT", "1800"))
    max_tokens = int(os.getenv("GIGACHAT_MAX_TOKENS", "8192"))
    # Минимальное значение max_tokens для корректной работы Deep Agent
    if max_tokens < 8192:
        max_tokens = 8192
    kwargs = {
        "credentials": credentials,
        "model": os.getenv("GIGACHAT_MODEL", "GigaChat-2-Max"),
        "temperature": float(os.getenv("GIGACHAT_TEMPERATURE", "0.2")),
        "max_tokens": max_tokens,
        "verify_ssl_certs": verify_ssl,
        "timeout": gigachat_timeout,
    }
    
    base_url = os.getenv("GIGACHAT_BASE_URL")
    scope = os.getenv("GIGACHAT_SCOPE")
    ca_bundle = os.getenv("GIGACHAT_CA_BUNDLE")
    
    if base_url:
        kwargs["base_url"] = base_url
    if scope:
        kwargs["scope"] = scope
    if ca_bundle:
        kwargs["ca_bundle_file"] = ca_bundle
    
    # Привязываем callback для логирования сообщений (если включён)
    handler = get_message_history()
    if handler:
        kwargs["callbacks"] = [handler]
    
    llm = GigaChat(**kwargs)
    logger.info(f"GigaChat LLM created: model={kwargs['model']}, timeout={gigachat_timeout}")
    return llm


# ==================== TOOL OUTPUT TRUNCATION ====================

MAX_TOOL_OUTPUT_CHARS = 6000  # ≈ 2048 токенов для русского/JSON текста


def _truncate_tool_output(text: str, max_chars: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Обрезать вывод инструмента до ~2048 токенов."""
    if not isinstance(text, str) or len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n\n...[вывод обрезан: {len(text)} → {max_chars} символов (~2048 токенов)]"


def _wrap_with_truncation(tool, max_chars: int = MAX_TOOL_OUTPUT_CHARS):
    """Обернуть LangChain tool для обрезки вывода до ~2048 токенов.

    Создаёт новый StructuredTool с той же схемой аргументов,
    но обрезающий результат если он превышает max_chars.
    """
    from langchain_core.tools import StructuredTool

    original_func = tool.func

    def truncated_func(*args, **kwargs):
        result = original_func(*args, **kwargs)
        return _truncate_tool_output(result, max_chars)

    return StructuredTool.from_function(
        func=truncated_func,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        infer_schema=False,
    )


# ==================== DEEP AGENT FACTORY ====================

def get_all_forensic_tools() -> list:
    """Получить список forensic tools для Deep Agent (только ФС и анализ).
    """
    return [
        # Работа с файловой системой образа (выгружена в image_fs/)
        read_local_file,
        list_local_directory,
        get_local_file_metadata,
        search_in_local_files,
        calculate_file_hashes,
        write_local_file,
        # Анализ и парсинг
        extract_entities_from_text,
        parse_passwd_file,
        parse_services_list,
        extract_public_ips,
        parse_ssh_successful_logins,
        # Управление расследованием
        get_investigation_context,
        record_finding,
        record_explored_path,
    ]


def create_forensic_deep_agent(llm=None, image_fs_dir: str = "image_fs"):
    """
    Создать Deep Agent для криминалистического анализа.

    Использует create_agent (не create_deep_agent) с кастомным middleware стеком
    БЕЗ FilesystemMiddleware — чтобы GigaChat не видел виртуальные ФС-инструменты
    (read_file, ls, edit_file, glob, grep) и вызывал только forensic-инструменты.

    Middleware стек:
    - TodoListMiddleware — планирование задач
    - SubAgentMiddleware — делегирование 5 субагентам + general-purpose
    - SummarizationMiddleware — сжатие контекста (критично для GigaChat)
    - PatchToolCallsMiddleware — исправление tool calls

    Args:
        llm: BaseChatModel instance (если None, создаётся GigaChat)
        image_fs_dir: Путь к локальной директории с выгруженной ФС образа

    Returns:
        CompiledStateGraph — скомпилированный Deep Agent
    """
    from langchain.agents import create_agent
    from langchain.agents.middleware import TodoListMiddleware
    from deepagents.backends import StateBackend
    from deepagents.middleware.subagents import SubAgentMiddleware, GENERAL_PURPOSE_SUBAGENT
    from deepagents.middleware.summarization import SummarizationMiddleware, _compute_summarization_defaults
    from deepagents.middleware.patch_tool_calls import PatchToolCallsMiddleware

    if llm is None:
        llm = create_gigachat_llm()

    # Оборачиваем все инструменты для обрезки вывода до ~2048 токенов
    raw_tools = get_all_forensic_tools()
    tools = [_wrap_with_truncation(t) for t in raw_tools]
    _t = {t.name: t for t in tools}  # маппинг по имени для субагентов

    # Форматируем системный промпт с путём к выгруженной ФС
    system_prompt = FORENSIC_SYSTEM_PROMPT.format(image_fs_dir=image_fs_dir)

    # Backend и настройки суммаризации
    backend = lambda rt: StateBackend(rt)
    summarization_defaults = _compute_summarization_defaults(llm)

    def _build_subagent_middleware():
        """Middleware стек для субагентов (без FilesystemMiddleware)."""
        return [
            TodoListMiddleware(),
            SummarizationMiddleware(
                model=llm,
                backend=backend,
                trigger=summarization_defaults["trigger"],
                keep=summarization_defaults["keep"],
                trim_tokens_to_summarize=None,
                truncate_args_settings=summarization_defaults["truncate_args_settings"],
            ),
            PatchToolCallsMiddleware(),
        ]

    # Субагенты с явным middleware (без FilesystemMiddleware), обрезанными инструментами
    subagents = [
        # General-purpose субагент (fallback для задач вне специализации)
        {
            **GENERAL_PURPOSE_SUBAGENT,
            "model": llm,
            "tools": tools,
            "middleware": _build_subagent_middleware(),
        },
        {
            "name": "service_analyzer",
            "description": (
                "Анализирует системные сервисы, пакеты и cron-задачи. "
                "Определяет нестандартные и подозрительные сервисы. "
                "Используй для детального анализа списков сервисов, пакетов и cron."
            ),
            "model": llm,
            "tools": [
                _t['read_local_file'], _t['list_local_directory'], _t['search_in_local_files'],
                _t['record_finding'], _t['record_explored_path'], _t['get_investigation_context'],
            ],
            "system_prompt": SERVICE_ANALYZER_PROMPT,
            "middleware": _build_subagent_middleware(),
        },
        {
            "name": "file_explorer",
            "description": (
                "Исследует файловую структуру образа диска (выгружена в локальную папку). "
                "Находит нестандартные директории и файлы, скрытые файлы, "
                "подозрительные скрипты и бинарники. "
                "Используй для исследования конкретных директорий."
            ),
            "model": llm,
            "tools": [
                _t['read_local_file'], _t['list_local_directory'],
                _t['get_local_file_metadata'], _t['search_in_local_files'],
                _t['calculate_file_hashes'],
                _t['record_finding'], _t['record_explored_path'], _t['get_investigation_context'],
            ],
            "system_prompt": FILE_EXPLORER_PROMPT,
            "middleware": _build_subagent_middleware(),
        },
        {
            "name": "connection_analyzer",
            "description": (
                "Анализирует SSH-подключения и сетевую активность. "
                "Парсит auth-логи, извлекает IP-адреса, определяет подозрительные соединения. "
                "Используй для анализа сетевых данных и логов авторизации."
            ),
            "model": llm,
            "tools": [
                _t['read_local_file'], _t['list_local_directory'],
                _t['parse_ssh_successful_logins'], _t['extract_public_ips'],
                _t['extract_entities_from_text'],
                _t['record_finding'], _t['record_explored_path'], _t['get_investigation_context'],
            ],
            "system_prompt": CONNECTION_ANALYZER_PROMPT,
            "middleware": _build_subagent_middleware(),
        },
        {
            "name": "history_analyzer",
            "description": (
                "Анализирует историю команд пользователей. "
                "Извлекает публичные IP-адреса, выявляет подозрительные команды, "
                "составляет саммари активности каждого пользователя. "
                "Используй для детального анализа истории команд."
            ),
            "model": llm,
            "tools": [
                _t['read_local_file'], _t['list_local_directory'],
                _t['extract_public_ips'], _t['extract_entities_from_text'],
                _t['record_finding'], _t['record_explored_path'], _t['get_investigation_context'],
            ],
            "system_prompt": HISTORY_ANALYZER_PROMPT,
            "middleware": _build_subagent_middleware(),
        },
        {
            "name": "file_content_analyzer",
            "description": (
                "Анализирует содержимое файлов из домашних директорий на malware-паттерны. "
                "Обнаруживает reverse shell, backdoor, криптомайнеры, обфускацию. "
                "ОБЯЗАТЕЛЬНО вызови для каждого батча файлов из /root/ и /home/*/. "
                "Передай ему содержимое файлов в текстовом виде."
            ),
            "model": llm,
            "tools": [
                _t['record_finding'], _t['record_explored_path'], _t['get_investigation_context'],
                _t['read_local_file'], _t['list_local_directory'],
            ],
            "system_prompt": FILE_CONTENT_ANALYZER_PROMPT,
            "middleware": _build_subagent_middleware(),
        },
    ]

    # Основной middleware стек (без FilesystemMiddleware)
    main_middleware = [
        TodoListMiddleware(),
        SubAgentMiddleware(backend=backend, subagents=subagents),
        SummarizationMiddleware(
            model=llm,
            backend=backend,
            trigger=summarization_defaults["trigger"],
            keep=summarization_defaults["keep"],
            trim_tokens_to_summarize=None,
            truncate_args_settings=summarization_defaults["truncate_args_settings"],
        ),
        PatchToolCallsMiddleware(),
    ]

    agent = create_agent(
        llm,
        system_prompt=system_prompt,
        tools=tools,
        middleware=main_middleware,
        name="forensic_deep_agent",
    ).with_config({"recursion_limit": 1000})

    logger.info("Forensic Deep Agent created with 5 subagents (incl. general-purpose)")
    return agent


# ==================== CONFIG & GLOB RESOLUTION ====================

def _load_triage_config() -> Dict:
    """Загрузить конфигурацию из configs/triage.yaml."""
    config_paths = [
        Path("configs/triage.yaml"),
        Path(__file__).parent.parent.parent / "configs" / "triage.yaml",
    ]
    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                logger.info(f"Loaded triage config from {config_path}")
                return config or {}
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
    logger.warning("triage.yaml not found, using default paths")
    return {}


def _resolve_image_globs(paths: List[str]) -> List[str]:
    """Разрешить glob-паттерны в путях образа."""
    manager = get_image_manager()
    resolved = []
    for path in paths:
        if '*' not in path:
            resolved.append(path)
            continue
        parts = path.split('/')
        glob_idx = next(i for i, p in enumerate(parts) if '*' in p)
        parent = '/'.join(parts[:glob_idx]) or '/'
        suffix = '/'.join(parts[glob_idx + 1:])
        entries = manager.list_directory(parent)
        for entry in entries:
            if entry['type'] == 'directory' and entry['name'] not in ('.', '..'):
                full_path = f"{parent.rstrip('/')}/{entry['name']}"
                if suffix:
                    full_path += f"/{suffix}"
                resolved.append(full_path)
    return resolved


# ==================== SUMMARY BUILDERS ====================

def _build_enriched_baseline_context(triage_data: Dict, analysis_result: Dict) -> str:
    """Сформировать обогащённую сводку baseline-данных для Deep Agent.

    Включает конкретные аномалии с деталями (команды, пользователи, сервисы),
    а не только подсчёты. Оптимизирована по размеру для контекстного окна GigaChat.
    """
    if not analysis_result:
        return "Базовый анализ не выполнен."

    parts = []

    # --- ОС ---
    os_info = triage_data.get('os_info', {})
    if os_info:
        os_release = os_info.get('/etc/os-release', '')
        if os_release:
            for line in os_release.split('\n'):
                if line.startswith('PRETTY_NAME='):
                    os_ = line.split('=', 1)[1].strip('\"')
                    parts.append(f"ОС: {os_}")
                    break

    # --- Статистика ---
    summary = analysis_result.get('summary', {})
    stats_items = []
    if summary.get('total_users'):
        stats_items.append(f"пользователей: {summary['total_users']}")
    if summary.get('total_commands'):
        stats_items.append(f"команд в истории: {summary['total_commands']}")
    if summary.get('total_services'):
        stats_items.append(f"сервисов: {summary['total_services']}")
    if stats_items:
        parts.append(f"Статистика: {', '.join(stats_items)}")

    # --- Docker ---
    docker = triage_data.get('docker', {})
    if docker and docker.get('docker_installed'):
        parts.append(f"Docker: установлен, контейнеров: {len(docker.get('containers', []))}")

    # --- SSH ---
    ssh = triage_data.get('ssh', {})
    if ssh and ssh.get('authorized_keys'):
        parts.append(f"SSH: {len(ssh['authorized_keys'])} пользователей с authorized_keys")

    # --- Аномалии (главная часть) ---
    anomalies = analysis_result.get('anomalies', [])
    if anomalies:
        by_severity: Dict[str, list] = {}
        for a in anomalies:
            sev = a.get('severity', 'medium').lower()
            by_severity.setdefault(sev, []).append(a)

        parts.append(f"\n=== ОБНАРУЖЕННЫЕ АНОМАЛИИ ({len(anomalies)}) ===")

        shown = 0
        max_total = 50
        for sev in ['critical', 'high', 'medium', 'low']:
            items = by_severity.get(sev, [])
            if not items:
                continue
            parts.append(f"\n[{sev.upper()}] — {len(items)} шт:")
            limit = len(items) if sev in ('critical', 'high') else min(len(items), max_total - shown)
            for a in items[:limit]:
                atype = a.get('type', '?')
                line_parts = [f"  - {atype}"]
                if a.get('user'):
                    line_parts.append(f"user={a['user']}")
                if a.get('command'):
                    line_parts.append(f"cmd: {a['command']}")
                if a.get('description'):
                    line_parts.append(a['description'])
                if a.get('service'):
                    line_parts.append(f"service={a['service']}")
                if a.get('pattern'):
                    line_parts.append(f"pattern={a['pattern']}")
                parts.append(" | ".join(line_parts))
                shown += 1
            if len(items) > limit:
                parts.append(f"  ... и ещё {len(items) - limit}")
    else:
        parts.append("\nАномалий не обнаружено алгоритмическим анализом.")

    return "\n".join(parts)


# ==================== GRAPH NODES ====================

def _cb_config(node: str) -> Optional[dict]:
    """Собрать callback config для прямых tool.invoke() вызовов в graph-нодах."""
    handler = get_message_history()
    if not handler:
        return None
    handler.set_current_node(node)
    return {"callbacks": [handler]}


def open_image_node(state: ForensicAgentState) -> Dict:
    """Узел открытия образа диска."""
    print_phase("OPEN", f"Открытие образа: {state['image_path']}")
    
    cb = _cb_config("open_image")
    messages = []
    result_json = open_disk_image.invoke({"image_path": state['image_path']}, config=cb)
    result = json.loads(result_json)
    
    messages.append({'role': 'tool', 'tool': 'open_disk_image', 'content': result_json})
    
    if result.get('success'):
        print_status('success', "Образ открыт успешно")
        fs_extract_depth = state.get("fs_extract_depth", 5)
        project_root = Path(__file__).resolve().parent.parent.parent
        image_fs_dir = project_root / "image_fs"
        # Пропускаем выгрузку если папка уже существует и не пуста
        if image_fs_dir.is_dir() and any(image_fs_dir.iterdir()):
            print_status('info', f"Папка {image_fs_dir} уже содержит данные — выгрузка пропущена")
        else:
            print_status('info', f"Выгрузка файловой системы в {image_fs_dir} (глубина: {fs_extract_depth})")
            extract_result = extract_image_fs(output_dir=str(image_fs_dir), max_depth=fs_extract_depth)
            if extract_result.get("success"):
                stats = extract_result.get("stats", {})
                print_status(
                    'success',
                    f"ФС выгружена: dirs={stats.get('dirs_created', 0)}, files={stats.get('files_extracted', 0)}, "
                    f"failed={stats.get('files_failed', 0)}",
                )
            else:
                print_status('warning', f"Выгрузка ФС завершилась с ошибкой: {extract_result.get('error')}")
                messages.append(
                    {
                        'role': 'tool',
                        'tool': 'extract_image_fs',
                        'content': json.dumps(extract_result, ensure_ascii=False),
                    }
                )
        return {
            'messages': messages,
            'image_open': True,
            'current_step': 'collect_baseline',
        }
    else:
        print_status('error', f"Ошибка открытия образа: {result.get('error')}")
        return {
            'messages': messages,
            'image_open': False,
            'errors': [f"Failed to open image: {result.get('error')}"],
            'current_step': 'error',
        }


def collect_baseline_node(state: ForensicAgentState) -> Dict:
    """
    Узел сбора базовых данных (Фаза 1).
    
    Выполняет:
    1. Сбор всех артефактов по triage.yaml (детерминированный)
    2. Алгоритмический анализ (analyze_triage_data)
    3. Формирование рекомендаций
    """
    print_phase("BASELINE", "Сбор базовых артефактов из triage.yaml")
    
    cb = _cb_config("collect_baseline")
    messages = []
    triage = TriageData()
    
    # Загружаем конфигурацию
    config = _load_triage_config()
    artifacts_cfg = config.get('artifacts', {})
    logs_cfg = artifacts_cfg.get('logs', {})
    
    # Разрешаем glob-паттерны
    history_paths = _resolve_image_globs(artifacts_cfg.get('history', []))
    ssh_paths = _resolve_image_globs(artifacts_cfg.get('ssh', []))
    
    # Список инструментов сбора
    artifact_tools = [
        ('collect_os_info', collect_os_info, {'paths': artifacts_cfg.get('system')}),
        ('collect_users_info', collect_users_info, {'paths': artifacts_cfg.get('users')}),
        ('collect_command_history', collect_command_history, {'history_paths': history_paths or None}),
        ('collect_services_info', collect_services_info, {'paths': artifacts_cfg.get('services')}),
        ('collect_cron_info', collect_cron_info, {'paths': artifacts_cfg.get('cron')}),
        ('collect_packages_info', collect_packages_info, {'paths': artifacts_cfg.get('packages')}),
        ('collect_docker_info', collect_docker_info, {'paths': artifacts_cfg.get('docker')}),
        ('collect_ssh_artifacts', collect_ssh_artifacts, {'paths': ssh_paths or None}),
        ('collect_network_config', collect_network_config, {'paths': artifacts_cfg.get('network')}),
        ('collect_auth_logs', collect_auth_logs, {}),
        ('collect_logs_info', collect_logs_info, {
            'var_paths': logs_cfg.get('var') if logs_cfg else None,
            'www_paths': logs_cfg.get('www') if logs_cfg else None,
        }),
        ('extract_home_files', extract_home_files, {}),
    ]
    
    for tool_name, tool_func, tool_args in artifact_tools:
        print_status('info', f"Запуск {tool_name}...")
        try:
            filtered_args = {k: v for k, v in tool_args.items() if v is not None}
            invoke_args = filtered_args if filtered_args else {}
            result_json = tool_func.invoke(invoke_args, config=cb)
            result = json.loads(result_json)
            triage.update_from_tool_result(tool_name, result)
            messages.append({'role': 'tool', 'tool': tool_name, 'content': result_json})
            
            if result.get('success', True):
                print_status('success', f"{tool_name} завершён")
            else:
                print_status('warning', f"{tool_name}: {result.get('error', 'unknown')}")
        except Exception as e:
            print_status('error', f"{tool_name} ошибка: {e}")
            triage.collection_errors.append(f"{tool_name}: {str(e)}")
    
    triage_data = triage.to_dict()
    
    # Алгоритмический анализ
    print_status('info', "Запуск алгоритмического анализа (analyze_triage_data)...")
    triage_json = json.dumps(triage_data, ensure_ascii=False)
    analysis_json = analyze_triage_data.invoke({'triage_data_json': triage_json}, config=cb)
    analysis_result = json.loads(analysis_json)
    
    recommendations = analysis_result.get('recommendations', [])
    anomalies = analysis_result.get('anomalies', [])
    
    print_status('success', f"Базовый анализ: {len(anomalies)} аномалий, {len(recommendations)} рекомендаций")
    
    # Сбрасываем хранилище расследования и засеиваем аномалиями из baseline
    store = get_investigation_store()
    store.reset()

    for anomaly in anomalies:
        atype = anomaly.get('type', 'unknown')
        severity = anomaly.get('severity', 'medium')

        if atype == 'suspicious_command':
            title = f"Подозрительная команда ({anomaly.get('pattern', '?')})"
            details = f"Пользователь {anomaly.get('user', '?')} выполнил: {anomaly.get('command', '?')}"
            category = 'command'
        elif atype == 'suspicious_user':
            title = f"Пользователь с UID 0: {anomaly.get('user', '?')}"
            details = anomaly.get('description', '')
            category = 'user'
        elif atype == 'suspicious_service':
            title = f"Подозрительный сервис: {anomaly.get('service', '?')}"
            details = (
                f"Сервис '{anomaly.get('service', '?')}' содержит паттерн "
                f"'{anomaly.get('pattern', '?')}' (расположение: {anomaly.get('location', '?')})"
            )
            category = 'service'
        elif atype == 'suspicious_file':
            title = f"Подозрительный файл: {anomaly.get('file', '?')}"
            details = anomaly.get('description', f"Имя файла содержит паттерн '{anomaly.get('pattern', '?')}'")
            category = 'file'
        else:
            title = anomaly.get('description', atype)[:100]
            details = json.dumps(anomaly, ensure_ascii=False)
            category = atype

        evidence = []
        if anomaly.get('command'):
            evidence.append(anomaly['command'])

        store.add_finding(
            category=category,
            severity=severity,
            title=title,
            details=details,
            evidence=evidence,
        )

    if anomalies:
        print_status('info', f"Засеяно {len(anomalies)} находок из baseline в InvestigationStore")

    # ==================== ДЕТАЛЬНЫЙ АНАЛИЗ ЛОГОВ ====================
    print_status('info', "Запуск детального анализа логов...")
    log_analysis: Dict[str, Any] = {}
    log_tools = [
        ('analyze_utmp_logs', analyze_utmp_logs, {}),
        ('analyze_auth_logs_detailed', analyze_auth_logs_detailed, {}),
        ('analyze_lastlog', analyze_lastlog, {}),
        ('analyze_dpkg_logs', analyze_dpkg_logs, {}),
        ('analyze_history_commands', analyze_history_commands, {}),
        ('analyze_alternatives_logs', analyze_alternatives_logs, {}),
    ]
    for log_tool_name, log_tool_func, log_tool_args in log_tools:
        try:
            result_json = log_tool_func.invoke(log_tool_args, config=cb)
            result = json.loads(result_json)
            log_analysis[log_tool_name] = result
            if result.get('success'):
                print_status('success', f"{log_tool_name} завершён")
            else:
                print_status('warning', f"{log_tool_name}: {result.get('error', 'unknown')}")
        except Exception as e:
            print_status('error', f"{log_tool_name} ошибка: {e}")
            log_analysis[log_tool_name] = {'success': False, 'error': str(e)}

    # Записываем результаты логанализа в triage_data для отчёта
    triage_data['log_analysis'] = log_analysis

    # --- Фиксация находок и исследованных путей из логанализа ---
    _record_log_analysis_findings(log_analysis, store)

    messages.append({
        'role': 'assistant',
        'content': f"Baseline сбор завершён. Аномалий: {len(anomalies)}, рекомендаций: {len(recommendations)}.",
    })

    return {
        'messages': messages,
        'triage_data': triage_data,
        'analysis_result': analysis_result,
        'recommendations': recommendations,
        'current_step': 'deep_analysis',
    }


def deep_analysis_node(state: ForensicAgentState) -> Dict:
    """
    Узел глубокого анализа с помощью Deep Agent (Фазы 2-4).
    
    Создаёт Deep Agent и передаёт ему:
    - Сводку собранных данных
    - Результат алгоритмического анализа
    - Рекомендации
    - Текущий контекст расследования (включая находки из предыдущих итераций)
    
    Deep Agent самостоятельно:
    1. Выполняет рекомендации
    2. Исследует неизученные области
    3. Ищет взаимосвязи
    4. Формирует детальный анализ для отчёта
    
    При повторных итерациях (analysis_iteration > 0) Deep Agent получает
    контекст предыдущих находок и исследованных путей, чтобы
    сфокусироваться на неисследованных областях.
    """
    iteration = state.get('analysis_iteration', 0)
    max_iter = state.get('max_iterations', 3)
    print_phase("DEEP ANALYSIS", f"Запуск Deep Agent (итерация {iteration + 1}/{max_iter})")
    
    messages = []
    triage_data = state.get('triage_data', {})
    analysis_result = state.get('analysis_result', {})
    recommendations = state.get('recommendations', [])
    
    # Формируем задание для Deep Agent
    # Обогащённый контекст baseline с конкретными аномалиями
    baseline_context = _build_enriched_baseline_context(triage_data, analysis_result)

    # На повторных итерациях — компактная сводка + инструкция вызвать get_investigation_context()
    investigation_context = ""
    if iteration > 0:
        prior_paths = state.get('investigated_paths', [])
        prior_findings = state.get('suspicious_findings', [])
        ctx_parts = [
            f"Итерация {iteration + 1}/{max_iter}.",
            f"Исследовано путей: {len(prior_paths)}",
            f"Подозрительных находок: {len(prior_findings)}",
        ]
        severity_counts: Dict[str, int] = {}
        for f in prior_findings:
            sev = f.get('severity', 'info').lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if severity_counts:
            sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
            ctx_parts.append(f"По уровням: {sev_str}")
        ctx_parts.append("")
        ctx_parts.append("Вызови get_investigation_context() для полного списка находок и исследованных путей.")
        ctx_parts.append("Сфокусируйся на НЕИССЛЕДОВАННЫХ областях и углублённом анализе имеющихся находок.")
        investigation_context = "\n".join(ctx_parts)

    # Путь к выгруженной ФС образа
    project_root = Path(__file__).resolve().parent.parent.parent
    image_fs_dir = str(project_root / "image_fs")

    # Читаем файлы из home/root для передачи субагенту file_content_analyzer
    # Только на первой итерации — повторно анализировать те же файлы не нужно
    home_files_batches: List[List[Dict]] = []
    MAX_FILE_BATCHES = 3
    if iteration == 0:
        try:
            home_files = read_home_files_for_analysis(image_fs_dir=image_fs_dir)
            if home_files:
                # Разбиваем на батчи (~2000 токенов ≈ ~4000 символов на батч)
                max_batch_chars = 4000
                current_batch: List[Dict] = []
                current_chars = 0
                for f in home_files:
                    file_chars = len(f['content']) + len(f['path']) + 50  # overhead
                    if current_batch and current_chars + file_chars > max_batch_chars:
                        home_files_batches.append(current_batch)
                        current_batch = []
                        current_chars = 0
                    current_batch.append(f)
                    current_chars += file_chars
                if current_batch:
                    home_files_batches.append(current_batch)
                # Ограничиваем количество батчей (макс. MAX_FILE_BATCHES)
                # Если батчей больше — объединяем хвостовые в последний батч
                if len(home_files_batches) > MAX_FILE_BATCHES:
                    merged_tail: List[Dict] = []
                    for extra_batch in home_files_batches[MAX_FILE_BATCHES - 1:]:
                        merged_tail.extend(extra_batch)
                    home_files_batches = home_files_batches[:MAX_FILE_BATCHES - 1] + [merged_tail]
                print_status('info', f"Файлы для file_content_analyzer: {len(home_files)} файлов, {len(home_files_batches)} батчей")
        except Exception as e:
            print_status('warning', f"Не удалось прочитать файлы для file_content_analyzer: {e}")

    task_message = build_deep_agent_task(
        baseline_context=baseline_context,
        recommendations=recommendations,
        investigation_context=investigation_context,
        image_fs_dir=image_fs_dir,
        home_files_batches=home_files_batches if home_files_batches else None,
    )
    
    print_status('info', "Создание Deep Agent...")
    
    # Очищаем кэш инструментов от предыдущих запусков
    clear_tool_cache()
    clear_log_analyzer_cache()
    
    deep_agent_output = None
    llm_analyses = {}
    
    # Конфиг для deep_agent.invoke() — с callbacks для real-time логирования
    _handler = get_message_history()
    _invoke_config: Dict[str, Any] = {"recursion_limit": 100}
    if _handler:
        _invoke_config["callbacks"] = [_handler]
    
    try:
        # Создаём Deep Agent (callback уже привязан к LLM через create_gigachat_llm)
        llm = create_gigachat_llm()
        deep_agent = create_forensic_deep_agent(llm=llm, image_fs_dir=image_fs_dir)
        
        print_status('success', "Deep Agent создан. Запуск анализа...")
        print_status('info', "Это может занять несколько минут...")
        
        # Запускаем Deep Agent с ретраями при ReadTimeout
        max_retries = 3
        result = None
        for _attempt in range(1, max_retries + 1):
            try:
                if _attempt > 1:
                    print_status('warning', f"Повторная попытка {_attempt}/{max_retries}...")
                    # Пересоздаём Deep Agent с увеличенным таймаутом
                    llm = create_gigachat_llm()
                    deep_agent = create_forensic_deep_agent(llm=llm, image_fs_dir=image_fs_dir)
                
                result = deep_agent.invoke(
                    {"messages": [{"role": "user", "content": task_message}]},
                    config=_invoke_config,
                )
                
                # Проверяем, были ли tool_calls (Deep Agent может просто написать текст)
                _tc = 0
                if result and 'messages' in result:
                    for _m in result['messages']:
                        if hasattr(_m, 'tool_calls') and _m.tool_calls:
                            _tc += len(_m.tool_calls)
                
                if _tc == 0 and _attempt < max_retries:
                    # Deep Agent написал план, но не вызвал инструменты — повтор с усилением
                    print_status('warning', f"Попытка {_attempt}: Deep Agent не использовал инструменты ({_tc} tool calls). Повтор...")
                    llm = create_gigachat_llm()
                    deep_agent = create_forensic_deep_agent(llm=llm, image_fs_dir=image_fs_dir)
                    continue
                
                break  # Успех — выходим из цикла
                
            except Exception as retry_err:
                err_name = type(retry_err).__name__
                err_msg_lower = str(retry_err).lower()
                err_msg_short = str(retry_err)[:300]
                
                # Контекст переполнен (422 "context too long") — не повторяем,
                # принимаем то, что есть, и переходим к fallback-анализу
                is_context_overflow = (
                    'unprocessableentityerror' in err_name.lower()
                    or 'context too long' in err_msg_lower
                    or ('422' in err_msg_short and 'context' in err_msg_lower)
                )
                # Recursion limit reached — agent hit step limit, accept results
                is_recursion_limit = (
                    'graphrecursionerror' in err_name.lower()
                    or 'recursion limit' in err_msg_lower
                )
                
                if is_context_overflow or is_recursion_limit:
                    _kind = "context overflow" if is_context_overflow else "recursion limit"
                    print_status('warning', f"Deep Agent остановлен ({_kind}). Продолжаем с тем, что есть...")
                    _store = get_investigation_store()
                    if _store.suspicious_findings:
                        print_status('info', f"Сохранено {len(_store.suspicious_findings)} находок")
                    result = None  # Proceed to fallback analysis
                    break
                
                # Определяем, является ли ошибка транзиентной (можно повторить)
                is_transient = (
                    'timeout' in err_name.lower() or 'timeout' in err_msg_lower
                    or 'servererror' in err_name.lower() or '500' in err_msg_short
                    or 'connectionerror' in err_name.lower()
                    or 'remotedisconnected' in err_name.lower()
                    or 'internal server error' in err_msg_lower
                )
                
                if is_transient and _attempt < max_retries:
                    print_status('warning', f"Попытка {_attempt} — {err_name}. Повтор через 10 сек...")
                    _store = get_investigation_store()
                    if _store.suspicious_findings:
                        print_status('info', f"Сохранено {len(_store.suspicious_findings)} находок из попытки {_attempt}")
                    time.sleep(10)
                    continue
                else:
                    raise
        
        # Извлекаем ответ Deep Agent'а
        if result and 'messages' in result:
            agent_messages = result['messages']
            # Находим последнее сообщение assistant с непустым текстовым content
            for msg in reversed(agent_messages):
                if hasattr(msg, 'content') and hasattr(msg, 'type') and msg.type == 'ai':
                    if msg.content:  # Пропускаем AI-сообщения без текста (только tool_calls)
                        deep_agent_output = msg.content
                        break
                elif isinstance(msg, dict) and msg.get('role') == 'assistant':
                    if msg.get('content'):
                        deep_agent_output = msg.get('content', '')
                        break
        
        if deep_agent_output:
            print_status('success', f"Deep Agent завершил анализ ({len(deep_agent_output)} символов)")
        else:
            deep_agent_output = "Deep Agent не вернул текстовый ответ."
            print_status('warning', "Deep Agent не вернул текстового ответа")
        
        # Извлекаем файлы анализа из виртуальной ФС Deep Agent (если доступны)
        # Deep Agent SDK использует ключ 'files'
        _fs_key = 'files' if (result and 'files' in result) else ('fs' if (result and 'fs' in result) else None)
        if _fs_key:
            fs_state = result[_fs_key]
            if isinstance(fs_state, dict):
                for filename, content in fs_state.items():
                    if filename.startswith('/analysis/') and filename.endswith('.json'):
                        key = filename.replace('/analysis/', '').replace('.json', '')
                        try:
                            llm_analyses[key] = json.loads(content) if isinstance(content, str) else content
                        except (json.JSONDecodeError, TypeError):
                            llm_analyses[key] = content
        
        messages.append({
            'role': 'assistant',
            'content': f"Deep Agent завершил анализ. Файлов анализа: {len(llm_analyses)}"
        })
        
    except ImportError as e:
        # deepagents не установлен — используем fallback через прямой LLM-вызов
        print_status('warning', f"Deep Agents SDK недоступен: {e}")
        print_status('info', "Используем fallback: прямой LLM-анализ через GigaChat...")
        
        deep_agent_output, llm_analyses = _fallback_llm_analysis(
            triage_data, analysis_result, recommendations,
            image_fs_dir=image_fs_dir,
        )
        
        messages.append({
            'role': 'assistant',
            'content': f"LLM-анализ завершён (fallback mode). Секций: {len(llm_analyses)}"
        })
        
    except Exception as e:
        error_msg = f"Deep Agent ошибка: {e}"
        print_status('error', error_msg)
        logger.exception("Deep Agent error")
        deep_agent_output = f"Ошибка Deep Agent: {str(e)}"
        messages.append({'role': 'error', 'content': error_msg})
    
    # --- Детерминированные данные (SSH-входы, публичные IP) ---
    # Извлекаются безусловно — не требуют LLM, всегда детерминированы.
    deterministic = _extract_deterministic_data(triage_data, image_fs_dir=image_fs_dir)
    for k, v in deterministic.items():
        if k not in llm_analyses:
            llm_analyses[k] = v

    # --- Фиксация находок из детерминированных данных ---
    # SSH-входы с публичных IP и публичные IP из команд → suspicious_findings
    store = get_investigation_store()
    det_findings_count = _record_deterministic_findings(deterministic, store)
    if det_findings_count:
        print_status('info', f"Зафиксировано {det_findings_count} находок из детерминированного анализа")

    # --- Дополнительный LLM-анализ для заполнения отчёта ---
    # Deep Agent выполняет расследование (findings, paths), но не генерирует
    # структурированные данные для секций отчёта (services, cron, packages и т.д.)
    # Запускаем fallback только для недостающих секций (only_keys).
    required_report_keys = ['services', 'cron', 'packages', 'web_software',
                            'nonstandard_root', 'nonstandard_home',
                            'ssh_logins', 'public_ips',
                            'user_summaries', 'expert_analysis']
    missing_keys = [k for k in required_report_keys if k not in llm_analyses]

    if missing_keys:
        print_phase("REPORT ANALYSIS", "Дополнительный LLM-анализ для секций отчёта")
        print_status('info', f"Секции без данных: {', '.join(missing_keys)}")

        try:
            fallback_output, fallback_analyses = _fallback_llm_analysis(
                triage_data, analysis_result, recommendations,
                image_fs_dir=image_fs_dir,
                only_keys=missing_keys,
            )
            for key in missing_keys:
                if key in fallback_analyses:
                    llm_analyses[key] = fallback_analyses[key]

            if not deep_agent_output or deep_agent_output == "Deep Agent не вернул текстовый ответ.":
                deep_agent_output = fallback_output

            filled = len([k for k in missing_keys if k in llm_analyses])
            print_status('success', f"Дополнено секций отчёта: {filled}/{len(missing_keys)}")
        except Exception as e:
            print_status('error', f"Ошибка дополнительного анализа: {e}")
            logger.exception("Supplementary analysis error")
    
    # Синхронизируем данные из InvestigationStore в состояние графа (только дельта)
    # store уже получен выше при фиксации детерминированных находок
    store_data = sync_store_to_state(store)
    
    return {
        'messages': messages,
        'investigated_paths': store_data['investigated_paths'],
        'suspicious_findings': store_data['suspicious_findings'],
        'llm_analyses': llm_analyses,
        'deep_agent_output': deep_agent_output,
        'current_step': 'evaluate_analysis',
    }


def _extract_deterministic_data(
    triage_data: Dict,
    image_fs_dir: str = "image_fs",
) -> Dict[str, Any]:
    """Извлечь данные, не требующие LLM: SSH-входы, публичные IP, нестандартные файлы (листинг).

    Вызывается безусловно перед любым LLM-анализом (deep agent или fallback).

    Returns:
        Dict с ключами ssh_logins, public_ips (заполненными, если данные есть).
    """
    cb = _cb_config("deterministic_extraction")
    result: Dict[str, Any] = {}

    # SSH успешные входы
    auth_logs = triage_data.get('auth_logs', {})
    if auth_logs:
        try:
            auth_content = ""
            if isinstance(auth_logs, dict):
                for val in auth_logs.values():
                    if isinstance(val, str):
                        auth_content += val + "\n"
                    elif isinstance(val, dict) and 'content' in val:
                        auth_content += val['content'] + "\n"
            elif isinstance(auth_logs, str):
                auth_content = auth_logs

            if auth_content:
                ssh_result_json = parse_ssh_successful_logins.invoke({"auth_log_content": auth_content}, config=cb)
                ssh_result = json.loads(ssh_result_json)
                result['ssh_logins'] = ssh_result
                print_status('success', f"SSH входов: {ssh_result.get('total_logins', 0)}")
        except Exception as e:
            print_status('error', f"Ошибка парсинга SSH: {e}")

    # Публичные IP из истории команд
    history = triage_data.get('history', {})
    if history:
        try:
            all_commands_text = ""
            for cmds in history.values():
                if isinstance(cmds, list):
                    all_commands_text += "\n".join(cmds) + "\n"
                elif isinstance(cmds, str):
                    all_commands_text += cmds + "\n"

            ips_result_json = extract_public_ips.invoke({"text": all_commands_text}, config=cb)
            ips_result = json.loads(ips_result_json)
            result['public_ips'] = ips_result
            print_status('success', f"Публичных IP: {ips_result.get('total_public', 0)}")
        except Exception as e:
            print_status('error', f"Ошибка извлечения IP: {e}")

    # Листинг /home/ (2-уровневый: пользователи + их файлы)
    try:
        home_dir = f"{image_fs_dir}/home"
        home_json = list_local_directory.invoke({"dir_path": home_dir}, config=cb)
        home_data = json.loads(home_json)
        if home_data.get('success'):
            home_tree: Dict[str, list] = {}
            for entry in home_data.get('entries', []):
                if entry.get('type') == 'directory' and entry.get('name') not in ('.', '..'):
                    user_dir = f"{home_dir}/{entry['name']}"
                    try:
                        user_json = list_local_directory.invoke({"dir_path": user_dir}, config=cb)
                        user_data = json.loads(user_json)
                        home_tree[entry['name']] = user_data.get('entries', []) if user_data.get('success') else []
                    except Exception:
                        home_tree[entry['name']] = []
            result['home_listing'] = home_tree
            print_status('success', f"Листинг /home/: {len(home_tree)} пользователей")
        else:
            result['home_listing'] = None
            print_status('warning', "Каталог /home/ не найден")
    except Exception as e:
        result['home_listing'] = None
        print_status('warning', f"Ошибка листинга /home/: {e}")

    # Листинг /root/
    try:
        root_home_dir = f"{image_fs_dir}/root"
        root_json = list_local_directory.invoke({"dir_path": root_home_dir}, config=cb)
        root_data = json.loads(root_json)
        if root_data.get('success'):
            result['root_listing'] = root_data.get('entries', [])
            print_status('success', f"Листинг /root/: {len(result['root_listing'])} записей")
        else:
            result['root_listing'] = None
            print_status('warning', "Каталог /root/ не найден")
    except Exception as e:
        result['root_listing'] = None
        print_status('warning', f"Ошибка листинга /root/: {e}")

    # Сканирование файлов в home/root на malware-паттерны (через @tool)
    try:
        scan_result_json = scan_home_files_for_malware.invoke(
            {"image_fs_dir": image_fs_dir}, config=cb
        )
        scan_result = json.loads(scan_result_json)
        malware_hits = scan_result.get('hits', [])
        if malware_hits:
            result['malware_hits'] = malware_hits
            print_status('warning', f"Обнаружено {len(malware_hits)} malware-индикаторов в файлах!")
        else:
            print_status('success', "Malware-паттерны в файлах home/root не обнаружены")
    except Exception as e:
        print_status('error', f"Ошибка сканирования файлов: {e}")

    return result


def _record_deterministic_findings(
    deterministic: Dict[str, Any],
    store,
) -> int:
    """Зафиксировать находки из детерминированных данных в InvestigationStore.

    Создаёт находки для:
    - SSH-входов с публичных IP-адресов (severity=high)
    - Публичных IP-адресов в истории команд (severity=medium)
    - Malware-паттернов в файлах home/root (severity по паттерну)

    Дедупликация выполняется автоматически через store.add_finding().

    Returns:
        Количество новых (не дублирующихся) находок.
    """
    initial_count = len(store.suspicious_findings)

    # SSH-входы с публичных IP
    ssh_logins = deterministic.get('ssh_logins', {})
    if ssh_logins and ssh_logins.get('unique_ips'):
        summary_by_ip = ssh_logins.get('summary_by_ip', {})
        for ip in ssh_logins['unique_ips']:
            if not is_public_ip(ip):
                continue
            count = summary_by_ip.get(ip, 1)
            store.add_finding(
                category='network',
                severity='high',
                title=f'SSH-вход с публичного IP: {ip}',
                details=f'Обнаружено {count} успешных SSH-входов с публичного IP-адреса {ip}.',
                evidence=[f'Количество SSH-входов: {count}'],
            )

    # Публичные IP из истории команд
    public_ips = deterministic.get('public_ips', {})
    if public_ips and public_ips.get('public_ips'):
        for ip in public_ips['public_ips']:
            store.add_finding(
                category='network',
                severity='medium',
                title=f'Публичный IP в истории команд: {ip}',
                details=f'IP-адрес {ip} обнаружен в истории команд пользователей. '
                        f'Требуется проверка контекста использования.',
                evidence=[f'IP: {ip}'],
            )

    # Malware-паттерны в файлах home/root
    malware_hits = deterministic.get('malware_hits', [])
    for hit in malware_hits:
        store.add_finding(
            category='malware',
            severity=hit['severity'],
            title=hit['title'],
            details=hit['details'],
            evidence=hit.get('evidence', []),
            related_paths=hit.get('related_paths', []),
        )

    new_count = len(store.suspicious_findings) - initial_count
    return new_count


def _record_log_analysis_findings(
    log_analysis: Dict[str, Any],
    store,
) -> int:
    """Зафиксировать находки и исследованные пути из детального анализа логов.

    Записывает в InvestigationStore:
    - Brute-force атаки из auth.log (critical)
    - Хосты с неуспешными И успешными входами из btmp/wtmp (high)
    - Подозрительные команды из bash_history (high)
    - Исследованные пути для каждого типа лога

    Дедупликация выполняется автоматически через store.add_finding()
    по ключу (category, title).

    Returns:
        Количество новых (не дублирующихся) находок.
    """
    initial_count = len(store.suspicious_findings)

    # --- auth.log: brute-force detection ---
    auth_data = log_analysis.get('analyze_auth_logs_detailed', {})
    if isinstance(auth_data, dict) and auth_data.get('success'):
        files_str = ', '.join(auth_data.get('files_analyzed', []))
        store.add_explored_path(
            path='/var/log/auth.log*',
            description=f"Детальный анализ auth.log: {auth_data.get('total_events', 0)} событий "
                        f"(SSH: {auth_data.get('ssh_events', 0)}, sudo: {auth_data.get('sudo_events', 0)}). "
                        f"Файлы: {files_str}",
            suspicious=bool(auth_data.get('potentially_bruted_accounts')),
        )

        bruted = auth_data.get('potentially_bruted_accounts', [])
        for b in bruted:
            user = b.get('user', '?')
            ip = b.get('ip', '?')
            failed_before = b.get('failed_attempts_before', '?')
            store.add_finding(
                category='network',
                severity='critical',
                title=f'Brute-force атака → успешный вход: {user}',
                details=(
                    f"Обнаружен brute-force: {failed_before} неуспешных попыток, "
                    f"затем успешный вход пользователя '{user}' с IP {ip} "
                    f"в {b.get('time', '?')}."
                ),
                evidence=[
                    f"Пользователь: {user}",
                    f"IP: {ip}",
                    f"Неуспешных попыток до входа: {failed_before}",
                    f"Время успешного входа: {b.get('time', '?')}",
                ],
                related_paths=['/var/log/auth.log'],
            )

        # Хосты с большим количеством неуспешных SSH-входов
        failed_by_host = auth_data.get('failed_by_host', [])
        for host_info in failed_by_host:
            attempts = host_info.get('total_attempts', 0)
            if attempts >= 50:
                ip = host_info.get('ip', '?')
                store.add_finding(
                    category='network',
                    severity='high',
                    title=f'Массовый brute-force с IP: {ip}',
                    details=(
                        f"IP {ip}: {attempts} неуспешных SSH-входов, "
                        f"{host_info.get('unique_users', 0)} уникальных пользователей, "
                        f"{host_info.get('active_days', 0)} активных дней."
                    ),
                    evidence=[f"Всего попыток: {attempts}"],
                    related_paths=['/var/log/auth.log'],
                )

    # --- btmp/wtmp: корреляции ---
    utmp_data = log_analysis.get('analyze_utmp_logs', {})
    if isinstance(utmp_data, dict) and utmp_data.get('success'):
        files_str = ', '.join(utmp_data.get('files_analyzed', []))
        store.add_explored_path(
            path='/var/log/btmp,wtmp',
            description=f"Анализ btmp/wtmp: {utmp_data.get('failed_logins_count', 0)} неуспешных, "
                        f"{utmp_data.get('successful_logins_count', 0)} успешных входов. "
                        f"Файлы: {files_str}",
            suspicious=bool(utmp_data.get('hosts_in_both_btmp_wtmp')),
        )

        hosts_both = utmp_data.get('hosts_in_both_btmp_wtmp', [])
        if hosts_both:
            hosts_str = ', '.join(hosts_both[:10])
            store.add_finding(
                category='network',
                severity='high',
                title='Хосты с неуспешными И успешными входами (btmp/wtmp)',
                details=(
                    f"Обнаружено {len(hosts_both)} хостов, с которых были и неуспешные, "
                    f"и успешные входы: {hosts_str}. "
                    f"Возможный brute-force с последующим успешным проникновением."
                ),
                evidence=[f"Хосты: {hosts_str}"],
                related_paths=['/var/log/btmp', '/var/log/wtmp'],
            )

        date_diff = utmp_data.get('btmp_wtmp_date_difference_days')
        if date_diff is not None and abs(date_diff) > 30:
            store.add_finding(
                category='config',
                severity='medium',
                title='Подозрительная разница дат btmp/wtmp',
                details=(
                    f"Разница между последними записями btmp и wtmp: {date_diff} дней. "
                    f"Может указывать на чистку логов."
                ),
                evidence=[f"Разница дат: {date_diff} дней"],
                related_paths=['/var/log/btmp', '/var/log/wtmp'],
            )

    # --- lastlog: исследованный путь ---
    lastlog_data = log_analysis.get('analyze_lastlog', {})
    if isinstance(lastlog_data, dict) and lastlog_data.get('success'):
        store.add_explored_path(
            path='/var/log/lastlog',
            description=f"Анализ lastlog: {lastlog_data.get('total_entries', 0)} записей о последних входах",
        )

    # --- dpkg.log: исследованный путь ---
    dpkg_data = log_analysis.get('analyze_dpkg_logs', {})
    if isinstance(dpkg_data, dict) and dpkg_data.get('success'):
        store.add_explored_path(
            path='/var/log/dpkg.log*',
            description=(
                f"Анализ dpkg.log: {dpkg_data.get('total_records', 0)} записей. "
                f"Установлено: {dpkg_data.get('installed_count', 0)}, "
                f"удалено: {dpkg_data.get('removed_count', 0)}, "
                f"purge: {dpkg_data.get('purged_count', 0)}"
            ),
            suspicious=dpkg_data.get('removed_count', 0) > 0 or dpkg_data.get('purged_count', 0) > 0,
        )

    # --- bash_history: подозрительные команды ---
    hist_data = log_analysis.get('analyze_history_commands', {})
    if isinstance(hist_data, dict) and hist_data.get('success'):
        total_susp = hist_data.get('total_suspicious_commands', 0)
        store.add_explored_path(
            path='/root/.bash_history, /home/*/.bash_history',
            description=f"Детальный анализ bash_history: {total_susp} подозрительных команд",
            suspicious=total_susp > 0,
        )

        # Записываем подозрительные команды как находки (дедупликация по title)
        for path_key, info in hist_data.get('analysis', {}).items():
            susp_cmds = info.get('suspicious_commands', [])
            if susp_cmds:
                # Группируем все подозрительные команды из одного файла в одну находку
                cmds_preview = susp_cmds[:10]
                store.add_finding(
                    category='command',
                    severity='high',
                    title=f'Подозрительные команды в {path_key}',
                    details=(
                        f"Обнаружено {len(susp_cmds)} подозрительных команд в файле {path_key}. "
                        f"Включают потенциально опасные утилиты, reverse shell, "
                        f"сокрытие следов или повышение привилегий."
                    ),
                    evidence=cmds_preview,
                    related_paths=[path_key],
                )

    # --- alternatives.log: исследованный путь ---
    alt_data = log_analysis.get('analyze_alternatives_logs', {})
    if isinstance(alt_data, dict) and alt_data.get('success'):
        store.add_explored_path(
            path='/var/log/alternatives.log*',
            description=f"Анализ alternatives.log: {alt_data.get('total_changes', 0)} изменений",
        )

    new_count = len(store.suspicious_findings) - initial_count
    if new_count:
        print_status('info', f"Зафиксировано {new_count} находок из анализа логов")
    else:
        print_status('success', "Подозрительных находок в логах не обнаружено")

    return new_count


def _fallback_llm_analysis(
    triage_data: Dict,
    analysis_result: Dict,
    recommendations: List[str],
    image_fs_dir: str = "image_fs",
    only_keys: Optional[List[str]] = None,
) -> tuple:
    """
    Fallback: прямой LLM-анализ через GigaChat без Deep Agents SDK.

    Используется если deepagents не установлен, а также для дополнения
    секций отчёта, которые Deep Agent не заполнил.

    Args:
        only_keys: Если задан, анализировать только эти секции (оптимизация).

    Returns:
        (deep_agent_output, llm_analyses)
    """
    from src.agent.prompts import (
        ANALYZE_SERVICES_PROMPT,
        ANALYZE_CRON_PROMPT,
        ANALYZE_PACKAGES_PROMPT,
        ANALYZE_WEB_SOFTWARE_PROMPT,
        SUMMARIZE_USER_COMMANDS_PROMPT,
        IDENTIFY_NONSTANDARD_FILES_PROMPT,
    )
    
    # Устанавливаем текущий узел для логирования (LLM-вызовы + tool.invoke)
    cb = _cb_config("fallback_analysis")

    def _need(key: str) -> bool:
        """Нужно ли анализировать эту секцию."""
        return only_keys is None or key in only_keys

    llm = create_gigachat_llm()
    llm_analyses = {}
    all_outputs = []

    # 1. Анализ сервисов
    services = triage_data.get('services', {})
    if services and _need('services'):
        print_status('info', "LLM: Анализ сервисов...")
        try:
            services_str = json.dumps(services, ensure_ascii=False)[:4000]
            prompt = ANALYZE_SERVICES_PROMPT.format(services_data=services_str)
            response = llm.invoke(prompt)
            content = getattr(response, 'content', str(response))
            llm_analyses['services'] = content
            all_outputs.append(f"=== АНАЛИЗ СЕРВИСОВ ===\n{content}")
            print_status('success', "Сервисы проанализированы")
        except Exception as e:
            print_status('error', f"Ошибка анализа сервисов: {e}")
    
    # 2. Анализ cron
    cron = triage_data.get('cron', {})
    if cron and _need('cron'):
        print_status('info', "LLM: Анализ cron-задач...")
        try:
            cron_str = json.dumps(cron, ensure_ascii=False)[:4000]
            prompt = ANALYZE_CRON_PROMPT.format(cron_data=cron_str)
            response = llm.invoke(prompt)
            content = getattr(response, 'content', str(response))
            llm_analyses['cron'] = content
            all_outputs.append(f"=== АНАЛИЗ CRON ===\n{content}")
            print_status('success', "Cron проанализирован")
        except Exception as e:
            print_status('error', f"Ошибка анализа cron: {e}")
    
    # 3. Анализ пакетов
    packages = triage_data.get('packages', {})
    if packages and _need('packages'):
        print_status('info', "LLM: Анализ пакетов...")
        try:
            packages_str = json.dumps(packages, ensure_ascii=False)[:4000]
            prompt = ANALYZE_PACKAGES_PROMPT.format(packages_data=packages_str)
            response = llm.invoke(prompt)
            content = getattr(response, 'content', str(response))
            llm_analyses['packages'] = content
            all_outputs.append(f"=== АНАЛИЗ ПАКЕТОВ ===\n{content}")
            print_status('success', "Пакеты проанализированы")
        except Exception as e:
            print_status('error', f"Ошибка анализа пакетов: {e}")
    
    # 4. Веб-серверы и ПО
    if (services or packages) and _need('web_software'):
        print_status('info', "LLM: Анализ веб-серверов и ПО...")
        try:
            svc_str = json.dumps(services, ensure_ascii=False)[:2000]
            pkg_str = json.dumps(packages, ensure_ascii=False)[:2000]
            prompt = ANALYZE_WEB_SOFTWARE_PROMPT.format(services_data=svc_str, packages_data=pkg_str)
            response = llm.invoke(prompt)
            content = getattr(response, 'content', str(response))
            llm_analyses['web_software'] = content
            all_outputs.append(f"=== ВЕБ-СЕРВЕРЫ И ПО ===\n{content}")
            print_status('success', "Веб-серверы и ПО проанализированы")
        except Exception as e:
            print_status('error', f"Ошибка анализа ПО: {e}")
    
    # 5. Саммари по пользователям
    history = triage_data.get('history', {})
    if history and _need('user_summaries'):
        user_summaries = {}
        for username, commands in history.items():
            if not commands:
                continue
            print_status('info', f"LLM: Саммари для пользователя {username}...")
            try:
                cmds_str = "\n".join(commands[:100]) if isinstance(commands, list) else str(commands)[:3000]
                prompt = SUMMARIZE_USER_COMMANDS_PROMPT.format(username=username, commands=cmds_str)
                response = llm.invoke(prompt)
                content = getattr(response, 'content', str(response))
                user_summaries[username] = content
            except Exception as e:
                print_status('error', f"Ошибка саммари для {username}: {e}")
        
        if user_summaries:
            llm_analyses['user_summaries'] = user_summaries
            all_outputs.append(f"=== САММАРИ ПОЛЬЗОВАТЕЛЕЙ ===\n{json.dumps(user_summaries, ensure_ascii=False, indent=2)}")
            print_status('success', f"Саммари для {len(user_summaries)} пользователей")
    
    # SSH и публичные IP теперь извлекаются в _extract_deterministic_data()

    # 6. Нестандартные файлы в корне
    if _need('nonstandard_root'):
        print_status('info', "Проверка корневой директории...")
        try:
            root_listing_json = list_local_directory.invoke({"dir_path": image_fs_dir}, config=cb)
            root_listing = json.loads(root_listing_json)
            if root_listing.get('success'):
                entries = root_listing.get('entries', [])
                listing_str = json.dumps(entries, ensure_ascii=False)[:3000]
                prompt = IDENTIFY_NONSTANDARD_FILES_PROMPT.format(
                    directory="/", directory_listing=listing_str
                )
                response = llm.invoke(prompt)
                content = getattr(response, 'content', str(response))
                llm_analyses['nonstandard_root'] = content
                all_outputs.append(f"=== НЕСТАНДАРТНЫЕ ФАЙЛЫ (/) ===\n{content}")
                print_status('success', "Корневая директория проанализирована")
        except Exception as e:
            print_status('error', f"Ошибка анализа корня: {e}")

    # 7. Нестандартные файлы в домашних каталогах
    if _need('nonstandard_home'):
        print_status('info', "LLM: Анализ нестандартных файлов в домашних каталогах...")
        try:
            all_listings = []

            # Собираем листинг /home/*
            home_dir = f"{image_fs_dir}/home"
            home_json = list_local_directory.invoke({"dir_path": home_dir}, config=cb)
            home_data = json.loads(home_json)
            if home_data.get('success'):
                for entry in home_data.get('entries', []):
                    if entry.get('type') == 'directory' and entry.get('name') not in ('.', '..'):
                        user_dir = f"{home_dir}/{entry['name']}"
                        try:
                            user_json = list_local_directory.invoke({"dir_path": user_dir}, config=cb)
                            user_data = json.loads(user_json)
                            if user_data.get('success') and user_data.get('entries'):
                                entries_str = json.dumps(user_data['entries'], ensure_ascii=False)[:2000]
                                all_listings.append(f"/home/{entry['name']}/:\n{entries_str}")
                        except Exception:
                            pass

            # Собираем листинг /root/
            root_home_dir = f"{image_fs_dir}/root"
            root_json = list_local_directory.invoke({"dir_path": root_home_dir}, config=cb)
            root_data = json.loads(root_json)
            if root_data.get('success') and root_data.get('entries'):
                entries_str = json.dumps(root_data['entries'], ensure_ascii=False)[:2000]
                all_listings.append(f"/root/:\n{entries_str}")

            if all_listings:
                listing_combined = "\n\n".join(all_listings)[:5000]
                prompt = IDENTIFY_NONSTANDARD_FILES_PROMPT.format(
                    directory="домашние каталоги (/home/*, /root/)",
                    directory_listing=listing_combined,
                )
                response = llm.invoke(prompt)
                content = getattr(response, 'content', str(response))
                llm_analyses['nonstandard_home'] = content
                all_outputs.append(f"=== НЕСТАНДАРТНЫЕ ФАЙЛЫ (HOME) ===\n{content}")
                print_status('success', "Нестандартные файлы в домашних каталогах проанализированы")
        except Exception as e:
            print_status('error', f"Ошибка анализа домашних каталогов: {e}")

    # 8. Общий экспертный анализ
    if _need('expert_analysis'):
        print_status('info', "LLM: Формирование экспертного заключения...")
        try:
            baseline_ctx = _build_enriched_baseline_context(triage_data, analysis_result)
            expert_prompt = f"""Ты — эксперт по кибербезопасности. На основе собранных данных проведи анализ.

BASELINE-ДАННЫЕ:
{baseline_ctx}

РЕКОМЕНДАЦИИ:
{chr(10).join(f'- {r}' for r in recommendations)}

ЗАДАЧА:
1. РЕЗЮМЕ: краткое состояние системы
2. ПРИЗНАКИ КОМПРОМЕТАЦИИ: если есть
3. ПОДОЗРИТЕЛЬНЫЕ НАХОДКИ: детальный анализ
4. ВЕРОЯТНЫЙ СЦЕНАРИЙ АТАКИ: если есть признаки
5. РЕКОМЕНДАЦИИ: что делать дальше

Пиши на русском языке, конкретно и по существу.
"""
            response = llm.invoke(expert_prompt)
            expert_content = getattr(response, 'content', str(response))
            llm_analyses['expert_analysis'] = expert_content
            all_outputs.append(f"=== ЭКСПЕРТНОЕ ЗАКЛЮЧЕНИЕ ===\n{expert_content}")
            print_status('success', "Экспертное заключение сформировано")
        except Exception as e:
            print_status('error', f"Ошибка экспертного анализа: {e}")
    
    deep_agent_output = "\n\n".join(all_outputs) if all_outputs else "LLM-анализ не дал результатов."
    return deep_agent_output, llm_analyses


def evaluate_analysis_node(state: ForensicAgentState) -> Dict:
    """
    Узел оценки достаточности анализа (LLM-evaluation loop).
    
    Вызывает LLM с EVALUATE_ANALYSIS_PROMPT и на основе вердикта
    решает: продолжить анализ (deep_analysis) или перейти к отчёту
    (generate_report).
    
    Также выполняет инкремент analysis_iteration.
    
    Hard cap: если analysis_iteration >= max_iterations - 1,
    всегда переходит к generate_report.
    """
    iteration = state.get('analysis_iteration', 0)
    max_iter = state.get('max_iterations', 3)
    investigated_paths = state.get('investigated_paths', [])
    suspicious_findings = state.get('suspicious_findings', [])
    recommendations = state.get('recommendations', [])
    
    print_phase("EVALUATE", f"Оценка достаточности анализа (итерация {iteration + 1}/{max_iter})")
    
    messages = []
    next_step = 'generate_report'  # По умолчанию — достаточно
    
    # Hard cap: последняя итерация — всегда generate_report
    if iteration >= max_iter - 1:
        print_status('info', f"Достигнут лимит итераций ({max_iter}). Переход к отчёту.")
        messages.append({
            'role': 'assistant',
            'content': f"Лимит итераций ({max_iter}) достигнут. Формируем отчёт."
        })
        return {
            'messages': messages,
            'analysis_iteration': iteration + 1,
            'current_step': 'generate_report',
        }
    
    # Подготовка статистики для промпта
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in suspicious_findings:
        sev = f.get('severity', 'info').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Сводка по исследованным путям
    if investigated_paths:
        paths_lines = []
        for p in investigated_paths[-20:]:
            suspicious_mark = " [!]" if p.get('suspicious') else ""
            paths_lines.append(f"  - {p.get('path', '?')}{suspicious_mark}: {p.get('description', '')[:80]}")
        explored_paths_summary = "\n".join(paths_lines)
        if len(investigated_paths) > 20:
            explored_paths_summary = f"  (показаны последние 20 из {len(investigated_paths)})\n" + explored_paths_summary
    else:
        explored_paths_summary = "  (нет исследованных путей)"
    
    # Сводка по находкам
    if suspicious_findings:
        findings_lines = []
        for f in suspicious_findings[-15:]:
            findings_lines.append(f"  - [{f.get('severity', '?').upper()}] {f.get('title', '?')}: {f.get('details', '')[:60]}")
        findings_summary = "\n".join(findings_lines)
        if len(suspicious_findings) > 15:
            findings_summary = f"  (показаны последние 15 из {len(suspicious_findings)})\n" + findings_summary
    else:
        findings_summary = "  (нет находок)"
    
    # Рекомендации
    if recommendations:
        recs_text = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(recommendations))
    else:
        recs_text = "  (нет рекомендаций)"
    
    # Формируем промпт
    prompt = EVALUATE_ANALYSIS_PROMPT.format(
        iteration=iteration,
        max_iterations=max_iter,
        findings_count=len(suspicious_findings),
        critical_count=severity_counts['critical'],
        high_count=severity_counts['high'],
        medium_count=severity_counts['medium'],
        low_count=severity_counts['low'],
        info_count=severity_counts['info'],
        paths_count=len(investigated_paths),
        total_recommendations=len(recommendations),
        explored_paths_summary=explored_paths_summary,
        findings_summary=findings_summary,
        recommendations_text=recs_text,
    )
    
    try:
        # Устанавливаем текущий узел для логирования
        _cb_config("evaluate_analysis")
        
        llm = create_gigachat_llm()
        response = llm.invoke(prompt)
        content = getattr(response, 'content', str(response))
        
        # Парсим JSON-вердикт
        # Пытаемся извлечь JSON из ответа (LLM может обернуть в markdown)
        json_str = content.strip()
        if '```' in json_str:
            # Извлекаем JSON из markdown code block
            import re as _re
            json_match = _re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', json_str, _re.DOTALL)
            if json_match:
                json_str = json_match.group(1).strip()
        
        verdict_data = json.loads(json_str)
        verdict = verdict_data.get('verdict', 'sufficient')
        reason = verdict_data.get('reason', '')
        
        if verdict == 'continue':
            next_step = 'deep_analysis'
            print_status('info', f"Вердикт: ПРОДОЛЖИТЬ анализ. Причина: {reason}")
        else:
            next_step = 'generate_report'
            print_status('success', f"Вердикт: ДОСТАТОЧНО для отчёта. Причина: {reason}")
        
        messages.append({
            'role': 'assistant',
            'content': f"Оценка итерации {iteration + 1}: {verdict}. {reason}"
        })
        
    except Exception as e:
        # При ошибке LLM — переходим к отчёту (безопасный вариант)
        print_status('warning', f"Ошибка оценки анализа: {e}. Переход к отчёту.")
        logger.warning(f"evaluate_analysis_node error: {e}")
        next_step = 'generate_report'
        messages.append({
            'role': 'error',
            'content': f"Ошибка оценки: {e}. Переход к формированию отчёта."
        })
    
    return {
        'messages': messages,
        'analysis_iteration': iteration + 1,
        'current_step': next_step,
    }


def route_after_evaluation(state: ForensicAgentState) -> Literal["deep_analysis", "generate_report"]:
    """
    Маршрутизация после оценки анализа.
    
    Если evaluate_analysis_node установил current_step='deep_analysis',
    возвращаемся к deep_analysis_node для ещё одной итерации.
    Иначе — переходим к generate_report.
    """
    if state.get('current_step') == 'deep_analysis':
        return "deep_analysis"
    return "generate_report"


def generate_report_node(state: ForensicAgentState) -> Dict:
    """
    Узел генерации всеобъемлющего HTML-отчёта (Фаза 5).
    
    Формирует отчёт из:
    - triage_data (baseline)
    - analysis_result (алгоритмический анализ)
    - llm_analyses (LLM-анализ по секциям)
    - investigated_paths (исследованные пути)
    - suspicious_findings (подозрительные находки)
    - deep_agent_output (экспертный текст)
    """
    print_phase("REPORT", "Генерация всеобъемлющего отчёта")
    
    messages = []
    
    # Собираем все данные
    triage_data = state.get('triage_data', {})
    analysis_result = state.get('analysis_result', {})
    llm_analyses = state.get('llm_analyses', {})
    investigated_paths = state.get('investigated_paths', [])
    suspicious_findings = state.get('suspicious_findings', [])
    deep_agent_output = state.get('deep_agent_output', '')
    
    # Формируем report_data
    report_data = {
        'triage_data': triage_data,
        'analysis_result': analysis_result,
        'llm_analyses': llm_analyses,
        'investigated_paths': investigated_paths,
        'suspicious_findings': suspicious_findings,
        'deep_agent_output': deep_agent_output,
    }
    
    # Определяем пути для сохранения
    output_dir = Path("output") / datetime.now().strftime("%Y%m%d_%H%M%S")
    fs_utils.ensure_directory(output_dir)
    
    report_path = output_dir / "comprehensive_report.html"
    data_path = output_dir / "report_data.json"
    triage_path = output_dir / "triage_data.json"
    analysis_path = output_dir / "analysis_result.json"
    
    # Сохраняем данные
    print_status('info', f"Сохранение данных в {output_dir}...")
    fs_utils.safe_write(triage_path, json.dumps(triage_data, ensure_ascii=False, indent=2))
    fs_utils.safe_write(analysis_path, json.dumps(analysis_result, ensure_ascii=False, indent=2))
    fs_utils.safe_write(data_path, json.dumps(report_data, ensure_ascii=False, indent=2, default=str))
    
    # Генерируем HTML
    print_status('info', "Генерация HTML-отчёта...")
    
    from src.agent.report_generator import generate_comprehensive_html_report
    html_content = generate_comprehensive_html_report(report_data)
    
    fs_utils.safe_write(report_path, html_content)
    file_size = len(html_content.encode('utf-8'))
    
    print_status('success', f"Отчёт сохранён: {report_path} ({file_size} байт)")
    
    messages.append({
        'role': 'assistant',
        'content': f"Отчёт сгенерирован: {report_path} ({file_size} байт)"
    })
    
    return {
        'messages': messages,
        'report_data': report_data,
        'report_path': str(report_path),
        'current_step': 'close_image',
    }


def close_image_node(state: ForensicAgentState) -> Dict:
    """Узел закрытия образа."""
    print_status('info', "Закрытие образа...")
    
    cb = _cb_config("close_image")
    messages = []
    result_json = close_disk_image.invoke({}, config=cb)
    result = json.loads(result_json)
    messages.append({'role': 'tool', 'tool': 'close_disk_image', 'content': result_json})
    
    if result.get('success'):
        print_status('success', "Образ закрыт")
    
    return {
        'messages': messages,
        'image_open': False,
        'current_step': 'finished',
    }


# ==================== GRAPH ROUTING ====================

def route_after_open(state: ForensicAgentState) -> Literal["collect_baseline", "end"]:
    if state.get('image_open'):
        return "collect_baseline"
    return "end"


def route_after_report(state: ForensicAgentState) -> Literal["close_image", "end"]:
    if state.get('image_open'):
        return "close_image"
    return "end"


# ==================== GRAPH BUILDER ====================

def build_forensic_graph() -> StateGraph:
    """
    Построить граф Deep Forensic Agent.
    
    Архитектура графа с итеративным циклом анализа:
    
        open_image → collect_baseline → deep_analysis → evaluate_analysis
                                             ↑               ↓
                                             └── "needs_more" ┘
                                                        ↓ "sufficient"
                                                  generate_report → close_image → END
    
    evaluate_analysis вызывает LLM для оценки достаточности анализа.
    При вердикте "continue" возвращается к deep_analysis.
    Hard cap: max_iterations (default 3) предотвращает бесконечные циклы.
    """
    graph = StateGraph(ForensicAgentState)
    
    # Добавляем узлы
    graph.add_node("open_image", open_image_node)
    graph.add_node("collect_baseline", collect_baseline_node)
    graph.add_node("deep_analysis", deep_analysis_node)
    graph.add_node("evaluate_analysis", evaluate_analysis_node)
    graph.add_node("generate_report", generate_report_node)
    graph.add_node("close_image", close_image_node)
    
    # Точка входа
    graph.set_entry_point("open_image")
    
    # Рёбра
    graph.add_conditional_edges(
        "open_image",
        route_after_open,
        {"collect_baseline": "collect_baseline", "end": END}
    )
    graph.add_edge("collect_baseline", "deep_analysis")
    graph.add_edge("deep_analysis", "evaluate_analysis")
    graph.add_conditional_edges(
        "evaluate_analysis",
        route_after_evaluation,
        {"deep_analysis": "deep_analysis", "generate_report": "generate_report"}
    )
    graph.add_conditional_edges(
        "generate_report",
        route_after_report,
        {"close_image": "close_image", "end": END}
    )
    graph.add_edge("close_image", END)
    
    return graph


# ==================== AGENT CLASS ====================

class ForensicDeepAgent:
    """
    Deep Forensic Agent — интеллектуальный агент для криминалистического анализа.
    
    Архитектура:
    - LangGraph Orchestrator → Deep Agent (deepagents) → 4 Subagents
    - GigaChat-2-Max как LLM
    - Chain of Thought + Reflection + Tool Calling
    - Расширенное управление состоянием (ForensicAgentState)
    
    Этапы:
    1. Открытие образа
    2. Сбор базовых артефактов (triage.yaml) + алгоритмический анализ
    3. Deep Agent: рекомендации → исследование → корреляция → детальный анализ
    4. Генерация всеобъемлющего HTML-отчёта
    5. Закрытие образа
    """
    
    def __init__(self):
        self.graph = build_forensic_graph()
        self.app = self.graph.compile()
    
    def run(self, image_path: str, fs_depth: int = 5) -> Dict[str, Any]:
        """
        Запустить полный анализ образа.
        
        Args:
            image_path: Путь к образу диска (RAW)
        
        Returns:
            Финальное состояние агента (ForensicAgentState)
        """
        print(f"\n{ConsoleColors.BOLD}{'='*60}")
        print(f"🔬 FORSETI DEEP FORENSIC AGENT")
        print(f"   GigaChat-2-Max | Deep Agents | LangGraph")
        print(f"{'='*60}{ConsoleColors.RESET}\n")
        
        initial_state: ForensicAgentState = {
            'messages': [
                {'role': 'system', 'content': 'Forseti Deep Forensic Agent initialized'},
                {'role': 'user', 'content': f'Проанализируй образ диска: {image_path}'},
            ],
            'image_path': image_path,
            'image_open': False,
            'os_info': None,
            'triage_data': None,
            'analysis_result': None,
            'recommendations': [],
            'investigated_paths': [],
            'suspicious_findings': [],
            'llm_analyses': {},
            'report_data': {},
            'deep_agent_output': None,
            'report_path': None,
            'current_step': 'start',
            'errors': [],
            'analysis_iteration': 0,
            'max_iterations': 3,
            'fs_extract_depth': fs_depth,
        }
        
        final_state = self.app.invoke(initial_state)
        
        # Итоги
        print(f"\n{ConsoleColors.BOLD}{'='*60}")
        print(f"✅ АНАЛИЗ ЗАВЕРШЁН")
        print(f"{'='*60}{ConsoleColors.RESET}\n")
        
        if final_state.get('report_path'):
            print_status('success', f"Отчёт: {final_state['report_path']}")
        
        findings = final_state.get('suspicious_findings', [])
        paths = final_state.get('investigated_paths', [])
        print_status('info', f"Исследовано путей: {len(paths)}")
        print_status('info', f"Подозрительных находок: {len(findings)}")
        
        if final_state.get('errors'):
            print_status('warning', f"Ошибок: {len(final_state['errors'])}")
        
        # Сохраняем историю сообщений на диск (если callback включён)
        _handler = get_message_history()
        if _handler:
            _handler.save_to_disk()
        
        return final_state


def run_deep_agent(image_path: str, fs_depth: int = 5) -> Dict[str, Any]:
    """
    Удобная функция для запуска Deep Forensic Agent.
    
    Args:
        image_path: Путь к образу диска
    
    Returns:
        Финальное состояние агента
    """
    agent = ForensicDeepAgent()
    return agent.run(image_path, fs_depth=fs_depth)
