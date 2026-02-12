"""
Forensic Deep Agent — Интеллектуальный AI-агент для криминалистического анализа.

Архитектура:
  Layer 1: LangGraph Orchestrator (ForensicAgentState)
    ├── open_image_node         (детерминированный)
    ├── collect_baseline_node   (детерминированный: triage.yaml + analyze_triage_data)
    ├── deep_analysis_node      (Deep Agent: рекомендации → исследование → корреляция)
    ├── generate_report_node    (формирование всеобъемлющего HTML-отчёта)
    └── close_image_node        (детерминированный)
  
  Layer 2: Deep Agent (create_deep_agent)
    - GigaChat-2-Max + все forensic tools
    - TodoListMiddleware + FilesystemMiddleware + SubAgentMiddleware
  
  Layer 3: Subagents
    - service_analyzer: анализ сервисов, пакетов, cron
    - file_explorer: исследование файловой структуры
    - connection_analyzer: анализ SSH-подключений
    - history_analyzer: анализ истории команд

Использует:
  - deepagents (create_deep_agent) — Deep Agent SDK
  - langgraph (StateGraph) — оркестрация workflow
  - langchain-gigachat (GigaChat) — LLM
  - Существующие tools проекта для сбора и анализа артефактов
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
    build_deep_agent_task,
)
from src.tools.image_manager import get_image_manager
from src.tools import (
    # Image tools
    open_disk_image,
    close_disk_image,
    get_os_info,
    read_file_from_image,
    list_directory_in_image,
    extract_file_from_image,
    get_file_metadata_from_image,
    search_in_image_files,
    # Artifact tools
    collect_os_info,
    collect_users_info,
    collect_command_history,
    collect_services_info,
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
    # Filesystem tools
    calculate_file_hashes,
    read_local_file,
    write_local_file,
    list_local_directory,
    search_in_local_files,
)
from src.utils.logger import get_logger
from src.utils.filesystem import FileSystemUtils

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
    
    llm = GigaChat(**kwargs)
    logger.info(f"GigaChat LLM created: model={kwargs['model']}, timeout={gigachat_timeout}")
    return llm


# ==================== DEEP AGENT FACTORY ====================

def get_all_forensic_tools() -> list:
    """Получить список всех forensic tools для Deep Agent."""
    return [
        # Image tools
        read_file_from_image,
        list_directory_in_image,
        extract_file_from_image,
        get_file_metadata_from_image,
        search_in_image_files,
        # Artifact tools (сбор данных)
        collect_os_info,
        collect_users_info,
        collect_command_history,
        collect_services_info,
        collect_cron_info,
        collect_packages_info,
        collect_docker_info,
        collect_ssh_artifacts,
        collect_network_config,
        collect_auth_logs,
        collect_logs_info,
        extract_home_files,
        # Analysis tools
        extract_entities_from_text,
        parse_passwd_file,
        parse_services_list,
        extract_public_ips,
        parse_ssh_successful_logins,
        # Investigation management
        get_investigation_context,
        record_finding,
        record_explored_path,
        # Local filesystem
        calculate_file_hashes,
        read_local_file,
        write_local_file,
        list_local_directory,
        search_in_local_files,
    ]


def create_forensic_deep_agent(llm=None):
    """
    Создать Deep Agent для криминалистического анализа.
    
    Использует create_deep_agent из deepagents с:
    - GigaChat-2-Max как LLM
    - Все forensic tools
    - Кастомный системный промпт
    - 4 субагента (service_analyzer, file_explorer, connection_analyzer, history_analyzer)
    
    Args:
        llm: BaseChatModel instance (если None, создаётся GigaChat)
    
    Returns:
        CompiledStateGraph — скомпилированный Deep Agent
    """
    from deepagents import create_deep_agent
    # try:
    #     from deepagents import create_deep_agent
    # except ImportError:
    #     raise RuntimeError(
    #         "deepagents is required. Install: pip install deepagents"
    #     )
    
    if llm is None:
        llm = create_gigachat_llm()
    
    tools = get_all_forensic_tools()
    
    # Субагенты для делегирования специализированных задач
    subagents = [
        {
            "name": "service_analyzer",
            "description": (
                "Анализирует системные сервисы, пакеты и cron-задачи. "
                "Определяет нестандартные и подозрительные сервисы. "
                "Используй для детального анализа списков сервисов, пакетов и cron."
            ),
            "model": llm,
            "tools": [
                read_file_from_image, list_directory_in_image,
                collect_services_info, collect_cron_info, collect_packages_info,
                record_finding, record_explored_path, get_investigation_context,
            ],
            "system_prompt": SERVICE_ANALYZER_PROMPT,
        },
        {
            "name": "file_explorer",
            "description": (
                "Исследует файловую структуру образа диска. "
                "Находит нестандартные директории и файлы, скрытые файлы, "
                "подозрительные скрипты и бинарники. "
                "Используй для исследования конкретных директорий в образе."
            ),
            "model": llm,
            "tools": [
                read_file_from_image, list_directory_in_image,
                extract_file_from_image, get_file_metadata_from_image,
                search_in_image_files, extract_home_files,
                record_finding, record_explored_path, get_investigation_context,
                calculate_file_hashes,
            ],
            "system_prompt": FILE_EXPLORER_PROMPT,
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
                read_file_from_image, collect_auth_logs, collect_network_config,
                parse_ssh_successful_logins, extract_public_ips,
                extract_entities_from_text,
                record_finding, record_explored_path, get_investigation_context,
            ],
            "system_prompt": CONNECTION_ANALYZER_PROMPT,
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
                read_file_from_image, collect_command_history,
                extract_public_ips, extract_entities_from_text,
                record_finding, record_explored_path, get_investigation_context,
            ],
            "system_prompt": HISTORY_ANALYZER_PROMPT,
        },
    ]
    
    agent = create_deep_agent(
        name="forseti",
        model=llm,
        tools=tools,
        system_prompt=FORENSIC_SYSTEM_PROMPT,
        subagents=subagents,
    )
    
    logger.info("Forensic Deep Agent created with 4 subagents")
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

def _build_triage_summary(triage_data: Dict) -> str:
    """Сформировать краткую сводку собранных артефактов для Deep Agent."""
    parts = []
    
    # ОС
    os_info = triage_data.get('os_info', {})
    if os_info:
        os_release = os_info.get('/etc/os-release', '')
        if os_release:
            for line in os_release.split('\n'):
                if line.startswith('PRETTY_NAME='):
                    os_name = line.split('=', 1)[1].strip('"')
                    parts.append(f"ОС: {os_name}")
                    # parts.append(f"ОС: {line.split('=', 1)[1].strip('\"')}")
                    break
    
    # Пользователи
    passwd = triage_data.get('passwd', '')
    if passwd:
        user_count = len([l for l in passwd.split('\n') if l.strip() and not l.startswith('#')])
        parts.append(f"Пользователей в /etc/passwd: {user_count}")
    
    shadow = triage_data.get('shadow', '')
    if shadow:
        parts.append(f"Файл /etc/shadow: доступен ({len(shadow)} символов)")
    
    # История
    history = triage_data.get('history', {})
    if history:
        total_cmds = sum(len(cmds) if isinstance(cmds, list) else 0 for cmds in history.values())
        parts.append(f"Пользователей с историей: {len(history)}, всего команд: {total_cmds}")
    
    # Сервисы
    services = triage_data.get('services', {})
    if services:
        total_svc = services.get('total_services', 0)
        parts.append(f"Сервисов: {total_svc}")
    
    # Cron
    cron = triage_data.get('cron', {})
    if cron:
        parts.append(f"Cron-данные: собраны")
    
    # Пакеты
    packages = triage_data.get('packages', {})
    if packages:
        parts.append(f"Пакеты: собраны")
    
    # Docker
    docker = triage_data.get('docker', {})
    if docker and docker.get('docker_installed'):
        parts.append(f"Docker: установлен, контейнеров: {len(docker.get('containers', []))}")
    
    # SSH
    ssh = triage_data.get('ssh', {})
    if ssh:
        ak = ssh.get('authorized_keys', {})
        parts.append(f"SSH: пользователей с authorized_keys: {len(ak)}")
    
    # Auth logs
    auth_logs = triage_data.get('auth_logs', {})
    if auth_logs:
        parts.append(f"Auth logs: собраны")
    
    return "\n".join(f"- {p}" for p in parts) if parts else "Данные триажа не собраны."


def _build_analysis_summary(analysis_result: Dict) -> str:
    """Сформировать краткую сводку алгоритмического анализа."""
    if not analysis_result:
        return "Алгоритмический анализ не выполнен."
    
    parts = []
    summary = analysis_result.get('summary', {})
    anomalies = analysis_result.get('anomalies', [])
    
    parts.append(f"Пользователей: {summary.get('total_users', 0)}")
    parts.append(f"Команд: {summary.get('total_commands', 0)}")
    parts.append(f"Сервисов: {summary.get('total_services', 0)}")
    parts.append(f"Аномалий обнаружено: {len(anomalies)}")
    
    if anomalies:
        parts.append("\nАномалии:")
        for i, a in enumerate(anomalies[:10], 1):
            severity = a.get('severity', '?').upper()
            atype = a.get('type', '?')
            desc = a.get('description', a.get('command', ''))[:100]
            user = a.get('user', '')
            parts.append(f"  {i}. [{severity}] {atype}: {desc}" + (f" (user: {user})" if user else ""))
        if len(anomalies) > 10:
            parts.append(f"  ... и ещё {len(anomalies) - 10} аномалий")
    
    return "\n".join(parts)


# ==================== GRAPH NODES ====================

def open_image_node(state: ForensicAgentState) -> Dict:
    """Узел открытия образа диска."""
    print_phase("OPEN", f"Открытие образа: {state['image_path']}")
    
    messages = []
    result_json = open_disk_image.invoke({"image_path": state['image_path']})
    result = json.loads(result_json)
    
    messages.append({'role': 'tool', 'tool': 'open_disk_image', 'content': result_json})
    
    if result.get('success'):
        print_status('success', "Образ открыт успешно")
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
            result_json = tool_func.invoke(filtered_args if filtered_args else {})
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
    analysis_json = analyze_triage_data.invoke({'triage_data_json': triage_json})
    analysis_result = json.loads(analysis_json)
    
    recommendations = analysis_result.get('recommendations', [])
    anomalies = analysis_result.get('anomalies', [])
    
    print_status('success', f"Базовый анализ: {len(anomalies)} аномалий, {len(recommendations)} рекомендаций")
    
    # Сбрасываем хранилище расследования для нового анализа
    store = get_investigation_store()
    store.reset()
    
    messages.append({
        'role': 'assistant',
        'content': f"Baseline сбор завершён. Аномалий: {len(anomalies)}, рекомендаций: {len(recommendations)}."
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
    triage_summary = _build_triage_summary(triage_data)
    analysis_summary = _build_analysis_summary(analysis_result)
    
    # На повторных итерациях передаём контекст предыдущих находок
    investigation_context = ""
    if iteration > 0:
        prior_paths = state.get('investigated_paths', [])
        prior_findings = state.get('suspicious_findings', [])
        ctx_parts = []
        if prior_paths:
            ctx_parts.append(f"Уже исследовано путей: {len(prior_paths)}")
            for p in prior_paths[-20:]:  # Последние 20 для контекста
                suspicious_mark = " [ПОДОЗРИТЕЛЬНО]" if p.get('suspicious') else ""
                ctx_parts.append(f"  - {p.get('path', '?')}: {p.get('description', '')[:100]}{suspicious_mark}")
        if prior_findings:
            ctx_parts.append(f"\nНайдено подозрительных находок: {len(prior_findings)}")
            for f in prior_findings[-15:]:  # Последние 15
                ctx_parts.append(f"  - [{f.get('severity', '?').upper()}] {f.get('title', '?')}")
        ctx_parts.append("\nСфокусируйся на НЕИССЛЕДОВАННЫХ областях и углублённом анализе имеющихся находок.")
        investigation_context = "\n".join(ctx_parts)
    
    task_message = build_deep_agent_task(triage_summary, analysis_summary, recommendations, investigation_context)
    
    print_status('info', "Создание Deep Agent...")
    
    # Очищаем кэш инструментов от предыдущих запусков
    clear_tool_cache()
    
    deep_agent_output = None
    llm_analyses = {}
    
    try:
        # Создаём Deep Agent
        llm = create_gigachat_llm()
        deep_agent = create_forensic_deep_agent(llm=llm)
        
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
                    deep_agent = create_forensic_deep_agent(llm=llm)
                
                result = deep_agent.invoke(
                    {"messages": [{"role": "user", "content": task_message}]},
                    config={"recursion_limit": 100},
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
                    deep_agent = create_forensic_deep_agent(llm=llm)
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
            triage_data, analysis_result, recommendations
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
    
    # --- Дополнительный LLM-анализ для заполнения отчёта ---
    # Deep Agent выполняет расследование (findings, paths), но не генерирует
    # структурированные данные для секций отчёта (services, cron, packages и т.д.)
    # Запускаем fallback-анализ для заполнения этих секций.
    required_report_keys = ['services', 'cron', 'packages', 'web_software',
                            'nonstandard_root', 'ssh_logins', 'public_ips',
                            'user_summaries', 'expert_analysis']
    missing_keys = [k for k in required_report_keys if k not in llm_analyses]
    
    if missing_keys:
        print_phase("REPORT ANALYSIS", "Дополнительный LLM-анализ для секций отчёта")
        print_status('info', f"Секции без данных: {len(missing_keys)} из {len(required_report_keys)}")
        
        try:
            fallback_output, fallback_analyses = _fallback_llm_analysis(
                triage_data, analysis_result, recommendations
            )
            # Дополняем llm_analyses только недостающими секциями
            for key in missing_keys:
                if key in fallback_analyses:
                    llm_analyses[key] = fallback_analyses[key]
            
            # Если deep_agent_output пуст, используем fallback
            if not deep_agent_output or deep_agent_output == "Deep Agent не вернул текстовый ответ.":
                deep_agent_output = fallback_output
            
            print_status('success', f"Дополнено секций отчёта: {len([k for k in missing_keys if k in llm_analyses])}")
        except Exception as e:
            print_status('error', f"Ошибка дополнительного анализа: {e}")
            logger.exception("Supplementary analysis error")
    
    # Синхронизируем данные из InvestigationStore в состояние графа (только дельта)
    store = get_investigation_store()
    store_data = sync_store_to_state(store)
    
    return {
        'messages': messages,
        'investigated_paths': store_data['investigated_paths'],
        'suspicious_findings': store_data['suspicious_findings'],
        'llm_analyses': llm_analyses,
        'deep_agent_output': deep_agent_output,
        'current_step': 'evaluate_analysis',
    }


def _fallback_llm_analysis(
    triage_data: Dict,
    analysis_result: Dict,
    recommendations: List[str]
) -> tuple:
    """
    Fallback: прямой LLM-анализ через GigaChat без Deep Agents SDK.
    
    Используется если deepagents не установлен. Выполняет тот же анализ,
    но без субагентов, планирования и файловой системы.
    
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
    
    llm = create_gigachat_llm()
    llm_analyses = {}
    all_outputs = []
    
    # 1. Анализ сервисов
    services = triage_data.get('services', {})
    if services:
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
    if cron:
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
    if packages:
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
    if services or packages:
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
    if history:
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
    
    # 6. SSH успешные входы
    auth_logs = triage_data.get('auth_logs', {})
    if auth_logs:
        print_status('info', "Парсинг успешных SSH-входов...")
        try:
            auth_content = ""
            if isinstance(auth_logs, dict):
                for key, val in auth_logs.items():
                    if isinstance(val, str):
                        auth_content += val + "\n"
                    elif isinstance(val, dict) and 'content' in val:
                        auth_content += val['content'] + "\n"
            elif isinstance(auth_logs, str):
                auth_content = auth_logs
            
            if auth_content:
                ssh_result_json = parse_ssh_successful_logins.invoke({"auth_log_content": auth_content})
                ssh_result = json.loads(ssh_result_json)
                llm_analyses['ssh_logins'] = ssh_result
                print_status('success', f"SSH входов: {ssh_result.get('total_logins', 0)}")
        except Exception as e:
            print_status('error', f"Ошибка парсинга SSH: {e}")
    
    # 7. Извлечение публичных IP из истории
    if history:
        print_status('info', "Извлечение публичных IP из истории команд...")
        try:
            all_commands_text = ""
            for user, cmds in history.items():
                if isinstance(cmds, list):
                    all_commands_text += "\n".join(cmds) + "\n"
                elif isinstance(cmds, str):
                    all_commands_text += cmds + "\n"
            
            ips_result_json = extract_public_ips.invoke({"text": all_commands_text})
            ips_result = json.loads(ips_result_json)
            llm_analyses['public_ips'] = ips_result
            print_status('success', f"Публичных IP: {ips_result.get('total_public', 0)}")
        except Exception as e:
            print_status('error', f"Ошибка извлечения IP: {e}")
    
    # 8. Нестандартные файлы в корне
    print_status('info', "Проверка корневой директории...")
    try:
        root_listing_json = list_directory_in_image.invoke({"dir_path": "/"})
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
    
    # 9. Общий экспертный анализ
    print_status('info', "LLM: Формирование экспертного заключения...")
    try:
        expert_prompt = f"""Ты — эксперт по кибербезопасности. На основе собранных данных проведи анализ.

ДАННЫЕ ТРИАЖА:
{_build_triage_summary(triage_data)}

АЛГОРИТМИЧЕСКИЙ АНАЛИЗ:
{_build_analysis_summary(analysis_result)}

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
        'content': f"Отчёт сгенерирован: {report_path}"
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
    
    messages = []
    result_json = close_disk_image.invoke({})
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
    
    def run(self, image_path: str) -> Dict[str, Any]:
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
        
        return final_state


def run_deep_agent(image_path: str) -> Dict[str, Any]:
    """
    Удобная функция для запуска Deep Forensic Agent.
    
    Args:
        image_path: Путь к образу диска
    
    Returns:
        Финальное состояние агента
    """
    agent = ForensicDeepAgent()
    return agent.run(image_path)
