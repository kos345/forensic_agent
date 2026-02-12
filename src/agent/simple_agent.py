"""
Simple Forensic Agent - Простой агент для криминалистического анализа.

Использует LangGraph и GigaChat LLM для:
1. Открытие образа
2. Сбор всех артефактов
3. Анализ данных с помощью LLM
4. Генерация отчёта

Все сообщения выводятся в консоль.
Требует настройки .env файла с GIGACHAT_CREDENTIALS.
"""

import json
import os
import uuid
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Literal
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END

from src.agent.state import AgentState, TriageData
from src.tools.image_manager import get_image_manager
from src.tools import (
    # Image tools
    open_disk_image,
    close_disk_image,
    get_os_info,
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
    # Analysis tools
    analyze_triage_data,
    generate_html_report,
)
from src.utils.logger import get_logger
from src.utils.filesystem import FileSystemUtils

# Load environment variables
load_dotenv()

logger = get_logger("ForensicAgent")
fs_utils = FileSystemUtils()


# ==================== GIGACHAT CLIENT ====================

class GigaChatWrapper:
    """
    Обёртка для GigaChat LLM.
    
    Использует параметры из .env файла:
    - GIGACHAT_CREDENTIALS: API ключ
    - GIGACHAT_MODEL: модель (по умолчанию GigaChat-2-Max)
    - GIGACHAT_TEMPERATURE: температура (по умолчанию 0.2)
    - GIGACHAT_MAX_TOKENS: максимум токенов (по умолчанию 4096)
    """
    
    def __init__(self):
        self.credentials = os.getenv("GIGACHAT_CREDENTIALS")
        if not self.credentials:
            raise ValueError(
                "GIGACHAT_CREDENTIALS not found in environment. "
                "Please create .env file with your GigaChat API key."
            )
        
        self.model = os.getenv("GIGACHAT_MODEL", "GigaChat-2-Max")
        self.temperature = float(os.getenv("GIGACHAT_TEMPERATURE", "0.2"))
        self.max_tokens = int(os.getenv("GIGACHAT_MAX_TOKENS", "4096"))
        self.base_url = os.getenv("GIGACHAT_BASE_URL")
        self.scope = os.getenv("GIGACHAT_SCOPE")
        
        self._llm = None
    
    def _build_llm(self):
        """Создать экземпляр GigaChat LLM."""
        if self._llm is not None:
            return self._llm
        
        try:
            from langchain_gigachat import GigaChat
        except ImportError:
            raise RuntimeError(
                "langchain_gigachat is required. Install: pip install langchain-gigachat"
            )
        
        verify_ssl_env = os.getenv("GIGACHAT_VERIFY_SSL", "true").strip().lower()
        verify_ssl = verify_ssl_env not in {"0", "false", "no", "off"}
        ca_bundle_file = os.getenv("GIGACHAT_CA_BUNDLE")
        
        kwargs = {
            "credentials": self.credentials,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "verify_ssl_certs": verify_ssl,
        }
        
        if self.base_url:
            kwargs["base_url"] = self.base_url
        if self.scope:
            kwargs["scope"] = self.scope
        if ca_bundle_file:
            kwargs["ca_bundle_file"] = ca_bundle_file
        
        self._llm = GigaChat(**kwargs)
        return self._llm
    
    def invoke(self, prompt: str) -> str:
        """
        Вызвать GigaChat с промптом.
        
        Args:
            prompt: Текст промпта
            
        Returns:
            Ответ от модели
        """
        llm = self._build_llm()
        response = llm.invoke(prompt)
        return getattr(response, "content", str(response))
    
    def analyze_forensic_data(self, triage_data: Dict, analysis_result: Dict) -> str:
        """
        Проанализировать криминалистические данные с помощью LLM.
        
        Args:
            triage_data: Собранные артефакты
            analysis_result: Результат алгоритмического анализа
            
        Returns:
            Текстовый анализ от LLM
        """
        # Формируем промпт для анализа
        prompt = self._build_analysis_prompt(triage_data, analysis_result)
        return self.invoke(prompt)
    
    def _build_analysis_prompt(self, triage_data: Dict, analysis_result: Dict) -> str:
        """Построить промпт для анализа."""
        
        # Извлекаем ключевую информацию
        summary = analysis_result.get('summary', {})
        anomalies = analysis_result.get('anomalies', [])
        recommendations = analysis_result.get('recommendations', [])
        
        # История команд (первые 50 для каждого пользователя)
        history_str = ""
        history = triage_data.get('history', {})
        if history:
            for user, commands in list(history.items())[:5]:  # Первые 5 пользователей
                if commands:
                    cmds = commands[:30] if isinstance(commands, list) else commands.split('\n')[:30]
                    history_str += f"\n[{user}]:\n" + "\n".join(cmds[:30])
        
        # SSH ключи
        ssh_info = ""
        ssh = triage_data.get('ssh', {})
        if ssh:
            auth_keys = ssh.get('authorized_keys', {})
            if auth_keys:
                ssh_info = f"Пользователи с authorized_keys: {list(auth_keys.keys())}"
        
        # Сервисы
        services_info = ""
        services = triage_data.get('services', {})
        if services:
            systemd = services.get('systemd', [])
            if systemd:
                service_names = [s.get('name', str(s)) if isinstance(s, dict) else str(s) for s in systemd[:20]]
                services_info = f"Systemd сервисы: {', '.join(service_names)}"
        
        # Docker
        docker_info = ""
        docker = triage_data.get('docker', {})
        if docker and docker.get('docker_installed'):
            containers = docker.get('containers', [])
            docker_info = f"Docker установлен. Контейнеры: {len(containers)}"
        
        prompt = f"""Ты — эксперт по кибербезопасности и криминалистическому анализу Linux-серверов.

Проанализируй собранные данные с сервера и определи:
1. Есть ли признаки компрометации сервера
2. Какие подозрительные действия могли быть выполнены злоумышленниками
3. Какие рекомендации по расследованию и защите

СОБРАННАЯ СТАТИСТИКА:
- Всего пользователей: {summary.get('total_users', 0)}
- Команд в истории: {summary.get('total_commands', 0)}
- Всего сервисов: {summary.get('total_services', 0)}

ОБНАРУЖЕННЫЕ АНОМАЛИИ ({len(anomalies)}):
"""
        
        if anomalies:
            for i, anomaly in enumerate(anomalies[:15], 1):
                prompt += f"{i}. [{anomaly.get('severity', 'unknown').upper()}] {anomaly.get('type', '')}"
                if anomaly.get('description'):
                    prompt += f": {anomaly['description']}"
                if anomaly.get('command'):
                    prompt += f"\n   Команда: {anomaly['command'][:100]}"
                if anomaly.get('user'):
                    prompt += f" (пользователь: {anomaly['user']})"
                prompt += "\n"
        else:
            prompt += "Аномалии не обнаружены алгоритмически.\n"
        
        prompt += f"""
ИСТОРИЯ КОМАНД (выборка):
{history_str if history_str else "Не найдена"}

SSH:
{ssh_info if ssh_info else "SSH артефакты не найдены"}

СЕРВИСЫ:
{services_info if services_info else "Сервисы не найдены"}

DOCKER:
{docker_info if docker_info else "Docker не установлен"}

ЗАДАЧА:
Проведи экспертный анализ и напиши отчёт со следующими разделами:

1. РЕЗЮМЕ (краткое описание состояния системы)
2. ПРИЗНАКИ КОМПРОМЕТАЦИИ (если есть)
3. ПОДОЗРИТЕЛЬНЫЕ НАХОДКИ (детальный анализ аномалий)
4. ВЕРОЯТНЫЙ СЦЕНАРИЙ АТАКИ (если есть признаки)
5. РЕКОМЕНДАЦИИ (что делать дальше)

Пиши конкретно и по существу. Если данных недостаточно для выводов, укажи это.
"""
        
        return prompt


# ==================== CONSOLE OUTPUT ====================

class ConsoleColors:
    """ANSI цвета для консоли."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    # Роли
    SYSTEM = "\033[95m"      # Magenta
    USER = "\033[94m"        # Blue
    ASSISTANT = "\033[92m"   # Green
    TOOL = "\033[93m"        # Yellow
    ERROR = "\033[91m"       # Red
    LLM = "\033[96m"         # Cyan
    
    # Статусы
    SUCCESS = "\033[92m"
    WARNING = "\033[93m"
    INFO = "\033[96m"        # Cyan


def print_message(role: str, content: str, tool_name: str = None):
    """Вывести сообщение в консоль с цветовой разметкой."""
    colors = {
        'system': ConsoleColors.SYSTEM,
        'user': ConsoleColors.USER,
        'assistant': ConsoleColors.ASSISTANT,
        'tool': ConsoleColors.TOOL,
        'error': ConsoleColors.ERROR,
        'llm': ConsoleColors.LLM,
    }
    
    color = colors.get(role.lower(), ConsoleColors.RESET)
    
    print(f"\n{ConsoleColors.BOLD}{'='*60}{ConsoleColors.RESET}")
    
    if tool_name:
        print(f"{color}[{role.upper()}] Tool: {tool_name}{ConsoleColors.RESET}")
    else:
        print(f"{color}[{role.upper()}]{ConsoleColors.RESET}")
    
    print(f"{ConsoleColors.BOLD}{'-'*60}{ConsoleColors.RESET}")
    
    # Ограничиваем вывод для больших сообщений
    if len(content) > 3000:
        print(content[:3000])
        print(f"\n{ConsoleColors.INFO}... (truncated, {len(content)} chars total){ConsoleColors.RESET}")
    else:
        print(content)


def print_status(status: str, message: str):
    """Вывести статус операции."""
    if status == 'success':
        color = ConsoleColors.SUCCESS
        symbol = '✓'
    elif status == 'error':
        color = ConsoleColors.ERROR
        symbol = '✗'
    elif status == 'warning':
        color = ConsoleColors.WARNING
        symbol = '⚠'
    else:
        color = ConsoleColors.INFO
        symbol = '→'
    
    print(f"{color}{symbol} {message}{ConsoleColors.RESET}")


# ==================== SYSTEM PROMPT ====================

SYSTEM_PROMPT = """Ты — Forseti, AI-агент для криминалистического анализа образов дисков Linux-серверов.

ТВОЯ ЗАДАЧА:
Провести полный анализ образа диска для выявления следов компрометации сервера хакерами.

ПРОЦЕСС АНАЛИЗА:
1. Собрать системную информацию (ОС, пользователи, сервисы)
2. Собрать историю команд всех пользователей
3. Проанализировать cron задачи и автозагрузку
4. Проверить SSH ключи и конфигурацию
5. Изучить Docker контейнеры (если есть)
6. Проанализировать сетевую конфигурацию
7. Просмотреть логи авторизации
8. Извлечь файлы из домашних директорий
9. Провести экспертный анализ с помощью LLM

ИНДИКАТОРЫ КОМПРОМЕТАЦИИ (IoC):
- Пользователи с UID 0 (кроме root)
- Подозрительные команды: wget, curl, nc, base64, chmod 777
- Нестандартные сервисы и cron задачи
- Неизвестные SSH ключи в authorized_keys
- Криптомайнеры и backdoor-ы

ФОРМАТ ВЫВОДА:
После сбора и анализа данных будет сгенерирован HTML отчёт с экспертными выводами от LLM.
"""


# ==================== CONFIG & GLOB RESOLUTION ====================

def _load_triage_config() -> Dict:
    """
    Загрузить конфигурацию из configs/triage.yaml.
    
    Ищет файл сначала рядом с проектом, потом в текущей директории.
    При ошибке возвращает пустой словарь (функции используют свои дефолты).
    """
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
    """
    Разрешить glob-паттерны (* подстановки) в путях образа диска.
    
    Паттерны типа /home/*/.bash_history разрешаются через листинг
    родительской директории в образе.
    
    Примеры:
        /home/*/.bash_history → [/home/user1/.bash_history, /home/user2/.bash_history]
        /home/*/.ssh          → [/home/user1/.ssh, /home/user2/.ssh]
        /etc/hosts            → [/etc/hosts] (без изменений)
    """
    manager = get_image_manager()
    resolved = []
    
    for path in paths:
        if '*' not in path:
            resolved.append(path)
            continue
        
        # Разбиваем путь на части
        parts = path.split('/')
        
        # Находим позицию глоба
        glob_idx = next(i for i, p in enumerate(parts) if '*' in p)
        
        # Собираем родительскую директорию
        parent = '/'.join(parts[:glob_idx]) or '/'
        
        # Суффикс после глоба
        suffix = '/'.join(parts[glob_idx + 1:])
        
        # Листинг родительской директории
        entries = manager.list_directory(parent)
        for entry in entries:
            if entry['type'] == 'directory' and entry['name'] not in ('.', '..'):
                full_path = f"{parent.rstrip('/')}/{entry['name']}"
                if suffix:
                    full_path += f"/{suffix}"
                resolved.append(full_path)
        
        logger.debug(f"Resolved glob {path} → {len(resolved)} paths")
    
    return resolved


# ==================== GRAPH NODES ====================

def open_image_node(state: AgentState) -> Dict:
    """Узел открытия образа диска."""
    print_status('info', f"Opening image: {state['image_path']}")
    
    messages = []
    
    # Вызываем tool
    result_json = open_disk_image.invoke({"image_path": state['image_path']})
    result = json.loads(result_json)
    
    print_message('tool', result_json, 'open_disk_image')
    
    messages.append({
        'role': 'tool',
        'tool': 'open_disk_image',
        'content': result_json
    })
    
    if result.get('success'):
        print_status('success', "Image opened successfully")
        return {
            'messages': messages,
            'image_open': True,
            'current_step': 'collect_artifacts'
        }
    else:
        print_status('error', f"Failed to open image: {result.get('error')}")
        return {
            'messages': messages,
            'image_open': False,
            'errors': [f"Failed to open image: {result.get('error')}"],
            'current_step': 'error'
        }


def collect_artifacts_node(state: AgentState) -> Dict:
    """Узел сбора артефактов. Загружает пути из configs/triage.yaml и передаёт в tools."""
    print_status('info', "Collecting artifacts...")
    
    messages = []
    triage = TriageData()
    
    # ========== Загружаем конфигурацию путей из triage.yaml ==========
    config = _load_triage_config()
    artifacts_cfg = config.get('artifacts', {})
    logs_cfg = artifacts_cfg.get('logs', {})
    
    print_status('info', f"Config loaded: {len(artifacts_cfg)} artifact sections")
    
    # Разрешаем glob-паттерны (для /home/*/ в history и ssh)
    history_paths = _resolve_image_globs(artifacts_cfg.get('history', []))
    ssh_paths = _resolve_image_globs(artifacts_cfg.get('ssh', []))
    
    print_status('info', f"Resolved history paths: {len(history_paths)}, ssh paths: {len(ssh_paths)}")
    
    # ========== Список инструментов с путями из конфига ==========
    artifact_tools = [
        ('collect_os_info', collect_os_info,
         {'paths': artifacts_cfg.get('system')}),
        
        ('collect_users_info', collect_users_info,
         {'paths': artifacts_cfg.get('users')}),
        
        ('collect_command_history', collect_command_history,
         {'history_paths': history_paths or None}),
        
        ('collect_services_info', collect_services_info,
         {'paths': artifacts_cfg.get('services')}),
        
        ('collect_cron_info', collect_cron_info,
         {'paths': artifacts_cfg.get('cron')}),
        
        ('collect_packages_info', collect_packages_info,
         {'paths': artifacts_cfg.get('packages')}),
        
        ('collect_docker_info', collect_docker_info,
         {'paths': artifacts_cfg.get('docker')}),
        
        ('collect_ssh_artifacts', collect_ssh_artifacts,
         {'paths': ssh_paths or None}),
        
        ('collect_network_config', collect_network_config,
         {'paths': artifacts_cfg.get('network')}),
        
        ('collect_auth_logs', collect_auth_logs,
         {}),  # auth logs — нет отдельной секции в yaml, используем дефолты
        
        ('collect_logs_info', collect_logs_info,
         {'var_paths': logs_cfg.get('var') if logs_cfg else None,
          'www_paths': logs_cfg.get('www') if logs_cfg else None}),
        
        ('extract_home_files', extract_home_files,
         {}),
    ]
    
    for tool_name, tool_func, tool_args in artifact_tools:
        print_status('info', f"Running {tool_name}...")
        
        try:
            # Фильтруем None значения, чтобы tools использовали свои дефолты
            filtered_args = {k: v for k, v in tool_args.items() if v is not None}
            result_json = tool_func.invoke(filtered_args if filtered_args else {})
            result = json.loads(result_json)
            
            # Выводим в консоль (сокращённо)
            preview = result_json[:500] + '...' if len(result_json) > 500 else result_json
            print_message('tool', preview, tool_name)
            
            # Обновляем triage data
            triage.update_from_tool_result(tool_name, result)
            
            messages.append({
                'role': 'tool',
                'tool': tool_name,
                'content': result_json
            })
            
            if result.get('success', True):
                print_status('success', f"{tool_name} completed")
            else:
                print_status('warning', f"{tool_name} had issues: {result.get('error', 'unknown')}")
                
        except Exception as e:
            print_status('error', f"{tool_name} failed: {e}")
            triage.collection_errors.append(f"{tool_name}: {str(e)}")
            messages.append({
                'role': 'tool',
                'tool': tool_name,
                'content': json.dumps({'success': False, 'error': str(e)})
            })
    
    # Формируем triage_data
    triage_data = triage.to_dict()
    
    # Добавляем сообщение assistant о завершении сбора
    assistant_msg = f"""Сбор артефактов завершён.

Собрано:
- Пользователей: {triage.users_count}
- Пользователей с историей: {len(triage.history)}
- Сервисов: {triage.services.get('total_services', 0) if triage.services else 0}
- Docker установлен: {triage.docker.get('docker_installed', False) if triage.docker else False}
- SSH ключей: {len(triage.ssh.get('ssh_keys', [])) if triage.ssh else 0}
- Ошибок сбора: {len(triage.collection_errors)}

Перехожу к анализу данных."""

    print_message('assistant', assistant_msg)
    messages.append({
        'role': 'assistant',
        'content': assistant_msg
    })
    
    return {
        'messages': messages,
        'triage_data': triage_data,
        'current_step': 'analyze'
    }


def analyze_node(state: AgentState) -> Dict:
    """Узел анализа данных (алгоритмический + LLM)."""
    print_status('info', "Analyzing collected data...")
    
    messages = []
    
    # Получаем triage_data
    triage_data = state.get('triage_data', {})
    triage_json = json.dumps(triage_data, ensure_ascii=False)
    
    # ========== Шаг 1: Алгоритмический анализ ==========
    print_status('info', "Running algorithmic analysis (analyze_triage_data)...")
    analysis_json = analyze_triage_data.invoke({'triage_data_json': triage_json})
    analysis_result = json.loads(analysis_json)
    
    print_message('tool', analysis_json, 'analyze_triage_data')
    
    messages.append({
        'role': 'tool',
        'tool': 'analyze_triage_data',
        'content': analysis_json
    })
    
    # Формируем сообщение о результатах алгоритмического анализа
    summary = analysis_result.get('summary', {})
    anomalies = analysis_result.get('anomalies', [])
    
    algo_msg = f"""Алгоритмический анализ завершён.

СТАТИСТИКА:
- Всего пользователей: {summary.get('total_users', 0)}
- Всего команд: {summary.get('total_commands', 0)}
- Всего сервисов: {summary.get('total_services', 0)}

АНОМАЛИИ: {len(anomalies)}
"""
    
    if anomalies:
        algo_msg += "\nПервые аномалии:\n"
        for i, a in enumerate(anomalies[:5], 1):
            algo_msg += f"  {i}. [{a.get('severity', '?').upper()}] {a.get('type', '?')}\n"
    
    print_message('assistant', algo_msg)
    messages.append({
        'role': 'assistant',
        'content': algo_msg
    })
    
    # ========== Шаг 2: LLM анализ через GigaChat ==========
    print_status('info', "Running LLM analysis (GigaChat)...")
    
    llm_analysis = None
    try:
        gigachat = GigaChatWrapper()
        
        print_message('assistant', "Отправляю данные в GigaChat для экспертного анализа...")
        
        llm_analysis = gigachat.analyze_forensic_data(triage_data, analysis_result)
        
        print_message('llm', llm_analysis)
        
        messages.append({
            'role': 'llm',
            'model': gigachat.model,
            'content': llm_analysis
        })
        
        # Добавляем LLM анализ в результат
        analysis_result['llm_analysis'] = llm_analysis
        analysis_result['llm_model'] = gigachat.model
        
        print_status('success', "LLM analysis completed")
        
    except Exception as e:
        error_msg = f"LLM analysis failed: {e}"
        print_status('error', error_msg)
        messages.append({
            'role': 'error',
            'content': error_msg
        })
        analysis_result['llm_analysis'] = None
        analysis_result['llm_error'] = str(e)
    
    return {
        'messages': messages,
        'analysis_result': analysis_result,
        'current_step': 'report'
    }


def generate_report_node(state: AgentState) -> Dict:
    """Узел генерации отчёта."""
    print_status('info', "Generating report...")
    
    messages = []
    
    # Получаем данные
    triage_data = state.get('triage_data', {})
    analysis_result = state.get('analysis_result', {})
    
    # Определяем пути для сохранения
    output_dir = Path("output") / datetime.now().strftime("%Y%m%d_%H%M%S")
    fs_utils.ensure_directory(output_dir)
    
    report_path = output_dir / "report.html"
    triage_path = output_dir / "triage_data.json"
    analysis_path = output_dir / "analysis_result.json"
    
    # ========== Сохраняем triage_data ==========
    print_status('info', f"Saving triage_data to {triage_path}...")
    fs_utils.safe_write(triage_path, json.dumps(triage_data, ensure_ascii=False, indent=2))
    print_status('success', f"Saved: {triage_path}")
    
    messages.append({
        'role': 'assistant',
        'content': f"Сохранён файл: {triage_path}"
    })
    
    # ========== Сохраняем analysis_result ==========
    print_status('info', f"Saving analysis_result to {analysis_path}...")
    fs_utils.safe_write(analysis_path, json.dumps(analysis_result, ensure_ascii=False, indent=2))
    print_status('success', f"Saved: {analysis_path}")
    
    messages.append({
        'role': 'assistant',
        'content': f"Сохранён файл: {analysis_path}"
    })
    
    # ========== Генерируем HTML отчёт ==========
    print_status('info', "Generating HTML report...")
    
    # Добавляем LLM анализ в triage_data для отчёта
    triage_for_report = triage_data.copy()
    if analysis_result.get('llm_analysis'):
        triage_for_report['llm_expert_analysis'] = analysis_result['llm_analysis']
    
    report_result_json = generate_html_report.invoke({
        'analysis_json': json.dumps(analysis_result, ensure_ascii=False),
        'triage_data_json': json.dumps(triage_for_report, ensure_ascii=False),
        'output_path': str(report_path)
    })
    report_result = json.loads(report_result_json)
    
    print_message('tool', report_result_json, 'generate_html_report')
    
    messages.append({
        'role': 'tool',
        'tool': 'generate_html_report',
        'content': report_result_json
    })
    
    # Финальное сообщение
    if report_result.get('success'):
        print_status('success', f"Report generated: {report_path}")
        
        assistant_msg = f"""Анализ завершён успешно!

СОХРАНЁННЫЕ ФАЙЛЫ:
1. HTML отчёт: {report_path}
2. Данные триажа (triage_data.json): {triage_path}
3. Результат анализа (analysis_result.json): {analysis_path}

ИТОГИ:
- Обнаружено аномалий: {len(analysis_result.get('anomalies', []))}
- Пользователей: {analysis_result.get('summary', {}).get('total_users', 0)}
- Команд в истории: {analysis_result.get('summary', {}).get('total_commands', 0)}
- LLM анализ: {'Выполнен' if analysis_result.get('llm_analysis') else 'Не выполнен'}

Откройте {report_path} в браузере для просмотра полного отчёта.
"""
    else:
        print_status('error', f"Report generation failed: {report_result.get('error')}")
        assistant_msg = f"Ошибка генерации отчёта: {report_result.get('error')}"
    
    print_message('assistant', assistant_msg)
    messages.append({
        'role': 'assistant',
        'content': assistant_msg
    })
    
    return {
        'messages': messages,
        'report_path': str(report_path) if report_result.get('success') else None,
        'current_step': 'done'
    }


def close_image_node(state: AgentState) -> Dict:
    """Узел закрытия образа."""
    print_status('info', "Closing image...")
    
    messages = []
    
    result_json = close_disk_image.invoke({})
    result = json.loads(result_json)
    
    print_message('tool', result_json, 'close_disk_image')
    
    messages.append({
        'role': 'tool',
        'tool': 'close_disk_image',
        'content': result_json
    })
    
    if result.get('success'):
        print_status('success', "Image closed")
    
    return {
        'messages': messages,
        'image_open': False,
        'current_step': 'finished'
    }


# ==================== GRAPH ROUTING ====================

def route_after_open(state: AgentState) -> Literal["collect_artifacts", "end"]:
    """Роутинг после открытия образа."""
    if state.get('image_open'):
        return "collect_artifacts"
    return "end"


def route_after_report(state: AgentState) -> Literal["close_image", "end"]:
    """Роутинг после генерации отчёта."""
    if state.get('image_open'):
        return "close_image"
    return "end"


# ==================== GRAPH BUILDER ====================

def build_graph() -> StateGraph:
    """Построить граф агента."""
    
    # Создаём граф
    graph = StateGraph(AgentState)
    
    # Добавляем узлы
    graph.add_node("open_image", open_image_node)
    graph.add_node("collect_artifacts", collect_artifacts_node)
    graph.add_node("analyze", analyze_node)
    graph.add_node("generate_report", generate_report_node)
    graph.add_node("close_image", close_image_node)
    
    # Определяем точку входа
    graph.set_entry_point("open_image")
    
    # Добавляем рёбра
    graph.add_conditional_edges(
        "open_image",
        route_after_open,
        {
            "collect_artifacts": "collect_artifacts",
            "end": END
        }
    )
    
    graph.add_edge("collect_artifacts", "analyze")
    graph.add_edge("analyze", "generate_report")
    
    graph.add_conditional_edges(
        "generate_report",
        route_after_report,
        {
            "close_image": "close_image",
            "end": END
        }
    )
    
    graph.add_edge("close_image", END)
    
    return graph


# ==================== AGENT CLASS ====================

class ForensicAgent:
    """
    Forensic Agent - Агент для криминалистического анализа.
    
    Использует LangGraph и GigaChat для выполнения workflow:
    1. Открытие образа
    2. Сбор артефактов
    3. Алгоритмический анализ
    4. LLM анализ (GigaChat)
    5. Генерация отчёта
    6. Закрытие образа
    """
    
    def __init__(self):
        """Инициализация агента."""
        self.graph = build_graph()
        self.app = self.graph.compile()
    
    def run(self, image_path: str) -> Dict[str, Any]:
        """
        Запустить анализ образа.
        
        Args:
            image_path: Путь к образу диска
            
        Returns:
            Финальное состояние агента
        """
        # Выводим начальные сообщения
        print_message('system', SYSTEM_PROMPT)
        
        user_msg = f"Проанализируй образ диска: {image_path}"
        print_message('user', user_msg)
        
        # Начальное состояние
        initial_state: AgentState = {
            'messages': [
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': user_msg}
            ],
            'image_path': image_path,
            'image_open': False,
            'os_info': None,
            'triage_data': None,
            'analysis_result': None,
            'report_path': None,
            'current_step': 'start',
            'errors': []
        }
        
        # Запускаем граф
        print(f"\n{ConsoleColors.BOLD}{'='*60}")
        print(f"🔍 FORSETI FORENSIC AGENT (GigaChat LLM)")
        print(f"{'='*60}{ConsoleColors.RESET}\n")
        
        final_state = self.app.invoke(initial_state)
        
        # Выводим итоги
        print(f"\n{ConsoleColors.BOLD}{'='*60}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'='*60}{ConsoleColors.RESET}\n")
        
        if final_state.get('report_path'):
            print_status('success', f"Report: {final_state['report_path']}")
        
        if final_state.get('errors'):
            print_status('warning', f"Errors: {len(final_state['errors'])}")
            for error in final_state['errors']:
                print(f"  - {error}")
        
        return final_state


def run_agent(image_path: str) -> Dict[str, Any]:
    """
    Удобная функция для запуска агента.
    
    Args:
        image_path: Путь к образу диска
        
    Returns:
        Финальное состояние агента
    """
    agent = ForensicAgent()
    return agent.run(image_path)


# ==================== CLI ====================

def main():
    """CLI точка входа для агента."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Forseti Forensic Agent - AI анализ образов дисков (GigaChat)'
    )
    parser.add_argument(
        '--image', '-i',
        type=str,
        required=True,
        help='Путь к образу диска (RAW формат)'
    )
    
    args = parser.parse_args()
    
    # Проверяем образ
    image_path = Path(args.image)
    if not image_path.exists():
        print_status('error', f"Image not found: {image_path}")
        return 1
    
    # Проверяем .env
    if not os.getenv("GIGACHAT_CREDENTIALS"):
        print_status('error', "GIGACHAT_CREDENTIALS not found!")
        print("  Please create .env file with your GigaChat API key.")
        print("  See .env.example for reference.")
        return 1
    
    # Запускаем агента
    try:
        result = run_agent(str(image_path))
        return 0 if result.get('report_path') else 1
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 1
    except Exception as e:
        print_status('error', f"Agent failed: {e}")
        logger.exception("Agent error")
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
