"""
Agent State - Определение состояния агента LangGraph.

Содержит:
- TriageData: Структура для хранения собранных артефактов
- BaseAgentState: Общие поля состояния для всех агентов
- AgentState: Состояние простого агента (наследует BaseAgentState)
- InvestigatedPath: Запись об исследованном пути
- SuspiciousFinding: Запись о подозрительной находке
- ForensicAgentState: Расширенное состояние для Deep Forensic Agent (наследует BaseAgentState)
- sync_store_to_state: Синхронизация InvestigationStore → ForensicAgentState
"""

from typing import TypedDict, Optional, List, Dict, Any, Annotated, TYPE_CHECKING
from dataclasses import dataclass, field
from datetime import datetime
import operator

if TYPE_CHECKING:
    from src.tools.investigation_tools import InvestigationStore


@dataclass
class TriageData:
    """
    Структура для хранения собранных артефактов.
    
    Объединяет результаты всех artifact_tools в единый формат
    для передачи в analyze_triage_data().
    """
    # Системная информация
    os_info: Optional[Dict] = None
    
    # Пользователи
    passwd: Optional[str] = None
    shadow: Optional[str] = None
    group: Optional[str] = None
    sudoers: Optional[str] = None
    users_count: int = 0
    
    # История команд
    history: Dict[str, List[str]] = field(default_factory=dict)
    
    # Сервисы
    services: Optional[Dict] = None
    
    # Cron
    cron: Optional[Dict] = None
    
    # Пакеты
    packages: Optional[Dict] = None
    
    # Docker
    docker: Optional[Dict] = None
    
    # SSH
    ssh: Optional[Dict] = None
    
    # Сеть
    network: Optional[Dict] = None
    
    # Логи авторизации
    auth_logs: Optional[Dict] = None
    
    # Логи системы
    logs: Optional[Dict] = None
    
    # Извлечённые файлы
    extracted_files: Optional[Dict] = None
    
    # IOCs
    iocs: List[Dict] = field(default_factory=list)
    
    # Метаданные сбора
    collection_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    collection_errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь для analyze_triage_data."""
        return {
            # Пользователи - формат для analyze_triage_data
            'passwd': self.passwd,
            'shadow': self.shadow,
            'group': self.group,
            'sudoers': self.sudoers,
            
            # История команд
            'history': self.history,
            
            # Сервисы
            'services': self.services,
            
            # Cron
            'cron': self.cron,
            
            # Пакеты
            'packages': self.packages,
            
            # Docker
            'docker': self.docker,
            
            # SSH
            'ssh': self.ssh,
            
            # Сеть
            'network': self.network,
            
            # Auth logs
            'auth_logs': self.auth_logs,
            
            # IOCs
            'iocs': self.iocs,
            
            # Метаданные
            'os_info': self.os_info,
            'collection_timestamp': self.collection_timestamp,
            'collection_errors': self.collection_errors,
        }
    
    def update_from_tool_result(self, tool_name: str, result: Dict):
        """
        Обновить данные из результата tool.
        
        Args:
            tool_name: Имя вызванного tool
            result: Результат выполнения tool (уже распарсенный JSON)
        """
        if not result.get('success', True):
            error = result.get('error', f'{tool_name} failed')
            self.collection_errors.append(f"{tool_name}: {error}")
            return
        
        if tool_name == 'collect_os_info':
            self.os_info = result.get('files', {})
            
        elif tool_name == 'collect_users_info':
            self.passwd = result.get('passwd')
            self.shadow = result.get('shadow')
            self.group = result.get('group')
            self.sudoers = result.get('sudoers')
            self.users_count = result.get('users_count', 0)
            
        elif tool_name == 'collect_command_history':
            users = result.get('users', {})
            self.history = users
            
        elif tool_name == 'collect_services_info':
            self.services = {
                'systemd': result.get('systemd', []),
                'initd': result.get('initd', []),
                'rcd': result.get('rcd', []),
                'xinetd': result.get('xinetd', []),
                'total_services': result.get('total_services', 0)
            }
            
        elif tool_name == 'collect_cron_info':
            self.cron = result
            
        elif tool_name == 'collect_packages_info':
            self.packages = result
            
        elif tool_name == 'collect_docker_info':
            self.docker = result
            
        elif tool_name == 'collect_ssh_artifacts':
            self.ssh = result
            
        elif tool_name == 'collect_network_config':
            self.network = result
            
        elif tool_name == 'collect_auth_logs':
            self.auth_logs = result
            
        elif tool_name == 'collect_logs_info':
            self.logs = result
            
        elif tool_name == 'extract_home_files':
            self.extracted_files = result


# ==================== БАЗОВОЕ СОСТОЯНИЕ ====================

class BaseAgentState(TypedDict):
    """
    Общие поля состояния для всех агентов LangGraph.
    
    Attributes:
        messages: История сообщений (system, user, assistant, tool).
                  Используется аддитивный reducer (operator.add) —
                  новые сообщения дописываются к существующим.
        image_path: Путь к образу диска
        image_open: Открыт ли образ
        os_info: Информация об ОС
        triage_data: Собранные артефакты (dict из TriageData.to_dict())
        analysis_result: Результат алгоритмического анализа
        report_path: Путь к сгенерированному отчёту
        current_step: Текущий шаг выполнения
        errors: Список ошибок
    """
    messages: Annotated[List[Dict], operator.add]
    image_path: str
    image_open: bool
    os_info: Optional[Dict]
    triage_data: Optional[Dict]
    analysis_result: Optional[Dict]
    report_path: Optional[str]
    current_step: str
    errors: List[str]


class AgentState(BaseAgentState):
    """
    Состояние агента LangGraph (простой агент — simple_agent).
    
    Наследует все поля из BaseAgentState без добавления новых.
    """
    pass


# ==================== РАСШИРЕННОЕ СОСТОЯНИЕ (Deep Agent) ====================

@dataclass
class InvestigatedPath:
    """
    Запись об исследованном пути в образе диска.
    
    Используется в InvestigationStore как каноническая модель данных.
    Сериализуется в dict через to_dict() при синхронизации
    store → ForensicAgentState.
    
    Attributes:
        path: Путь в образе (напр. /etc/cron.d)
        description: Что было найдено / описание содержимого
        timestamp: Когда исследовали
        suspicious: Были ли найдены подозрительные элементы
        findings_refs: Ссылки на id связанных находок
    """
    path: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    suspicious: bool = False
    findings_refs: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'path': self.path,
            'description': self.description,
            'timestamp': self.timestamp,
            'suspicious': self.suspicious,
            'findings_refs': self.findings_refs,
        }


@dataclass
class SuspiciousFinding:
    """
    Запись о подозрительной находке.
    
    Используется в InvestigationStore как каноническая модель данных.
    Сериализуется в dict через to_dict() при синхронизации
    store → ForensicAgentState.
    
    Attributes:
        id: Уникальный идентификатор находки
        category: Категория (file, command, service, network, user, config, malware, persistence)
        severity: Уровень (critical, high, medium, low, info)
        title: Краткое описание
        details: Подробности
        evidence: Доказательства (команды, файлы, логи)
        related_paths: Связанные пути в образе
        related_findings: Связанные находки (id)
        timestamp: Когда обнаружено
    """
    id: str
    category: str
    severity: str
    title: str
    details: str
    evidence: List[str] = field(default_factory=list)
    related_paths: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'category': self.category,
            'severity': self.severity,
            'title': self.title,
            'details': self.details,
            'evidence': self.evidence,
            'related_paths': self.related_paths,
            'related_findings': self.related_findings,
            'timestamp': self.timestamp,
        }


class ForensicAgentState(BaseAgentState):
    """
    Расширенное состояние для Deep Forensic Agent (LangGraph).
    
    Наследует BaseAgentState и добавляет:
    - Отслеживание исследованных путей и находок
    - Данные для детального отчёта (report_data)
    - Результаты LLM-анализа по секциям (llm_analyses)
    - Рекомендации из алгоритмического анализа
    - Сообщения Deep Agent'а
    - Счётчик итераций анализа
    
    Attributes:
        recommendations: Рекомендации из алгоритмического анализа
        investigated_paths: Все исследованные пути с описаниями (List[Dict]).
                          Используется аддитивный reducer (operator.add) —
                          новые записи дописываются к существующим между итерациями.
        suspicious_findings: Все подозрительные находки (List[Dict]).
                          Используется аддитивный reducer (operator.add) —
                          новые записи дописываются к существующим между итерациями.
        llm_analyses: Результаты LLM-анализа по секциям отчёта
        report_data: Данные для формирования итогового отчёта
        deep_agent_output: Вывод Deep Agent'а (текст)
        analysis_iteration: Текущая итерация глубокого анализа (0-based)
        max_iterations: Максимальное количество итераций анализа (hard cap)
    """
    recommendations: List[str]
    investigated_paths: Annotated[List[Dict], operator.add]
    suspicious_findings: Annotated[List[Dict], operator.add]
    llm_analyses: Dict[str, Any]
    report_data: Dict[str, Any]
    deep_agent_output: Optional[str]
    analysis_iteration: int
    max_iterations: int
    fs_extract_depth: int


# ==================== СИНХРОНИЗАЦИЯ STORE → STATE ====================

def sync_store_to_state(store: 'InvestigationStore') -> Dict[str, Any]:
    """
    Извлечь НОВЫЕ данные из InvestigationStore для записи в ForensicAgentState.
    
    Это единственная точка синхронизации бокового канала (InvestigationStore)
    с основным состоянием LangGraph-графа. Вызывается в deep_analysis_node
    после завершения работы Deep Agent'а.
    
    Возвращает только элементы, добавленные с момента предыдущего вызова
    (дельту). Это критично для корректной работы с operator.add reducer —
    если возвращать все элементы целиком, при повторных итерациях
    данные будут дублироваться.
    
    Args:
        store: Глобальное хранилище расследования (InvestigationStore)
    
    Returns:
        Dict с ключами 'investigated_paths' и 'suspicious_findings',
        содержащий только новые (несинхронизированные) записи.
        Готов для merge в ForensicAgentState через operator.add.
    """
    return store.get_new_since_last_sync()
