"""
Analysis Tools - Инструменты для анализа криминалистических данных.

Этот модуль содержит LangChain tools для:
- Извлечения сущностей (IP, домены, хеши) из текста
- Парсинга системных файлов (passwd, services)
- Генерации IOC (Indicators of Compromise)
- Анализа собранных артефактов

Эти tools используются для обработки и анализа данных,
собранных с помощью artifact_tools.
"""

import json
import re
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from langchain_core.tools import tool

from src.utils.logger import get_logger
from src.utils.filesystem import FileSystemUtils

logger = get_logger("AnalysisTools")
fs_utils = FileSystemUtils()


# Регулярные выражения для извлечения сущностей
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')


@tool
def extract_entities_from_text(text: str) -> str:
    """
    Извлечь сущности (IP-адреса, домены, хеши, email, URL) из текста.
    
    Анализирует текст и находит:
    - IPv4 адреса (например, 192.168.1.1)
    - Доменные имена (например, example.com)
    - MD5 хеши (32 символа)
    - SHA1 хеши (40 символов)
    - SHA256 хеши (64 символа)
    - Email адреса
    - URL ссылки
    
    Используйте для:
    - Извлечения IOC из логов и конфигурационных файлов
    - Поиска сетевых индикаторов
    - Выявления подозрительных хешей
    
    Args:
        text: Текст для анализа.
             Может быть содержимым файла, лога или любой строкой.
    
    Returns:
        JSON строка с найденными сущностями:
        - ips: Список уникальных IP-адресов
        - domains: Список уникальных доменов
        - hashes: Словарь {md5: [], sha1: [], sha256: []}
        - emails: Список email адресов
        - urls: Список URL
        - total_entities: Общее количество найденных сущностей
        
    Example:
        >>> extract_entities_from_text("Connection from 192.168.1.100 to evil.com")
        '{"ips": ["192.168.1.100"], "domains": ["evil.com"], "total_entities": 2}'
    """
    result = {
        "ips": [],
        "domains": [],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": []
        },
        "emails": [],
        "urls": [],
        "total_entities": 0
    }
    
    # Извлекаем IP-адреса
    ips = set(IP_PATTERN.findall(text))
    # Фильтруем невалидные IP
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)
    result["ips"] = sorted(valid_ips)
    
    # Извлекаем домены
    domains = set(DOMAIN_PATTERN.findall(text))
    # Фильтруем известные файловые расширения и localhost
    filtered_domains = [
        d for d in domains 
        if not d.endswith(('.log', '.txt', '.conf', '.cfg', '.pid', '.sock'))
        and d not in ('localhost', 'localdomain')
    ]
    result["domains"] = sorted(filtered_domains)
    
    # Извлекаем хеши
    result["hashes"]["md5"] = sorted(set(MD5_PATTERN.findall(text)))
    result["hashes"]["sha1"] = sorted(set(SHA1_PATTERN.findall(text)))
    result["hashes"]["sha256"] = sorted(set(SHA256_PATTERN.findall(text)))
    
    # Извлекаем email
    result["emails"] = sorted(set(EMAIL_PATTERN.findall(text)))
    
    # Извлекаем URL
    result["urls"] = sorted(set(URL_PATTERN.findall(text)))
    
    # Подсчитываем общее количество
    result["total_entities"] = (
        len(result["ips"]) + 
        len(result["domains"]) + 
        len(result["hashes"]["md5"]) +
        len(result["hashes"]["sha1"]) +
        len(result["hashes"]["sha256"]) +
        len(result["emails"]) +
        len(result["urls"])
    )
    
    logger.info(f"extract_entities_from_text: found {result['total_entities']} entities")
    return json.dumps(result, ensure_ascii=False)


@tool
def parse_passwd_file(passwd_content: str) -> str:
    """
    Распарсить содержимое файла /etc/passwd.
    
    Извлекает информацию о каждом пользователе:
    - username: имя пользователя
    - uid: идентификатор пользователя
    - gid: идентификатор группы
    - info: комментарий/описание
    - home: домашняя директория
    - shell: командная оболочка
    
    Также определяет:
    - Пользователей с UID 0 (root привилегии)
    - Пользователей с интерактивным shell
    - Системных пользователей (UID < 1000)
    
    Используйте для:
    - Анализа списка пользователей
    - Выявления подозрительных учётных записей
    - Обнаружения пользователей с root правами
    
    Args:
        passwd_content: Содержимое файла /etc/passwd как строка.
    
    Returns:
        JSON строка с распарсенными данными:
        - users: Список пользователей с детальной информацией
        - root_users: Пользователи с UID 0
        - interactive_users: Пользователи с интерактивным shell
        - system_users_count: Количество системных пользователей
        - regular_users_count: Количество обычных пользователей
        
    Example:
        >>> parse_passwd_file("root:x:0:0:root:/root:/bin/bash\\nuser1:x:1000:1000::/home/user1:/bin/bash")
        '{"users": [{"username": "root", "uid": 0, ...}], "root_users": ["root"], ...}'
    """
    users = []
    root_users = []
    interactive_users = []
    system_count = 0
    regular_count = 0
    
    interactive_shells = ['/bin/bash', '/bin/sh', '/bin/zsh', '/usr/bin/bash', '/usr/bin/zsh']
    
    for line in passwd_content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        parts = line.split(':')
        if len(parts) >= 7:
            user = {
                "username": parts[0],
                "uid": int(parts[2]) if parts[2].isdigit() else parts[2],
                "gid": int(parts[3]) if parts[3].isdigit() else parts[3],
                "info": parts[4],
                "home": parts[5],
                "shell": parts[6]
            }
            users.append(user)
            
            # Проверяем UID 0
            if user["uid"] == 0:
                root_users.append(user["username"])
            
            # Проверяем интерактивный shell
            if user["shell"] in interactive_shells:
                interactive_users.append(user["username"])
            
            # Подсчитываем системных/обычных пользователей
            if isinstance(user["uid"], int):
                if user["uid"] < 1000:
                    system_count += 1
                else:
                    regular_count += 1
    
    result = {
        "users": users,
        "total_users": len(users),
        "root_users": root_users,
        "interactive_users": interactive_users,
        "system_users_count": system_count,
        "regular_users_count": regular_count
    }
    
    logger.info(f"parse_passwd_file: found {len(users)} users, {len(root_users)} with UID 0")
    return json.dumps(result, ensure_ascii=False)


@tool
def parse_services_list(services_content: str) -> str:
    """
    Распарсить список системных сервисов.
    
    Анализирует вывод collect_services_info и извлекает:
    - Список имён сервисов
    - Типы сервисов (systemd unit, init script)
    - Потенциально подозрительные сервисы
    
    Используйте для:
    - Анализа автозагрузки
    - Выявления подозрительных сервисов
    - Обнаружения persistence механизмов
    
    Args:
        services_content: Содержимое файла со списком сервисов.
    
    Returns:
        JSON строка с распарсенными данными:
        - services: Список имён сервисов
        - systemd_units: Сервисы systemd
        - init_scripts: Init скрипты
        - suspicious: Потенциально подозрительные сервисы
        - total: Общее количество сервисов
        
    Example:
        >>> parse_services_list("=== /etc/systemd/system ===\\nssh.service\\nmalware.service")
        '{"services": ["ssh.service", "malware.service"], "total": 2}'
    """
    services = []
    systemd_units = []
    init_scripts = []
    suspicious = []
    
    current_section = None
    
    # Паттерны подозрительных имён
    suspicious_patterns = [
        r'.*backdoor.*', r'.*malware.*', r'.*hack.*', r'.*shell.*',
        r'.*reverse.*', r'.*miner.*', r'.*crypto.*', r'.*xmr.*',
        r'^\..*',  # Скрытые файлы
    ]
    
    for line in services_content.split('\n'):
        line = line.strip()
        
        if line.startswith('==='):
            if 'systemd' in line.lower():
                current_section = 'systemd'
            elif 'init.d' in line.lower():
                current_section = 'initd'
            continue
        
        if not line:
            continue
            
        # Извлекаем имя сервиса
        service_name = line.split('/')[-1] if '/' in line else line
        
        if service_name:
            services.append(service_name)
            
            if current_section == 'systemd':
                systemd_units.append(service_name)
            elif current_section == 'initd':
                init_scripts.append(service_name)
            
            # Проверяем на подозрительность
            for pattern in suspicious_patterns:
                if re.match(pattern, service_name.lower()):
                    suspicious.append({
                        "name": service_name,
                        "reason": f"Matches suspicious pattern: {pattern}"
                    })
                    break
    
    result = {
        "services": services,
        "systemd_units": systemd_units,
        "init_scripts": init_scripts,
        "suspicious": suspicious,
        "total": len(services)
    }
    
    logger.info(f"parse_services_list: found {len(services)} services, {len(suspicious)} suspicious")
    return json.dumps(result, ensure_ascii=False)


@tool
def generate_file_ioc(file_path: str) -> str:
    """
    Сгенерировать IOC (Indicators of Compromise) для локального файла.
    
    Вычисляет:
    - MD5, SHA1, SHA256 хеши файла
    - Размер файла
    - Временные метки (создание, изменение, доступ)
    - Имя файла
    
    Используйте для:
    - Создания IOC для подозрительных файлов
    - Документирования артефактов
    - Подготовки данных для threat intelligence
    
    ВАЖНО: Работает с файлами в локальной файловой системе,
    а не с файлами в образе диска. Сначала извлеките файл
    с помощью extract_file_from_image().
    
    Args:
        file_path: Путь к файлу в локальной файловой системе.
                  Пример: "extracted/etc_passwd" или "/tmp/suspicious_file"
    
    Returns:
        JSON строка с IOC:
        - success: True если IOC сгенерирован
        - file_path: Путь к файлу
        - name: Имя файла
        - size: Размер в байтах
        - hashes: {md5, sha1, sha256}
        - timestamps: {created, modified, accessed}
        
    Example:
        >>> generate_file_ioc("extracted/home_user_.bash_history")
        '{"success": true, "name": "home_user_.bash_history", "hashes": {"md5": "abc...", "sha256": "def..."}, ...}'
    """
    path = Path(file_path)
    
    if not path.exists():
        return json.dumps({
            "success": False,
            "error": f"File not found: {file_path}",
            "file_path": file_path
        }, ensure_ascii=False)
    
    if not path.is_file():
        return json.dumps({
            "success": False,
            "error": f"Not a file: {file_path}",
            "file_path": file_path
        }, ensure_ascii=False)
    
    try:
        # Получаем метаданные
        metadata = fs_utils.get_file_metadata(path)
        
        # Вычисляем хеши
        hashes = fs_utils.calculate_hashes(path)
        
        result = {
            "success": True,
            "file_path": str(path),
            "name": path.name,
            "size": metadata['size'],
            "hashes": hashes,
            "timestamps": {
                "created": metadata['created'],
                "modified": metadata['modified'],
                "accessed": metadata['accessed']
            },
            "ioc_generated_at": datetime.now().isoformat()
        }
        
        logger.info(f"generate_file_ioc: {path.name} - MD5: {hashes['md5'][:16]}...")
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error generating IOC for {file_path}: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "file_path": file_path
        }, ensure_ascii=False)


@tool
def analyze_triage_data(triage_data_json: str) -> str:
    """
    Проанализировать собранные данные триажа и сгенерировать статистику, некоторые находки и аномалии, выявленные алгоритмическим путем.
    
    Принимает JSON с данными, собранными artifact_tools, и генерирует:
    - Общую статистику (количество пользователей, сервисов, команд, IOC)
    - Сводку по артефактам
    - Выявленные аномалии
    
    ФОРМАТ ВХОДНЫХ ДАННЫХ (соответствует выводу artifact_tools):
    
    Ключи верхнего уровня (результаты соответствующих tools):
    - passwd: строка с содержимым /etc/passwd (из collect_users_info)
    - shadow: строка с содержимым /etc/shadow (из collect_users_info)  
    - services: строка ИЛИ dict с сервисами (из collect_services_info)
    - history: dict {username: [список команд]} (из collect_command_history)
    - users: dict {username: [список команд]} - альтернативный ключ для истории
    - iocs: список IOC объектов (из generate_file_ioc)
    - cron: строка с cron задачами (из collect_cron_info)
    - packages: строка с пакетами (из collect_packages_info)
    - docker: dict с Docker информацией (из collect_docker_info)
    - ssh: dict с SSH артефактами (из collect_ssh_artifacts)
    
    Используйте для:
    - Получения общей картины системы
    - Быстрой оценки объёма данных
    - Выявления областей для детального анализа
    
    Args:
        triage_data_json: JSON строка с данными триажа.
                         Пример: {"passwd": "root:x:0:0:...", "services": {...}, "history": {...}}
    
    Returns:
        JSON строка с анализом:
        - success: True если анализ выполнен
        - summary: Общая статистика (total_users, total_commands, total_files, total_services)
        - statistics: Детальная статистика с parsed данными (users list, services count и т.д.)
        - findings: Список находок
        - anomalies: Выявленные аномалии
        - anomalies_count: Количество аномалий
        - recommendations: Рекомендации для дальнейшего анализа
        - analysis_timestamp: Время анализа
        
    Example:
        >>> analyze_triage_data('{"passwd": "root:x:0:0:root:/root:/bin/bash", "services": {"systemd": [...]}}')
        '{"success": true, "summary": {"total_users": 1, "total_services": 45}, "statistics": {...}, ...}'
    """
    try:
        data = json.loads(triage_data_json)
    except json.JSONDecodeError as e:
        return json.dumps({
            "success": False,
            "error": f"Invalid JSON: {str(e)}"
        }, ensure_ascii=False)
    
    # Структура как в оригинальной analyze_artifacts()
    analysis = {
        "summary": {},
        "findings": [],
        "statistics": {}
    }
    
    anomalies = []
    recommendations = []
    
    # ========== АНАЛИЗ ПОЛЬЗОВАТЕЛЕЙ (как в оригинале) ==========
    # Поддерживаем разные форматы ключей
    passwd_content = None
    if 'passwd' in data and data['passwd']:
        passwd_content = data['passwd']
    elif 'users' in data and isinstance(data['users'], dict) and 'passwd' in data['users']:
        passwd_content = data['users']['passwd']
    
    if passwd_content:
        # Парсим passwd как в оригинальной _parse_passwd()
        users = []
        for line in passwd_content.split('\n'):
            if line and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 7:
                    user_info = {
                        'username': parts[0],
                        'uid': parts[2],
                        'gid': parts[3],
                        'home': parts[5],
                        'shell': parts[6]
                    }
                    users.append(user_info)
                    
                    # Проверяем аномалии: UID 0 не у root
                    if parts[2] == '0' and parts[0] != 'root':
                        anomalies.append({
                            "type": "suspicious_user",
                            "severity": "high",
                            "description": f"User '{parts[0]}' has UID 0 (root privileges)",
                            "user": parts[0]
                        })
        
        analysis['statistics']['total_users'] = len(users)
        analysis['statistics']['users'] = users
    
    # ========== АНАЛИЗ ИСТОРИИ КОМАНД (как в оригинале) ==========
    # Поддерживаем разные форматы: history или users (из collect_command_history)
    history_data = None
    if 'history' in data and data['history']:
        history_data = data['history']
    elif 'users' in data and isinstance(data['users'], dict):
        # collect_command_history возвращает {"users": {username: [commands]}}
        # Но это конфликтует с users из collect_users_info
        # Проверяем, есть ли списки команд внутри
        users_val = data['users']
        if users_val and isinstance(users_val, dict):
            # Если значения - списки строк, это история команд
            first_val = next(iter(users_val.values()), None) if users_val else None
            if isinstance(first_val, list):
                history_data = users_val
    
    if history_data and isinstance(history_data, dict):
        total_commands = 0
        users_with_history = 0
        
        # Подозрительные паттерны команд
        suspicious_patterns = [
            'wget', 'curl', 'nc ', 'netcat', 'ncat',
            'chmod 777', 'chmod +x', 
            '/dev/tcp', '/dev/udp',
            'base64', 'eval', 'exec',
            'rm -rf', 'history -c', 'history -w'
        ]
        
        for user, commands in history_data.items():
            if commands:
                # Нормализуем: может быть строка или список
                if isinstance(commands, str):
                    cmd_list = [c.strip() for c in commands.split('\n') if c.strip()]
                else:
                    cmd_list = commands
                
                total_commands += len(cmd_list)
                users_with_history += 1
                
                # Проверяем подозрительные команды
                for cmd in cmd_list:
                    cmd_lower = str(cmd).lower()
                    for pattern in suspicious_patterns:
                        if pattern in cmd_lower:
                            anomalies.append({
                                "type": "suspicious_command",
                                "severity": "medium",
                                "user": user,
                                "command": str(cmd)[:200],
                                "pattern": pattern
                            })
                            break  # Только одна аномалия на команду
        
        analysis['statistics']['total_commands'] = total_commands
        analysis['statistics']['users_with_history'] = users_with_history
    
    # ========== АНАЛИЗ IOCs (как в оригинале) ==========
    if 'iocs' in data and data['iocs']:
        iocs = data['iocs']
        if isinstance(iocs, list):
            analysis['statistics']['total_files'] = len(iocs)
            analysis['statistics']['total_iocs'] = len(iocs)
    
    # ========== ИЗВЛЕЧЁННЫЕ ФАЙЛЫ (проверка имён на подозрительность) ==========
    extracted = data.get('extracted_files')
    if extracted and isinstance(extracted, dict):
        files_list = extracted.get('extracted_files', [])
        if isinstance(files_list, list):
            suspicious_file_patterns = [
                'shell', 'backdoor', 'reverse', 'malware', 'hack',
                'exploit', 'payload', 'miner', 'xmrig', 'c2',
            ]
            for f in files_list:
                source = f.get('source', '') if isinstance(f, dict) else str(f)
                fname = source.split('/')[-1].lower()
                for pat in suspicious_file_patterns:
                    if pat in fname:
                        anomalies.append({
                            "type": "suspicious_file",
                            "severity": "high",
                            "file": source,
                            "pattern": pat,
                            "description": f"Подозрительное имя файла: {source}"
                        })
                        break

    # ========== АНАЛИЗ СЕРВИСОВ (как в оригинале) ==========
    services_data = data.get('services')
    if services_data:
        if isinstance(services_data, str):
            # Парсим как в оригинальной _parse_services()
            services = []
            for line in services_data.split('\n'):
                if line and not line.startswith('===') and line.strip():
                    services.append(line.strip())
            analysis['statistics']['total_services'] = len(services)
        elif isinstance(services_data, dict):
            # Данные уже структурированы (из collect_services_info)
            total = 0
            for key in ['systemd', 'initd', 'rcd', 'xinetd']:
                if key in services_data:
                    val = services_data[key]
                    if isinstance(val, list):
                        total += len(val)
                        # Проверяем подозрительные сервисы
                        suspicious_service_patterns = [
                            'backdoor', 'malware', 'hack', 'shell',
                            'reverse', 'miner', 'crypto', 'xmr'
                        ]
                        for service in val:
                            service_name = service.get('name', str(service)) if isinstance(service, dict) else str(service)
                            for pattern in suspicious_service_patterns:
                                if pattern in service_name.lower():
                                    anomalies.append({
                                        "type": "suspicious_service",
                                        "severity": "high",
                                        "service": service_name,
                                        "pattern": pattern,
                                        "location": key
                                    })
                                    break
            analysis['statistics']['total_services'] = total
    
    # ========== DOCKER (расширение для agent) ==========
    if 'docker' in data:
        docker_data = data['docker']
        if docker_data and isinstance(docker_data, dict):
            if docker_data.get('docker_installed'):
                analysis['statistics']['has_docker'] = True
                recommendations.append("Docker установлен — проверить контейнеры и образы на вредоносное ПО")
                if docker_data.get('containers'):
                    analysis['statistics']['docker_containers'] = len(docker_data['containers'])
    
    # ========== SSH (расширение для agent) ==========
    if 'ssh' in data:
        ssh_data = data['ssh']
        if ssh_data and isinstance(ssh_data, dict):
            if ssh_data.get('authorized_keys'):
                analysis['statistics']['has_ssh'] = True
                analysis['statistics']['ssh_users_with_keys'] = len(ssh_data['authorized_keys'])
                ak_users = ", ".join(ssh_data['authorized_keys'].keys())
                recommendations.append(
                    f"Проверить authorized_keys на неавторизованные ключи у пользователей: {ak_users}"
                )
            if ssh_data.get('ssh_keys'):
                analysis['statistics']['ssh_keys_count'] = len(ssh_data['ssh_keys'])
    
    # ========== ГЕНЕРАЦИЯ SUMMARY (как в оригинальной _generate_summary) ==========
    analysis['summary'] = {
        'total_users': analysis['statistics'].get('total_users', 0),
        'total_commands': analysis['statistics'].get('total_commands', 0),
        'total_files': analysis['statistics'].get('total_files', 0),
        'total_services': analysis['statistics'].get('total_services', 0),
        'analysis_date': datetime.now().isoformat()
    }
    
    # ========== РЕКОМЕНДАЦИИ (конкретные, на основе найденных аномалий) ==========
    if anomalies:
        # Группируем аномалии по пользователям и типам для конкретных рекомендаций
        users_with_suspicious_cmds: Dict[str, set] = {}
        suspicious_users: list = []
        suspicious_services: list = []
        for a in anomalies:
            atype = a.get('type', '')
            if atype == 'suspicious_command':
                user = a.get('user', '?')
                pattern = a.get('pattern', '?')
                users_with_suspicious_cmds.setdefault(user, set()).add(pattern)
            elif atype == 'suspicious_user':
                suspicious_users.append(a.get('user', '?'))
            elif atype == 'suspicious_service':
                suspicious_services.append(a.get('service', '?'))

        for user, patterns in users_with_suspicious_cmds.items():
            p_str = ", ".join(sorted(patterns))
            recommendations.insert(0,
                f"Исследовать активность пользователя '{user}': "
                f"обнаружены подозрительные паттерны ({p_str}). "
                f"Проверить загруженные/созданные файлы в home-директории и /tmp."
            )
        if suspicious_users:
            recommendations.insert(0,
                f"КРИТИЧНО: обнаружены пользователи с UID 0 ({', '.join(suspicious_users)}) — "
                "проверить /etc/passwd, /etc/shadow, историю команд этих пользователей."
            )
        if suspicious_services:
            recommendations.insert(0,
                f"Проверить подозрительные сервисы: {', '.join(suspicious_services)}. "
                "Изучить unit-файлы, бинарники и конфигурации."
            )

    if analysis['statistics'].get('total_commands', 0) > 0:
        recommendations.append(
            "Провести детальный анализ истории команд всех пользователей — "
            "проверить файлы .bash_history, .zsh_history в home-директориях."
        )

    if analysis['statistics'].get('total_users', 0) > 50:
        recommendations.append(
            f"Обнаружено много пользователей ({analysis['statistics']['total_users']}) — "
            "проверить на наличие неавторизованных учётных записей."
        )
    
    result = {
        "success": True,
        "summary": analysis['summary'],
        "statistics": analysis['statistics'],
        "findings": analysis['findings'],
        "anomalies": anomalies,
        "anomalies_count": len(anomalies),
        "recommendations": recommendations,
        "analysis_timestamp": datetime.now().isoformat()
    }
    
    logger.info(f"analyze_triage_data: users={analysis['summary'].get('total_users', 0)}, commands={analysis['summary'].get('total_commands', 0)}, anomalies={len(anomalies)}")
    return json.dumps(result, ensure_ascii=False)


@tool
def generate_html_report(
    analysis_json: str,
    triage_data_json: str = "{}",
    output_path: str = "extracted/report.html"
) -> str:
    """
    Сгенерировать HTML отчёт на основе результатов анализа.
    
    Создаёт визуальный HTML отчёт, содержащий:
    - Сводку (Summary) с ключевыми метриками
    - Выявленные аномалии с цветовой кодировкой по severity
    - Таблицу пользователей системы
    - Indicators of Compromise (IOCs)
    - Историю команд пользователей
    - Информацию о Docker и SSH
    - Рекомендации по дальнейшему анализу
    
    Используйте для:
    - Создания финального отчёта расследования
    - Визуализации результатов анализа
    - Документирования находок
    
    Args:
        analysis_json: JSON строка с результатом analyze_triage_data().
                      Содержит summary, statistics, anomalies, recommendations.
        triage_data_json: JSON строка с исходными данными триажа (опционально).
                         Используется для отображения деталей (история команд, IOCs).
        output_path: Путь для сохранения HTML отчёта.
                    По умолчанию: "extracted/report.html"
    
    Returns:
        JSON строка с результатом:
        - success: True если отчёт создан
        - report_path: Путь к созданному отчёту
        - file_size: Размер файла в байтах
        
    Example:
        >>> analysis = analyze_triage_data(triage_data)
        >>> generate_html_report(analysis, triage_data, "report.html")
        '{"success": true, "report_path": "extracted/report.html", "file_size": 15234}'
    """
    try:
        analysis = json.loads(analysis_json)
    except json.JSONDecodeError as e:
        return json.dumps({
            "success": False,
            "error": f"Invalid analysis JSON: {str(e)}"
        }, ensure_ascii=False)
    
    try:
        triage_data = json.loads(triage_data_json) if triage_data_json else {}
    except json.JSONDecodeError:
        triage_data = {}
    
    summary = analysis.get('summary', {})
    stats = analysis.get('statistics', {})
    anomalies = analysis.get('anomalies', [])
    recommendations = analysis.get('recommendations', [])
    
    # ========== HTML HEADER И STYLES ==========
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Triage Report</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #1a1a2e;
            color: #eaeaea;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background-color: #16213e;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        h1 {{
            color: #00d9ff;
            border-bottom: 3px solid #00d9ff;
            padding-bottom: 15px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #ff6b6b;
            margin-top: 40px;
            margin-bottom: 20px;
            border-left: 4px solid #ff6b6b;
            padding-left: 15px;
        }}
        h3 {{
            color: #feca57;
            margin-top: 20px;
        }}
        .meta {{
            color: #888;
            margin-bottom: 30px;
        }}
        
        /* Summary Cards */
        .summary {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 25px 0;
        }}
        .stat {{
            flex: 1;
            min-width: 150px;
            padding: 20px;
            background: linear-gradient(135deg, #1f4068 0%, #162447 100%);
            border-radius: 10px;
            text-align: center;
            border: 1px solid #2d4a6f;
        }}
        .stat-label {{
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: #00d9ff;
        }}
        .stat-value.warning {{
            color: #feca57;
        }}
        .stat-value.danger {{
            color: #ff6b6b;
        }}
        .stat-value.success {{
            color: #1dd1a1;
        }}
        
        /* Anomalies Section */
        .anomalies {{
            margin: 25px 0;
        }}
        .anomaly {{
            padding: 15px 20px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid;
        }}
        .anomaly.high {{
            background-color: rgba(255, 107, 107, 0.15);
            border-color: #ff6b6b;
        }}
        .anomaly.medium {{
            background-color: rgba(254, 202, 87, 0.15);
            border-color: #feca57;
        }}
        .anomaly.low {{
            background-color: rgba(29, 209, 161, 0.15);
            border-color: #1dd1a1;
        }}
        .anomaly-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .anomaly-type {{
            font-weight: bold;
            color: #fff;
        }}
        .anomaly-severity {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            text-transform: uppercase;
            font-weight: bold;
        }}
        .anomaly-severity.high {{
            background-color: #ff6b6b;
            color: #1a1a2e;
        }}
        .anomaly-severity.medium {{
            background-color: #feca57;
            color: #1a1a2e;
        }}
        .anomaly-severity.low {{
            background-color: #1dd1a1;
            color: #1a1a2e;
        }}
        .anomaly-details {{
            color: #ccc;
            font-size: 14px;
        }}
        .anomaly-details code {{
            background-color: rgba(0,0,0,0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
        }}
        
        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: #1f4068;
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #2d4a6f;
        }}
        th {{
            background-color: #0f3460;
            color: #00d9ff;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
        }}
        tr:hover {{
            background-color: rgba(0, 217, 255, 0.05);
        }}
        td code {{
            background-color: rgba(0,0,0,0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            font-size: 12px;
        }}
        
        /* Code Block */
        .code-block {{
            background-color: #0f0f23;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            line-height: 1.5;
            border: 1px solid #2d4a6f;
            color: #00ff00;
        }}
        
        /* Recommendations */
        .recommendations {{
            margin: 25px 0;
        }}
        .recommendation {{
            padding: 12px 20px;
            margin: 8px 0;
            background-color: rgba(0, 217, 255, 0.1);
            border-left: 4px solid #00d9ff;
            border-radius: 0 8px 8px 0;
        }}
        .recommendation.critical {{
            background-color: rgba(255, 107, 107, 0.15);
            border-color: #ff6b6b;
        }}
        
        /* Info boxes */
        .info-box {{
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 8px;
            background-color: rgba(29, 209, 161, 0.1);
            border: 1px solid #1dd1a1;
        }}
        .info-box.docker {{
            background-color: rgba(0, 150, 255, 0.1);
            border-color: #0096ff;
        }}
        .info-box.ssh {{
            background-color: rgba(255, 159, 67, 0.1);
            border-color: #ff9f43;
        }}
        
        /* Footer */
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #2d4a6f;
            text-align: center;
            color: #666;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Forensic Triage Report</h1>
        <p class="meta">
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
            <strong>Analysis Date:</strong> {summary.get('analysis_date', 'N/A')}
        </p>
"""
    
    # ========== SUMMARY SECTION ==========
    anomaly_count = len(anomalies)
    anomaly_class = "danger" if anomaly_count > 5 else ("warning" if anomaly_count > 0 else "success")
    
    html += f"""
        <div class="summary">
            <div class="stat">
                <div class="stat-label">Total Users</div>
                <div class="stat-value">{summary.get('total_users', 0)}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Total Commands</div>
                <div class="stat-value">{summary.get('total_commands', 0)}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Total Files/IOCs</div>
                <div class="stat-value">{summary.get('total_files', 0)}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Total Services</div>
                <div class="stat-value">{summary.get('total_services', 0)}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Anomalies Found</div>
                <div class="stat-value {anomaly_class}">{anomaly_count}</div>
            </div>
        </div>
"""
    
    # ========== ANOMALIES SECTION ==========
    if anomalies:
        html += """
        <h2>⚠️ Detected Anomalies</h2>
        <div class="anomalies">
"""
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'medium')
            atype = anomaly.get('type', 'unknown')
            
            html += f"""
            <div class="anomaly {severity}">
                <div class="anomaly-header">
                    <span class="anomaly-type">{atype.replace('_', ' ').title()}</span>
                    <span class="anomaly-severity {severity}">{severity.upper()}</span>
                </div>
                <div class="anomaly-details">
"""
            if anomaly.get('description'):
                html += f"<p>{anomaly['description']}</p>"
            if anomaly.get('user'):
                html += f"<p><strong>User:</strong> <code>{anomaly['user']}</code></p>"
            if anomaly.get('command'):
                html += f"<p><strong>Command:</strong> <code>{anomaly['command']}</code></p>"
            if anomaly.get('pattern'):
                html += f"<p><strong>Matched Pattern:</strong> <code>{anomaly['pattern']}</code></p>"
            if anomaly.get('service'):
                html += f"<p><strong>Service:</strong> <code>{anomaly['service']}</code></p>"
            if anomaly.get('location'):
                html += f"<p><strong>Location:</strong> {anomaly['location']}</p>"
            
            html += """
                </div>
            </div>
"""
        html += "        </div>"
    
    # ========== RECOMMENDATIONS SECTION ==========
    if recommendations:
        html += """
        <h2>📋 Recommendations</h2>
        <div class="recommendations">
"""
        for rec in recommendations:
            css_class = "critical" if "CRITICAL" in rec else ""
            html += f'            <div class="recommendation {css_class}">{rec}</div>\n'
        html += "        </div>"
    
    # ========== USERS SECTION ==========
    if stats.get('users'):
        html += """
        <h2>👤 System Users</h2>
        <table>
            <tr>
                <th>Username</th>
                <th>UID</th>
                <th>GID</th>
                <th>Home Directory</th>
                <th>Shell</th>
            </tr>
"""
        for user in stats['users']:
            # Highlight suspicious users
            row_style = ""
            if user.get('uid') == '0' and user.get('username') != 'root':
                row_style = ' style="background-color: rgba(255, 107, 107, 0.2);"'
            
            html += f"""            <tr{row_style}>
                <td><code>{user.get('username', 'N/A')}</code></td>
                <td>{user.get('uid', 'N/A')}</td>
                <td>{user.get('gid', 'N/A')}</td>
                <td><code>{user.get('home', 'N/A')}</code></td>
                <td><code>{user.get('shell', 'N/A')}</code></td>
            </tr>
"""
        html += "        </table>"
    
    # ========== IOCs SECTION ==========
    iocs = triage_data.get('iocs', [])
    if iocs:
        html += f"""
        <h2>🎯 Indicators of Compromise (IOCs)</h2>
        <p>Total IOCs: <strong>{len(iocs)}</strong></p>
        <table>
            <tr>
                <th>Name</th>
                <th>Size</th>
                <th>MD5</th>
                <th>SHA256</th>
                <th>Modified</th>
            </tr>
"""
        for ioc in iocs[:50]:  # Limit display
            md5 = ioc.get('md5', 'N/A')
            sha256 = ioc.get('sha256', 'N/A')
            html += f"""            <tr>
                <td>{ioc.get('name', 'N/A')}</td>
                <td>{ioc.get('size', 0)}</td>
                <td><code>{md5[:16] if md5 != 'N/A' else 'N/A'}...</code></td>
                <td><code>{sha256[:32] if sha256 != 'N/A' else 'N/A'}...</code></td>
                <td>{ioc.get('modified', 'N/A')}</td>
            </tr>
"""
        if len(iocs) > 50:
            html += f'            <tr><td colspan="5" style="text-align: center; color: #888;">... and {len(iocs) - 50} more IOCs</td></tr>\n'
        html += "        </table>"
    
    # ========== DOCKER SECTION ==========
    if stats.get('has_docker'):
        containers_count = stats.get('docker_containers', 0)
        html += f"""
        <h2>🐳 Docker Information</h2>
        <div class="info-box docker">
            <p><strong>Docker Installed:</strong> Yes</p>
            <p><strong>Containers Found:</strong> {containers_count}</p>
        </div>
"""
    
    # ========== SSH SECTION ==========
    if stats.get('has_ssh'):
        ssh_users = stats.get('ssh_users_with_keys', 0)
        ssh_keys = stats.get('ssh_keys_count', 0)
        html += f"""
        <h2>🔐 SSH Artifacts</h2>
        <div class="info-box ssh">
            <p><strong>Users with authorized_keys:</strong> {ssh_users}</p>
            <p><strong>SSH key files found:</strong> {ssh_keys}</p>
        </div>
"""
    
    # ========== COMMAND HISTORY SECTION ==========
    history_data = triage_data.get('history', {})
    if not history_data:
        # Try alternative key structure
        users_data = triage_data.get('users', {})
        if isinstance(users_data, dict):
            first_val = next(iter(users_data.values()), None) if users_data else None
            if isinstance(first_val, list):
                history_data = users_data
    
    if history_data:
        html += """
        <h2>📜 Command History</h2>
"""
        for user, commands in history_data.items():
            if commands:
                # Normalize commands
                if isinstance(commands, str):
                    cmd_list = [c.strip() for c in commands.split('\n') if c.strip()]
                else:
                    cmd_list = commands
                
                # Limit display
                display_cmds = cmd_list[:30]
                
                html += f"""
        <h3>User: {user}</h3>
        <div class="code-block">"""
                html += "<br>".join([f"$ {cmd}" for cmd in display_cmds])
                if len(cmd_list) > 30:
                    html += f"<br><br><em>... and {len(cmd_list) - 30} more commands</em>"
                html += "</div>"
    
    # ========== STATISTICS SECTION ==========
    html += """
        <h2>📊 Detailed Statistics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
"""
    stat_items = [
        ('Total Users', stats.get('total_users', 0)),
        ('Total Commands', stats.get('total_commands', 0)),
        ('Users with History', stats.get('users_with_history', 0)),
        ('Total Files/IOCs', stats.get('total_files', 0)),
        ('Total Services', stats.get('total_services', 0)),
        ('Docker Installed', 'Yes' if stats.get('has_docker') else 'No'),
        ('Docker Containers', stats.get('docker_containers', 'N/A')),
        ('SSH Users with Keys', stats.get('ssh_users_with_keys', 'N/A')),
        ('SSH Key Files', stats.get('ssh_keys_count', 'N/A')),
    ]
    
    for label, value in stat_items:
        if value not in [0, 'N/A', 'No', None]:
            html += f"""            <tr>
                <td>{label}</td>
                <td><strong>{value}</strong></td>
            </tr>
"""
    html += "        </table>"
    
    # ========== FOOTER ==========
    html += """
        <div class="footer">
            <p>Generated by Forseti Forensic Triage Agent</p>
        </div>
    </div>
</body>
</html>
"""
    
    # ========== SAVE REPORT ==========
    try:
        output_file = Path(output_path)
        fs_utils.ensure_directory(output_file.parent)
        fs_utils.safe_write(output_file, html)
        
        file_size = len(html.encode('utf-8'))
        
        logger.info(f"generate_html_report: saved to {output_path} ({file_size} bytes)")
        return json.dumps({
            "success": True,
            "report_path": str(output_file),
            "file_size": file_size,
            "sections_included": {
                "summary": True,
                "anomalies": len(anomalies) > 0,
                "recommendations": len(recommendations) > 0,
                "users": bool(stats.get('users')),
                "iocs": len(iocs) > 0,
                "docker": stats.get('has_docker', False),
                "ssh": stats.get('has_ssh', False),
                "history": bool(history_data)
            }
        }, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "output_path": output_path
        }, ensure_ascii=False)
