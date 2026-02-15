"""
Artifact Tools - Инструменты для сбора криминалистических артефактов.

Этот модуль содержит LangChain tools для сбора различных типов артефактов:
- Информация об ОС
- Пользователи системы
- История команд
- Системные сервисы
- Cron задачи
- Установленные пакеты
- Docker информация
- SSH артефакты
- Сетевая конфигурация
- Логи авторизации

Все tools используют ImageManager для доступа к образу диска.

УНИВЕРСАЛЬНОСТЬ:
    Каждая функция принимает необязательный параметр paths (или аналогичный),
    позволяющий LLM или агенту передавать собственный список путей для исследования.
    Если параметр не передан — используются стандартные пути (из конфига или захардкоженные).
"""

import json
import os
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from langchain_core.tools import tool

from .image_manager import get_image_manager
from src.utils.logger import get_logger

logger = get_logger("ArtifactTools")

# ==================== TOOL RESULT CACHE ====================
# Кеш предотвращает повторные вызовы одного и того же инструмента
# и переполнение контекста LLM дублирующимися данными.
_tool_result_cache: Dict[str, str] = {}


def clear_tool_cache():
    """Очистить кеш инструментов (вызывать между запусками)."""
    _tool_result_cache.clear()


# ==================== HELPER FUNCTIONS ====================

def _extract_user_from_path(file_path: str) -> str:
    """
    Определить имя пользователя из пути к файлу в домашней директории.
    
    Примеры:
        /root/.bash_history       → root
        /home/admin/.bash_history → admin
        /home/user1/.ssh          → user1
    """
    if file_path.startswith('/root/') or file_path == '/root':
        return 'root'
    parts = file_path.split('/')
    for i, part in enumerate(parts):
        if part == 'home' and i + 1 < len(parts):
            return parts[i + 1]
    return 'unknown'


def _safe_key_from_path(path: str) -> str:
    """Создать безопасный ключ из пути для использования в JSON результате."""
    return Path(path).name.replace('.', '_').replace('-', '_')


# ==================== TOOLS ====================


@tool
def collect_os_info(paths: Optional[List[str]] = None) -> str:
    """
    Собрать информацию об операционной системе из образа диска.
    
    Читает системные файлы для определения:
    - Типа и версии ОС
    - Имени хоста
    - Дополнительной информации о системе
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список путей к системным файлам для чтения.
               Если None, используются пути из configs/triage.yaml или стандартные.
               Пример: ["/etc/os-release", "/etc/issue", "/etc/hostname"]
    
    Returns:
        JSON строка с информацией об ОС:
        - success: True если хотя бы один файл прочитан
        - files: Словарь {путь: содержимое} для каждого прочитанного файла
        - files_found: Количество найденных файлов
        - files_total: Общее количество проверенных путей
        
    Example:
        >>> collect_os_info()
        '{"success": true, "files_found": 2, "files": {"/etc/os-release": "NAME=...", "/etc/hostname": "server1"}}'
        
        >>> collect_os_info(["/etc/os-release", "/etc/hostname", "/etc/debian_version"])
        '{"success": true, "files_found": 3, "files": {...}}'
    """
    _cache_key = f"collect_os_info:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_os_info: cache HIT")
        return json.dumps({"cached": True, "message": "Информация об ОС уже получена. Используйте данные из предыдущего вызова."}, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    # Определяем пути: переданные → из конфига → стандартные
    if paths:
        config_paths = paths
    else:
        config_paths = manager.get_config('artifacts.system') or [
            '/etc/os-release',
            '/etc/issue',
            '/etc/lsb-release',
            '/etc/redhat-release'
        ]
    
    files = {}
    for path in config_paths:
        content = manager.read_file(path)
        if content:
            files[path] = content
    
    logger.info(f"collect_os_info: found {len(files)}/{len(config_paths)} files")
    _r = json.dumps({
        "success": len(files) > 0,
        "files_found": len(files),
        "files_total": len(config_paths),
        "paths_used": config_paths,
        "files": files
    }, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_users_info(paths: Optional[List[str]] = None) -> str:
    """
    Собрать информацию о пользователях системы из образа диска.
    
    Читает ключевые файлы с информацией о пользователях:
    - /etc/passwd: список пользователей, UID, домашние директории, shell
    - /etc/shadow: хеши паролей (для анализа политик безопасности)
    - /etc/group: группы пользователей
    - /etc/sudoers: права sudo
    - /etc/gshadow: групповые пароли
    
    Используйте для:
    - Определения всех пользователей системы
    - Выявления подозрительных пользователей (новые, с UID 0, без пароля)
    - Анализа прав доступа
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список путей к файлам с информацией о пользователях.
               Если None, используются стандартные пути.
               Пример: ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"]
    
    Returns:
        JSON строка с информацией о пользователях:
        - success: True если файлы прочитаны
        - passwd: Содержимое файла passwd (или None)
        - shadow: Содержимое файла shadow (или None)
        - group: Содержимое файла group (или None)
        - sudoers: Содержимое файла sudoers (или None)
        - files: Словарь {путь: содержимое} всех прочитанных файлов
        - users_count: Количество пользователей в passwd
        
    Example:
        >>> collect_users_info()
        '{"success": true, "passwd": "root:x:0:0:...", "users_count": 25, ...}'
        
        >>> collect_users_info(["/etc/passwd", "/etc/shadow", "/etc/gshadow"])
        '{"success": true, "passwd": "root:x:0:0:...", "users_count": 25, "files": {...}}'
    """
    _cache_key = f"collect_users_info:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_users_info: cache HIT")
        return json.dumps({"cached": True, "message": "Информация о пользователях уже получена. Используйте данные из предыдущего вызова."}, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    # Стандартные пути и маппинг на ключи результата
    default_paths = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers']
    
    files_to_read = paths if paths else default_paths
    
    # Читаем все файлы
    files = {}
    for path in files_to_read:
        content = manager.read_file(path)
        if content:
            files[path] = content
    
    # Формируем результат с backward-compatible ключами
    result = {
        "success": False,
        "passwd": None,
        "shadow": None,
        "group": None,
        "sudoers": None,
        "users_count": 0,
        "files": files,
        "paths_used": files_to_read
    }
    
    # Маппинг: basename → ключ результата
    key_mapping = {
        'passwd': 'passwd',
        'shadow': 'shadow',
        'group': 'group',
        'sudoers': 'sudoers',
        'gshadow': 'gshadow',
    }
    
    for path, content in files.items():
        basename = Path(path).name
        result_key = key_mapping.get(basename)
        if result_key:
            result[result_key] = content
    
    # Подсчёт пользователей из passwd
    if result["passwd"]:
        result["users_count"] = len([
            line for line in result["passwd"].split('\n')
            if line and not line.startswith('#')
        ])
        result["success"] = True
    elif files:
        result["success"] = True
    
    logger.info(f"collect_users_info: found {result['users_count']} users, {len(files)}/{len(files_to_read)} files")
    _r = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_command_history(
    username: Optional[str] = None,
    history_paths: Optional[List[str]] = None
) -> str:
    """
    Собрать историю команд пользователей из образа диска.
    
    Ищет файлы истории команд:
    - .bash_history (Bash shell)
    - .zsh_history (Zsh shell)
    - .history (другие shell)
    
    Используйте для:
    - Анализа действий пользователей/злоумышленников
    - Выявления подозрительных команд
    - Восстановления хронологии событий
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        username: Имя пользователя для сбора истории.
                 Если None и history_paths не указан, собирается история всех пользователей.
                 Пример: "root" или "admin"
        history_paths: Список конкретных путей к файлам истории.
                      Если указан, читаются именно эти файлы (username игнорируется).
                      Имя пользователя определяется автоматически из пути.
                      Пример: ["/root/.bash_history", "/home/admin/.bash_history"]
    
    Returns:
        JSON строка с историей команд:
        - success: True если найдена хотя бы одна история
        - users: Словарь {username: [список команд]}
        - total_commands: Общее количество команд
        - users_with_history: Количество пользователей с историей
        
    Example:
        >>> collect_command_history()
        '{"success": true, "total_commands": 150, "users": {"root": ["ls -la", "cat /etc/passwd", ...]}}'
        
        >>> collect_command_history(history_paths=["/root/.bash_history", "/home/user1/.zsh_history"])
        '{"success": true, "total_commands": 80, "users": {"root": [...], "user1": [...]}}'
    """
    _cache_key = f"collect_command_history:{username}:{history_paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_command_history: cache HIT")
        return json.dumps({"cached": True, "message": "История команд уже получена. Используйте данные из предыдущего вызова."}, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    users_history = {}
    total_commands = 0
    
    if history_paths:
        # ======= Режим 1: Конкретные пути переданы =======
        for hist_path in history_paths:
            content = manager.read_file(hist_path)
            if content:
                user = _extract_user_from_path(hist_path)
                commands = [cmd.strip() for cmd in content.split('\n') if cmd.strip()]
                if user in users_history:
                    users_history[user].extend(commands)
                else:
                    users_history[user] = commands
    else:
        # ======= Режим 2: Стандартное поведение (из passwd) =======
        if username:
            users_to_check = [username]
        else:
            # Получаем список пользователей из passwd
            passwd_content = manager.read_file('/etc/passwd')
            if passwd_content:
                users_to_check = [
                    line.split(':')[0]
                    for line in passwd_content.split('\n')
                    if ':' in line
                ]
            else:
                users_to_check = ['root']
        
        # Собираем историю для каждого пользователя
        for user in users_to_check:
            if user == 'root':
                user_history_paths = [
                    '/root/.bash_history',
                    '/root/.zsh_history',
                    '/root/.history'
                ]
            else:
                user_history_paths = [
                    f'/home/{user}/.bash_history',
                    f'/home/{user}/.zsh_history',
                    f'/home/{user}/.history'
                ]
            
            user_commands = []
            for hist_path in user_history_paths:
                content = manager.read_file(hist_path)
                if content:
                    commands = [cmd.strip() for cmd in content.split('\n') if cmd.strip()]
                    user_commands.extend(commands)
            
            if user_commands:
                users_history[user] = user_commands
    
    # Дедупликация с сохранением порядка для каждого пользователя
    for user in users_history:
        seen = set()
        unique_commands = []
        for cmd in users_history[user]:
            if cmd not in seen:
                seen.add(cmd)
                unique_commands.append(cmd)
        users_history[user] = unique_commands
        total_commands += len(unique_commands)
    
    logger.info(f"collect_command_history: found {total_commands} commands from {len(users_history)} users")
    _r = json.dumps({
        "success": len(users_history) > 0,
        "total_commands": total_commands,
        "users_with_history": len(users_history),
        "users": users_history
    }, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_services_info(paths: Optional[List[str]] = None) -> str:
    """
    Собрать информацию о системных сервисах из образа диска.
    
    Анализирует директории сервисов:
    - /etc/systemd/system: systemd unit файлы
    - /etc/init.d: init скрипты
    - /etc/rc.d: rc скрипты
    - /etc/xinetd.d: xinetd сервисы
    
    Используйте для:
    - Выявления подозрительных сервисов
    - Обнаружения persistence механизмов
    - Анализа автозапуска
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список директорий сервисов для проверки.
               Если None, используются стандартные директории.
               Пример: ["/etc/systemd/system", "/etc/init.d", "/etc/rc.d"]
    
    Returns:
        JSON строка с информацией о сервисах:
        - success: True если найдены сервисы
        - systemd: Список файлов в systemd директории
        - initd: Список файлов в init.d
        - total_services: Общее количество найденных сервисов
        - directories: Словарь {путь: entries} для всех проверенных директорий
        
    Example:
        >>> collect_services_info()
        '{"success": true, "total_services": 45, "systemd": [{"name": "ssh.service", ...}], ...}'
        
        >>> collect_services_info(["/etc/systemd/system", "/lib/systemd/system"])
        '{"success": true, "total_services": 120, ...}'
    """
    _cache_key = f"collect_services_info:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_services_info: cache HIT")
        return json.dumps({"cached": True, "message": "Информация о сервисах уже получена. Используйте данные из предыдущего вызова."}, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    # Маппинг известных путей на ключи результата
    known_path_keys = {
        '/etc/systemd/system': 'systemd',
        '/etc/init.d': 'initd',
        '/etc/rc.d': 'rcd',
        '/etc/xinetd.d': 'xinetd',
    }
    
    # Стандартные пути
    default_paths = list(known_path_keys.keys())
    service_dirs = paths if paths else default_paths
    
    result = {
        "success": False,
        "systemd": [],
        "initd": [],
        "rcd": [],
        "xinetd": [],
        "total_services": 0,
        "paths_used": service_dirs
    }
    
    total = 0
    for path in service_dirs:
        entries = manager.list_directory(path)
        if entries:
            # Определяем ключ: известный маппинг или из имени директории
            key = known_path_keys.get(path, _safe_key_from_path(path))
            if key not in result:
                result[key] = []
            result[key] = entries
            total += len(entries)
            result["success"] = True
    
    result["total_services"] = total
    
    logger.info(f"collect_services_info: found {total} services in {len(service_dirs)} dirs")
    _r = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_cron_info(paths: Optional[List[str]] = None) -> str:
    """
    Собрать информацию о cron задачах из образа диска.
    
    Анализирует:
    - /etc/crontab: главный crontab файл
    - /var/spool/cron: пользовательские crontab
    - /etc/cron.d: дополнительные cron файлы
    - /etc/cron.daily, hourly, weekly, monthly: периодические задачи
    
    Используйте для:
    - Выявления подозрительных запланированных задач
    - Обнаружения persistence механизмов
    - Анализа автоматизации
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список путей к cron-файлам и директориям.
               Если None, используются стандартные пути.
               Функция сама определяет тип каждого пути (файл или директория).
               Пример: ["/etc/crontab", "/var/spool/cron", "/etc/cron.d", "/etc/cron.daily"]
    
    Returns:
        JSON строка с информацией о cron:
        - success: True если найдены cron задачи
        - crontab: Содержимое /etc/crontab
        - cron_d: Список файлов в /etc/cron.d
        - cron_daily: Список файлов в /etc/cron.daily
        - user_crons: Словарь пользовательских crontab
        
    Example:
        >>> collect_cron_info()
        '{"success": true, "crontab": "# /etc/crontab...", "cron_daily": ["logrotate", "apt-compat"]}'
        
        >>> collect_cron_info(["/etc/crontab", "/etc/cron.d", "/etc/cron.daily"])
        '{"success": true, "crontab": "...", "cron_d": [...], "cron_daily": [...]}'
    """
    _cache_key = f"collect_cron_info:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_cron_info: cache HIT")
        return json.dumps({"cached": True, "message": "Информация о cron уже получена. Используйте данные из предыдущего вызова."}, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    default_paths = [
        '/etc/crontab',
        '/var/spool/cron',
        '/etc/cron.d',
        '/etc/cron.daily',
        '/etc/cron.hourly',
        '/etc/cron.weekly',
        '/etc/cron.monthly'
    ]
    
    cron_paths = paths if paths else default_paths
    
    # Маппинг известных директорий на ключи
    known_dir_keys = {
        '/etc/cron.d': 'cron_d',
        '/etc/cron.daily': 'cron_daily',
        '/etc/cron.hourly': 'cron_hourly',
        '/etc/cron.weekly': 'cron_weekly',
        '/etc/cron.monthly': 'cron_monthly',
    }
    
    result = {
        "success": False,
        "crontab": None,
        "cron_d": [],
        "cron_daily": [],
        "cron_hourly": [],
        "cron_weekly": [],
        "cron_monthly": [],
        "user_crons": {},
        "paths_used": cron_paths
    }
    
    for path in cron_paths:
        basename = Path(path).name
        
        # 1. Если это crontab файл — читаем как файл
        if basename == 'crontab':
            content = manager.read_file(path)
            if content:
                result["crontab"] = content
                result["success"] = True
        
        # 2. Если это spool — ищем пользовательские crontab
        elif 'spool' in path:
            crontabs_path = path.rstrip('/') + '/crontabs' if not path.endswith('crontabs') else path
            spool_entries = manager.list_directory(crontabs_path)
            for entry in spool_entries:
                if entry['type'] == 'file':
                    content = manager.read_file(entry['path'])
                    if content:
                        result["user_crons"][entry['name']] = content
                        result["success"] = True
        
        # 3. Остальное — листинг директорий
        else:
            entries = manager.list_directory(path)
            if entries:
                key = known_dir_keys.get(path, _safe_key_from_path(path))
                if key not in result:
                    result[key] = []
                result[key] = [e['name'] for e in entries if e['type'] == 'file']
                result["success"] = True
    
    logger.info(f"collect_cron_info: success={result['success']}")
    _r = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_packages_info(paths: Optional[List[str]] = None) -> str:
    """
    Собрать информацию об установленных пакетах из образа диска.
    
    Поддерживает:
    - Debian/Ubuntu: /var/lib/dpkg/status
    - RedHat/CentOS: /var/lib/rpm
    - Arch Linux: /var/lib/pacman
    
    Используйте для:
    - Выявления подозрительных или уязвимых пакетов
    - Анализа установленного ПО
    - Обнаружения хакерских инструментов
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список путей к файлам/директориям пакетных менеджеров.
               Если None, проверяются стандартные пути (dpkg, rpm, pacman).
               Пример: ["/var/lib/dpkg/status", "/var/lib/rpm"]
    
    Returns:
        JSON строка с информацией о пакетах:
        - success: True если найдена информация о пакетах
        - package_manager: Тип менеджера пакетов ('dpkg', 'rpm', 'pacman')
        - dpkg_status: Содержимое /var/lib/dpkg/status (для Debian/Ubuntu)
        - packages_count: Приблизительное количество пакетов
        
    Example:
        >>> collect_packages_info()
        '{"success": true, "package_manager": "dpkg", "packages_count": 523, ...}'
        
        >>> collect_packages_info(["/var/lib/dpkg/status"])
        '{"success": true, "package_manager": "dpkg", "packages_count": 523}'
    """
    # Cache: prevent repeated identical calls
    _cache_key = f"collect_packages_info:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_packages_info: cache HIT")
        return json.dumps({
            "cached": True,
            "message": "Информация о пакетах уже была получена. Используйте данные из предыдущего вызова."
        }, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    default_paths = ['/var/lib/dpkg/status', '/var/lib/rpm', '/var/lib/pacman']
    package_paths = paths if paths else default_paths
    
    result = {
        "success": False,
        "package_manager": None,
        "dpkg_status": None,
        "packages_count": 0,
        "paths_used": package_paths
    }
    
    for path in package_paths:
        # Определяем тип пакетного менеджера по пути
        if 'dpkg' in path:
            dpkg_status = manager.read_file(path)
            if dpkg_status:
                result["success"] = True
                result["package_manager"] = result["package_manager"] or "dpkg"
                result["packages_count"] = dpkg_status.count('Package:')
                # Extract package names list instead of returning entire dpkg/status
                # (full dpkg_status can be 100K+ chars which blows up LLM context)
                _pkg_names = [line.split(': ', 1)[1].strip() for line in dpkg_status.splitlines() if line.startswith('Package: ')]
                result["package_names"] = _pkg_names
                # Keep only first 4000 chars of raw status for reference
                result["dpkg_status"] = dpkg_status[:4000] + '...[TRUNCATED]' if len(dpkg_status) > 4000 else dpkg_status
                logger.info(f"collect_packages_info: found {result['packages_count']} dpkg packages")
                if not paths:
                    _r = json.dumps(result, ensure_ascii=False)
                    _tool_result_cache[_cache_key] = _r
                    return _r
        
        elif 'rpm' in path:
            rpm_entries = manager.list_directory(path)
            if rpm_entries:
                result["success"] = True
                result["package_manager"] = result["package_manager"] or "rpm"
                result["packages_count"] += len(rpm_entries)
                logger.info(f"collect_packages_info: found RPM database")
                if not paths:
                    return json.dumps(result, ensure_ascii=False)
        
        elif 'pacman' in path:
            local_path = path if path.endswith('/local') else path.rstrip('/') + '/local'
            pacman_entries = manager.list_directory(local_path)
            if pacman_entries:
                result["success"] = True
                result["package_manager"] = result["package_manager"] or "pacman"
                result["packages_count"] += len(pacman_entries)
                logger.info(f"collect_packages_info: found {len(pacman_entries)} pacman packages")
                if not paths:
                    return json.dumps(result, ensure_ascii=False)
        
        else:
            # Неизвестный путь — пробуем прочитать как файл, потом как директорию
            content = manager.read_file(path)
            if content:
                result["success"] = True
                result.setdefault("additional_files", {})[path] = content
            else:
                entries = manager.list_directory(path)
                if entries:
                    result["success"] = True
                    result.setdefault("additional_dirs", {})[path] = [e['name'] for e in entries]
    
    logger.info(f"collect_packages_info: success={result['success']}, manager={result['package_manager']}")
    _r = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_docker_info(paths: Optional[List[str]] = None) -> str:
    """
    Собрать информацию о Docker из образа диска.
    
    Анализирует:
    - /var/lib/docker: данные Docker (images, containers, volumes)
    - /etc/docker: конфигурация Docker
    - /root/.docker: конфигурация пользователя root
    
    Используйте для:
    - Выявления запущенных контейнеров
    - Анализа Docker images
    - Обнаружения криптомайнеров и вредоносных контейнеров
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список путей к директориям Docker.
               Если None, используются стандартные пути.
               Пример: ["/var/lib/docker", "/etc/docker", "/root/.docker"]
    
    Returns:
        JSON строка с информацией о Docker:
        - success: True если найдена информация о Docker
        - docker_installed: True если Docker установлен
        - docker_lib: Содержимое /var/lib/docker
        - docker_config: Содержимое daemon.json
        - containers: Список контейнеров (если найдены)
        
    Example:
        >>> collect_docker_info()
        '{"success": true, "docker_installed": true, "containers": ["nginx", "redis"]}'
        
        >>> collect_docker_info(["/var/lib/docker", "/etc/docker"])
        '{"success": true, "docker_installed": true, ...}'
    """
    _cache_key = f"collect_docker_info:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_docker_info: cache HIT")
        return json.dumps({"cached": True, "message": "Информация о Docker уже получена. Используйте данные из предыдущего вызова."}, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    default_paths = ['/var/lib/docker', '/etc/docker', '/root/.docker']
    docker_paths = paths if paths else default_paths
    
    result = {
        "success": False,
        "docker_installed": False,
        "docker_lib": [],
        "docker_config": None,
        "containers": [],
        "images": [],
        "paths_used": docker_paths
    }
    
    for path in docker_paths:
        # /var/lib/docker — основная директория Docker
        if 'lib' in path and 'docker' in path:
            docker_lib = manager.list_directory(path)
            if docker_lib:
                result["docker_installed"] = True
                result["success"] = True
                result["docker_lib"] = [e['name'] for e in docker_lib]
                
                # Ищем контейнеры
                containers_dir = manager.list_directory(path.rstrip('/') + '/containers')
                if containers_dir:
                    result["containers"] = [e['name'] for e in containers_dir if e['type'] == 'directory']
        
        # /etc/docker — конфигурация
        elif '/etc/' in path and 'docker' in path:
            docker_config = manager.read_file(path.rstrip('/') + '/daemon.json')
            if docker_config:
                result["docker_config"] = docker_config
                result["success"] = True
            else:
                # Листинг директории
                entries = manager.list_directory(path)
                if entries:
                    result.setdefault("docker_etc", []).extend([e['name'] for e in entries])
                    result["success"] = True
        
        # Любая другая docker-директория (например, /root/.docker)
        else:
            entries = manager.list_directory(path)
            if entries:
                result.setdefault("docker_dirs", {})[path] = [e['name'] for e in entries]
                result["docker_installed"] = True
                result["success"] = True
    
    logger.info(f"collect_docker_info: docker_installed={result['docker_installed']}")
    _r = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_ssh_artifacts(paths: Optional[List[str]] = None) -> str:
    """
    Собрать SSH артефакты из образа диска.
    
    Анализирует:
    - /etc/ssh: конфигурация SSH сервера
    - /root/.ssh: SSH ключи и конфигурация root
    - /home/*/.ssh: SSH ключи и конфигурация пользователей
    - authorized_keys: авторизованные публичные ключи
    - known_hosts: известные хосты
    
    Используйте для:
    - Выявления backdoor ключей в authorized_keys
    - Анализа SSH конфигурации
    - Обнаружения подозрительных соединений
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список SSH-директорий для проверки.
               Если None, автоматически определяются из /etc/passwd.
               Пример: ["/etc/ssh", "/root/.ssh", "/home/admin/.ssh"]
    
    Returns:
        JSON строка с SSH артефактами:
        - success: True если найдены SSH артефакты
        - sshd_config: Конфигурация SSH сервера
        - authorized_keys: Словарь {пользователь: authorized_keys}
        - known_hosts: Словарь {пользователь: known_hosts}
        - ssh_keys: Список найденных SSH ключей
        
    Example:
        >>> collect_ssh_artifacts()
        '{"success": true, "authorized_keys": {"root": "ssh-rsa AAAA...", "admin": "ssh-ed25519 AAAA..."}}'
        
        >>> collect_ssh_artifacts(["/etc/ssh", "/root/.ssh", "/home/deploy/.ssh"])
        '{"success": true, "sshd_config": "...", "authorized_keys": {"root": "...", "deploy": "..."}}'
    """
    _cache_key = f"collect_ssh_artifacts:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_ssh_artifacts: cache HIT")
        return json.dumps({"cached": True, "message": "SSH артефакты уже получены. Используйте данные из предыдущего вызова."}, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    result = {
        "success": False,
        "sshd_config": None,
        "authorized_keys": {},
        "known_hosts": {},
        "ssh_keys": []
    }
    
    if paths:
        # ======= Режим 1: Конкретные пути переданы =======
        ssh_dirs = paths
    else:
        # ======= Режим 2: Стандартное поведение — собираем из /etc/passwd =======
        ssh_dirs = ['/etc/ssh']
        passwd_content = manager.read_file('/etc/passwd')
        if passwd_content:
            for line in passwd_content.split('\n'):
                parts = line.split(':')
                if len(parts) >= 6:
                    user = parts[0]
                    home_dir = parts[5]
                    ssh_path = f'{home_dir}/.ssh'
                    if ssh_path not in ssh_dirs:
                        ssh_dirs.append(ssh_path)
        else:
            ssh_dirs.append('/root/.ssh')
    
    result["paths_used"] = ssh_dirs
    
    for ssh_dir in ssh_dirs:
        # Директория /etc/ssh — серверная конфигурация
        if ssh_dir.rstrip('/') == '/etc/ssh' or (ssh_dir.startswith('/etc/') and 'ssh' in ssh_dir and '.ssh' not in ssh_dir):
            sshd_config = manager.read_file(f'{ssh_dir.rstrip("/")}/sshd_config')
            if sshd_config:
                result["sshd_config"] = sshd_config
                result["success"] = True
            continue
        
        # Пользовательская .ssh директория
        user = _extract_user_from_path(ssh_dir)
        
        # authorized_keys
        auth_keys = manager.read_file(f'{ssh_dir.rstrip("/")}/authorized_keys')
        if auth_keys:
            result["authorized_keys"][user] = auth_keys
            result["success"] = True
        
        # known_hosts
        known = manager.read_file(f'{ssh_dir.rstrip("/")}/known_hosts')
        if known:
            result["known_hosts"][user] = known
            result["success"] = True
        
        # SSH ключи
        ssh_entries = manager.list_directory(ssh_dir)
        for entry in ssh_entries:
            if entry['type'] == 'file' and (
                entry['name'].startswith('id_') or
                entry['name'].endswith('.pub')
            ):
                result["ssh_keys"].append({
                    "user": user,
                    "key_file": entry['path'],
                    "name": entry['name']
                })
                result["success"] = True
    
    logger.info(f"collect_ssh_artifacts: found {len(result['authorized_keys'])} authorized_keys, {len(result['ssh_keys'])} ssh keys")
    _r = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_network_config(paths: Optional[List[str]] = None) -> str:
    """
    Собрать сетевую конфигурацию из образа диска.
    
    Анализирует:
    - /etc/hosts: статические записи DNS
    - /etc/resolv.conf: DNS серверы
    - /etc/hostname: имя хоста
    - /etc/network/interfaces: сетевые интерфейсы (Debian)
    - /etc/sysconfig/network-scripts: сетевые интерфейсы (RedHat)
    - /etc/iptables: правила firewall
    
    Используйте для:
    - Выявления подозрительных DNS записей
    - Анализа сетевой топологии
    - Обнаружения туннелей и редиректов
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список путей к файлам/директориям сетевой конфигурации.
               Если None, используются стандартные пути.
               Функция автоматически определяет, является ли путь файлом или директорией.
               Пример: ["/etc/hosts", "/etc/resolv.conf", "/etc/network"]
    
    Returns:
        JSON строка с сетевой конфигурацией:
        - success: True если найдена сетевая конфигурация
        - hosts: Содержимое /etc/hosts
        - resolv_conf: Содержимое /etc/resolv.conf
        - interfaces: Сетевые интерфейсы
        - iptables: Правила iptables (если найдены)
        - files: Словарь {путь: содержимое} всех прочитанных файлов
        - directories: Словарь {путь: entries} для найденных директорий
        
    Example:
        >>> collect_network_config()
        '{"success": true, "hosts": "127.0.0.1 localhost\\n...", "resolv_conf": "nameserver 8.8.8.8"}'
        
        >>> collect_network_config(["/etc/hosts", "/etc/resolv.conf", "/etc/network"])
        '{"success": true, "hosts": "...", "resolv_conf": "...", "directories": {"/etc/network": [...]}}'
    """
    _cache_key = f"collect_network_config:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_network_config: cache HIT")
        return json.dumps({"cached": True, "message": "Сетевая конфигурация уже получена. Используйте данные из предыдущего вызова."}, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    # Стандартные пути (конкретные файлы)
    default_paths = [
        '/etc/hosts',
        '/etc/resolv.conf',
        '/etc/hostname',
        '/etc/network/interfaces',
        '/etc/iptables/rules.v4'
    ]
    
    network_paths = paths if paths else default_paths
    
    # Маппинг известных файлов на ключи результата
    known_file_keys = {
        '/etc/hosts': 'hosts',
        '/etc/resolv.conf': 'resolv_conf',
        '/etc/hostname': 'hostname',
        '/etc/network/interfaces': 'interfaces',
        '/etc/iptables/rules.v4': 'iptables',
    }
    
    result = {
        "success": False,
        "hosts": None,
        "resolv_conf": None,
        "hostname": None,
        "interfaces": None,
        "iptables": None,
        "files": {},
        "directories": {},
        "paths_used": network_paths
    }
    
    for path in network_paths:
        # Сначала пробуем прочитать как файл
        content = manager.read_file(path)
        if content:
            result["files"][path] = content
            result["success"] = True
            
            # Заполняем backward-compatible ключи
            if path in known_file_keys:
                value = content.strip() if 'hostname' in path else content
                result[known_file_keys[path]] = value
        else:
            # Пробуем как директорию
            entries = manager.list_directory(path)
            if entries:
                result["directories"][path] = entries
                result["success"] = True
    
    logger.info(f"collect_network_config: success={result['success']}, files={len(result['files'])}, dirs={len(result['directories'])}")
    _r = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def collect_auth_logs(paths: Optional[List[str]] = None) -> str:
    """
    Собрать логи авторизации из образа диска.
    
    Читает:
    - /var/log/auth.log: логи авторизации (Debian/Ubuntu)
    - /var/log/secure: логи авторизации (RedHat/CentOS)
    - /var/log/messages: системные сообщения
    
    Используйте для:
    - Выявления попыток взлома (brute force)
    - Анализа успешных/неуспешных входов
    - Обнаружения подозрительной активности
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        paths: Список путей к файлам логов авторизации.
               Если None, используются стандартные пути.
               Пример: ["/var/log/auth.log", "/var/log/secure", "/var/log/kern.log"]
    
    Returns:
        JSON строка с логами авторизации:
        - success: True если найдены логи
        - auth_log: Содержимое /var/log/auth.log
        - secure: Содержимое /var/log/secure
        - messages: Содержимое /var/log/messages
        - files: Словарь {путь: содержимое} всех прочитанных логов
        - failed_logins: Количество неудачных попыток входа
        
    Example:
        >>> collect_auth_logs()
        '{"success": true, "auth_log": "Jan 15 10:23:45 server sshd[1234]: Accepted publickey...", "failed_logins": 15}'
        
        >>> collect_auth_logs(["/var/log/auth.log", "/var/log/syslog"])
        '{"success": true, "auth_log": "...", "files": {"/var/log/syslog": "..."}, "failed_logins": 22}'
    """
    # Cache: prevent repeated identical calls
    _cache_key = f"collect_auth_logs:{paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_auth_logs: cache HIT")
        return json.dumps({
            "cached": True,
            "message": "Логи авторизации уже были получены. Используйте данные из предыдущего вызова."
        }, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    default_paths = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages']
    log_paths = paths if paths else default_paths
    
    # Маппинг известных файлов на ключи
    known_log_keys = {
        '/var/log/auth.log': 'auth_log',
        '/var/log/secure': 'secure',
        '/var/log/messages': 'messages',
    }
    
    result = {
        "success": False,
        "auth_log": None,
        "secure": None,
        "messages": None,
        "files": {},
        "failed_logins": 0,
        "successful_logins": 0,
        "paths_used": log_paths
    }
    
    for path in log_paths:
        content = manager.read_file(path)
        if content:
            result["files"][path] = content
            result["success"] = True
            
            # Заполняем backward-compatible ключи
            if path in known_log_keys:
                result[known_log_keys[path]] = content
            
            # Подсчитываем неудачные/успешные попытки входа
            content_lower = content.lower()
            result["failed_logins"] += content_lower.count('failed') + content_lower.count('invalid')
            result["successful_logins"] += content_lower.count('accepted')
    
    logger.info(f"collect_auth_logs: failed={result['failed_logins']}, success={result['successful_logins']}")
    # Truncate large log contents to prevent context overflow
    for _k in ['auth_log', 'secure', 'messages']:
        if result.get(_k) and len(result[_k]) > 4000:
            result[_k] = result[_k][:4000] + '\n...[TRUNCATED: показано 4000 символов]'
    for _fpath in list(result.get('files', {}).keys()):
        if len(result['files'][_fpath]) > 4000:
            result['files'][_fpath] = result['files'][_fpath][:4000] + '\n...[TRUNCATED]'
    _r = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _r
    return _r


@tool
def clean_command_history(history_json: str) -> str:
    """
    Очистить историю команд от дубликатов с сохранением порядка.
    
    Принимает JSON с историей команд (результат collect_command_history)
    и возвращает очищенную версию без повторяющихся команд.
    
    Используйте для:
    - Подготовки истории к анализу
    - Удаления повторяющихся команд
    - Уменьшения объёма данных для анализа
    
    Args:
        history_json: JSON строка с историей команд.
                     Формат: {"users": {"username": ["cmd1", "cmd2", ...]}}
    
    Returns:
        JSON строка с очищенной историей:
        - success: True если очистка выполнена
        - users: Словарь {username: [уникальные команды]}
        - total_commands_before: Количество команд до очистки
        - total_commands_after: Количество команд после очистки
        - duplicates_removed: Количество удалённых дубликатов
        
    Example:
        >>> clean_command_history('{"users": {"root": ["ls", "ls", "pwd", "ls"]}}')
        '{"success": true, "users": {"root": ["ls", "pwd"]}, "duplicates_removed": 2}'
    """
    try:
        data = json.loads(history_json)
    except json.JSONDecodeError as e:
        return json.dumps({
            "success": False,
            "error": f"Invalid JSON: {str(e)}"
        }, ensure_ascii=False)
    
    users_data = data.get('users', {})
    if not users_data:
        return json.dumps({
            "success": False,
            "error": "No 'users' key found in input"
        }, ensure_ascii=False)
    
    cleaned_users = {}
    total_before = 0
    total_after = 0
    
    for user, commands in users_data.items():
        if isinstance(commands, list):
            total_before += len(commands)
            # Удаляем дубликаты с сохранением порядка
            seen = set()
            unique_commands = []
            for cmd in commands:
                cmd_clean = cmd.strip() if isinstance(cmd, str) else str(cmd)
                if cmd_clean and cmd_clean not in seen:
                    seen.add(cmd_clean)
                    unique_commands.append(cmd_clean)
            cleaned_users[user] = unique_commands
            total_after += len(unique_commands)
        elif isinstance(commands, str):
            # Если команды переданы как строка с переносами
            cmd_list = [c.strip() for c in commands.split('\n') if c.strip()]
            total_before += len(cmd_list)
            seen = set()
            unique_commands = []
            for cmd in cmd_list:
                if cmd not in seen:
                    seen.add(cmd)
                    unique_commands.append(cmd)
            cleaned_users[user] = unique_commands
            total_after += len(unique_commands)
    
    result = {
        "success": True,
        "users": cleaned_users,
        "total_commands_before": total_before,
        "total_commands_after": total_after,
        "duplicates_removed": total_before - total_after,
        "users_count": len(cleaned_users)
    }
    
    logger.info(f"clean_command_history: removed {result['duplicates_removed']} duplicates")
    return json.dumps(result, ensure_ascii=False)


@tool
def collect_logs_info(
    var_paths: Optional[List[str]] = None,
    www_paths: Optional[List[str]] = None
) -> str:
    """
    Собрать информацию о лог-файлах из образа диска.
    
    Анализирует директории логов:
    
    Системные логи (var_paths):
    - /var/log: системные логи
    
    Веб-серверные логи и конфигурации (www_paths):
    - /var/www: файлы веб-сервера
    - /usr/share/nginx: статические файлы nginx
    - /etc/nginx: конфигурация nginx
    - /etc/apache2: конфигурация Apache (Debian/Ubuntu)
    - /etc/httpd: конфигурация Apache (RedHat/CentOS)
    
    Используйте для:
    - Получения списка всех доступных логов
    - Планирования детального анализа логов
    - Выявления нестандартных лог-файлов
    - Анализа конфигураций веб-серверов
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        var_paths: Список директорий системных логов.
                  Если None, используются пути из configs/triage.yaml.
                  Пример: ["/var/log"]
        www_paths: Список директорий веб-серверных файлов и конфигов.
                  Если None, используются пути из configs/triage.yaml.
                  Пример: ["/var/www", "/etc/nginx", "/etc/apache2"]
    
    Returns:
        JSON строка со списками логов:
        - success: True если найдены логи
        - var_logs: Список файлов в var-директориях
        - www_logs: Объединённый список файлов из www-директорий
        - nginx_config: Список файлов nginx
        - apache_config: Список файлов apache
        - total_logs: Общее количество файлов
        
    Example:
        >>> collect_logs_info()
        '{"success": true, "var_logs": [{"name": "auth.log", "size": 12345}, ...], "var_logs_count": 25}'
        
        >>> collect_logs_info(var_paths=["/var/log"], www_paths=["/etc/nginx"])
        '{"success": true, "var_logs": [...], "nginx_config": [...]}'
    """
    # Cache: prevent repeated identical calls that blow up LLM context
    _cache_key = f"collect_logs_info:{var_paths}:{www_paths}"
    if _cache_key in _tool_result_cache:
        logger.info(f"collect_logs_info: cache HIT (preventing duplicate call)")
        return json.dumps({
            "cached": True,
            "message": "Информация о логах уже была получена ранее. Используйте данные из предыдущего вызова collect_logs_info. Не вызывайте этот инструмент повторно."
        }, ensure_ascii=False)
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    # Определяем пути: переданные → из конфига → стандартные
    if var_paths is None:
        logs_config = manager.get_config('artifacts.logs') or {}
        var_paths = logs_config.get('var', ['/var/log'])
    
    if www_paths is None:
        logs_config = manager.get_config('artifacts.logs') or {}
        www_paths = logs_config.get('www', ['/var/www', '/usr/share/nginx', '/etc/nginx', '/etc/apache2', '/etc/httpd'])
    
    result = {
        "success": False,
        "var_logs": [],
        "www_logs": [],
        "nginx_config": [],
        "apache_config": [],
        "var_logs_count": 0,
        "www_logs_count": 0,
        "total_logs": 0,
        "scanned_paths": {
            "var": [],
            "www": []
        },
        "paths_used": {
            "var": var_paths,
            "www": www_paths
        }
    }
    
    # Обрабатываем var пути (системные логи)
    for var_path in var_paths:
        entries = manager.list_directory(var_path)
        if entries:
            result["var_logs"].extend(entries)
            result["scanned_paths"]["var"].append({
                "path": var_path,
                "count": len(entries)
            })
            result["success"] = True
    
    result["var_logs_count"] = len(result["var_logs"])
    
    # Обрабатываем www пути (веб-серверные логи и конфигурации)
    for www_path in www_paths:
        entries = manager.list_directory(www_path)
        if entries:
            # Определяем категорию
            if 'nginx' in www_path:
                result["nginx_config"].extend(entries)
            elif 'apache' in www_path or 'httpd' in www_path:
                result["apache_config"].extend(entries)
            else:
                result["www_logs"].extend(entries)
            
            result["scanned_paths"]["www"].append({
                "path": www_path,
                "count": len(entries)
            })
            result["success"] = True
    
    result["www_logs_count"] = (
        len(result["www_logs"]) +
        len(result["nginx_config"]) +
        len(result["apache_config"])
    )
    
    result["total_logs"] = result["var_logs_count"] + result["www_logs_count"]
    
    logger.info(f"collect_logs_info: found {result['total_logs']} log entries from {len(var_paths) + len(www_paths)} paths")
    _result_str = json.dumps(result, ensure_ascii=False)
    _tool_result_cache[_cache_key] = _result_str  # Cache for future calls
    # Truncate if too large
    if len(_result_str) > 8000:
        _result_str = _result_str[:7500] + '\n... [ОБРЕЗАНО: показано 7500 из ' + str(len(_result_str)) + ' символов] ...'
    return _result_str


@tool
def extract_log_file(log_path: str, output_dir: str = "extracted/logs") -> str:
    """
    Извлечь конкретный лог-файл из образа диска для детального анализа.
    
    Читает указанный лог-файл из образа и сохраняет его в локальную
    файловую систему для дальнейшего анализа.
    
    Используйте для:
    - Извлечения важных логов для анализа
    - Сохранения артефактов для отчёта
    - Подготовки данных для поиска паттернов
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        log_path: Путь к лог-файлу внутри образа.
                 Пример: "/var/log/auth.log" или "/var/log/syslog"
        output_dir: Директория для сохранения извлечённого файла.
                   По умолчанию: "extracted/logs"
    
    Returns:
        JSON строка с результатом:
        - success: True если файл извлечён
        - source_path: Исходный путь в образе
        - extracted_path: Путь к извлечённому файлу
        - size: Размер файла в байтах
        - lines_count: Количество строк в файле
        
    Example:
        >>> extract_log_file("/var/log/auth.log")
        '{"success": true, "source_path": "/var/log/auth.log", "extracted_path": "extracted/logs/var_log_auth.log", "size": 54321, "lines_count": 1234}'
    """
    from src.utils.filesystem import FileSystemUtils
    fs_utils = FileSystemUtils()
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first.",
            "source_path": log_path
        }, ensure_ascii=False)
    
    # Читаем файл из образа
    content = manager.read_file(log_path)
    
    if content is None:
        return json.dumps({
            "success": False,
            "error": f"Could not read log file: {log_path}",
            "source_path": log_path
        }, ensure_ascii=False)
    
    # Защита от абсолютных путей (AI может передать /analysis и т.п.)
    if output_dir.startswith('/'):
        logger.warning(f"Absolute output_dir '{output_dir}' rejected, using default")
        output_dir = "extracted/logs"
    
    # Создаём безопасное имя файла
    safe_name = log_path.replace('/', '_').lstrip('_')
    output_path = Path(output_dir) / safe_name
    
    # Создаём директорию и записываем файл
    fs_utils.ensure_directory(output_path.parent)
    
    try:
        fs_utils.safe_write(output_path, content)
        
        lines_count = len(content.split('\n'))
        
        logger.info(f"extract_log_file: {log_path} -> {output_path} ({len(content)} bytes)")
        return json.dumps({
            "success": True,
            "source_path": log_path,
            "extracted_path": str(output_path),
            "size": len(content),
            "lines_count": lines_count
        }, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error extracting log: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "source_path": log_path
        }, ensure_ascii=False)


@tool
def extract_home_files(
    output_dir: str = "extracted/files/raw",
    home_dirs: Optional[List[str]] = None
) -> str:
    """
    Извлечь файлы из домашних директорий (/home и /root).
    
    Извлекает файлы из домашних директорий пользователей для последующего анализа.
    
    Процесс:
    1. Проходит по указанным директориям (по умолчанию /home и /root)
    2. Получает список файлов первого уровня в каждой директории
    3. Извлекает содержимое каждого файла (лимит: 200 файлов на директорию)
    4. Сохраняет с безопасным именем (/ заменяется на _)
    
    Используйте для:
    - Извлечения конфигурационных файлов (.bashrc, .profile)
    - Поиска скрытых файлов и скриптов
    - Анализа persistence механизмов
    - Сбора артефактов из пользовательских директорий
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        output_dir: Директория для сохранения извлечённых файлов.
                   По умолчанию: "extracted/files/raw" (как в оригинале)
        home_dirs: Список домашних директорий для сканирования.
                  Если None, используются ["/home", "/root"].
                  Пример: ["/home", "/root", "/opt/users"]
    
    Returns:
        JSON строка с результатом:
        - success: True если файлы извлечены
        - extracted_files: Список извлечённых файлов с путями
        - total_files: Количество извлечённых файлов
        - total_size: Общий размер в байтах
        - home_dirs_processed: Список обработанных директорий
        - errors: Список ошибок при извлечении (если были)
        
    Example:
        >>> extract_home_files()
        '{"success": true, "total_files": 42, "extracted_files": [{"source": "/root/.bashrc", ...}]}'
        
        >>> extract_home_files(home_dirs=["/home", "/root", "/srv/users"])
        '{"success": true, "total_files": 60, ...}'
    """
    from src.utils.filesystem import FileSystemUtils
    fs_utils = FileSystemUtils()
    
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    logger.info("Extracting home/root files")
    
    # Директории для обработки
    dirs_to_scan = home_dirs if home_dirs else ['/home', '/root']
    
    # Создаём выходную директорию (защита от абсолютных путей)
    if output_dir.startswith('/'):
        logger.warning(f"Absolute output_dir '{output_dir}' rejected, using default")
        output_dir = "extracted/files/raw"
    output_path = Path(output_dir)
    fs_utils.ensure_directory(output_path)
    
    extracted_files = []
    total_size = 0
    home_dirs_processed = []
    errors = []
    
    # Лимит файлов (как в оригинале - 200)
    max_files_limit = 200
    
    for home_dir in dirs_to_scan:
        # Получаем список файлов в директории
        entries = manager.list_directory(home_dir)
        
        if not entries:
            logger.debug(f"No entries found in {home_dir}")
            continue
        
        home_dirs_processed.append(home_dir)
        
        # Собираем пути к файлам
        file_paths = []
        for entry in entries:
            file_paths.append(entry['path'])
        
        # Ограничиваем количество файлов (как в оригинале: files[:200])
        file_paths = file_paths[:max_files_limit]
        
        for file_path in file_paths:
            try:
                content = manager.read_file(file_path)
                if content:
                    # Создаём безопасное имя (как в оригинале)
                    safe_name = file_path.replace('/', '_').lstrip('_')
                    dest_path = output_path / safe_name
                    
                    fs_utils.safe_write(dest_path, content)
                    
                    extracted_files.append({
                        "source": file_path,
                        "dest": str(dest_path),
                        "size": len(content) if isinstance(content, (str, bytes)) else 0
                    })
                    total_size += len(content) if isinstance(content, (str, bytes)) else 0
                    
            except Exception as e:
                logger.debug(f"Could not extract {file_path}: {e}")
                errors.append({
                    "path": file_path,
                    "error": str(e)
                })
    
    result = {
        "success": len(extracted_files) > 0,
        "extracted_files": extracted_files,
        "total_files": len(extracted_files),
        "total_size": total_size,
        "home_dirs_processed": home_dirs_processed,
        "output_dir": str(output_path),
        "paths_used": dirs_to_scan
    }
    
    if errors:
        result["errors"] = errors
        result["error_count"] = len(errors)
    
    logger.info(f"extract_home_files: extracted {len(extracted_files)} files ({total_size} bytes)")
    return json.dumps(result, ensure_ascii=False)


# ==================== MALWARE PATTERNS ====================

_MALWARE_PATTERNS = [
    # Reverse shells
    (r'/dev/tcp/', 'critical', 'Reverse shell через /dev/tcp'),
    (r'/dev/udp/', 'critical', 'Reverse shell через /dev/udp'),
    (r'bash\s+-i\s+>&', 'critical', 'Bash interactive reverse shell'),
    (r'\bnc\s+.*-e\s+/bin/', 'critical', 'Netcat reverse shell (nc -e)'),
    (r'\bncat\s+.*-e\s+/bin/', 'critical', 'Ncat reverse shell'),
    (r'\bsocat\b.*\bexec\b', 'high', 'Socat exec shell'),
    (r'python.*socket.*connect', 'high', 'Python reverse shell'),
    (r'perl.*socket.*INET', 'high', 'Perl reverse shell'),
    (r'ruby.*TCPSocket', 'high', 'Ruby reverse shell'),
    (r'php.*fsockopen', 'high', 'PHP reverse shell'),
    (r'mkfifo\s+.*\bsh\b', 'critical', 'Named pipe reverse shell'),
    # Загрузчики / dropper-ы
    (r'(wget|curl)\s+.*\|\s*(ba)?sh', 'critical', 'Загрузка и исполнение скрипта из сети'),
    (r'(wget|curl)\s+.*&&\s*chmod\s+\+x', 'high', 'Загрузка и chmod +x'),
    # Кодирование / обфускация
    (r'base64\s+(-d|--decode)\s*\|', 'high', 'Base64-декодирование в pipeline'),
    (r'eval\s*\$\(.*base64', 'critical', 'eval + base64 обфускация'),
    # Persistence
    (r'crontab\s+.*-l.*\|.*crontab', 'high', 'Программное добавление в crontab'),
    # Crypto mining
    (r'(xmrig|minerd|cpuminer|stratum\+)', 'critical', 'Криптомайнер'),
]

_MALWARE_COMPILED = [(re.compile(pat, re.IGNORECASE), sev, desc) for pat, sev, desc in _MALWARE_PATTERNS]


# ==================== SCAN HOME FILES FOR MALWARE ====================

@tool
def scan_home_files_for_malware(image_fs_dir: str = "image_fs") -> str:
    """Детерминированное сканирование файлов в home/root на malware-паттерны.

    Сканирует текстовые файлы в /root/ и /home/*/ на:
    - Reverse shell паттерны (/dev/tcp, bash -i, nc -e и т.д.)
    - Backdoor-индикаторы (eval, base64-декодирование, загрузчики)
    - Криптомайнеры

    Ограничения:
    - Файлы > 1MB пропускаются (вероятно бинарники)
    - Максимум 500 файлов суммарно
    - Только 1-й уровень вложенности

    Args:
        image_fs_dir: Путь к директории с выгруженной ФС образа

    Returns:
        JSON с результатами сканирования: {success, hits, files_scanned, dirs_scanned}
    """
    hits: List[Dict[str, Any]] = []
    files_scanned = 0
    max_files = 500
    max_file_size = 1_000_000  # 1MB

    # Собираем директории для сканирования: /root/ + /home/*/
    dirs_to_scan: List[str] = []

    root_home = os.path.join(image_fs_dir, "root")
    if os.path.isdir(root_home):
        dirs_to_scan.append(root_home)

    home_dir = os.path.join(image_fs_dir, "home")
    if os.path.isdir(home_dir):
        try:
            for entry in os.listdir(home_dir):
                entry_path = os.path.join(home_dir, entry)
                if os.path.isdir(entry_path) and not entry.startswith('.'):
                    dirs_to_scan.append(entry_path)
        except OSError:
            pass

    for scan_dir in dirs_to_scan:
        if files_scanned >= max_files:
            break

        try:
            entries = os.listdir(scan_dir)
        except OSError:
            continue

        for fname in entries:
            if files_scanned >= max_files:
                break

            file_path = os.path.join(scan_dir, fname)

            # Пропускаем директории и симлинки
            if os.path.isdir(file_path):
                continue

            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                continue

            if file_size > max_file_size or file_size == 0:
                continue

            files_scanned += 1

            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            if not content:
                continue

            # Проверяем каждый malware-паттерн
            for regex, severity, description in _MALWARE_COMPILED:
                match = regex.search(content)
                if match:
                    matched_line = match.group(0)[:200]
                    start = max(0, match.start() - 40)
                    end = min(len(content), match.end() + 40)
                    context_snippet = content[start:end].strip().replace('\n', ' ')[:300]

                    # Путь внутри образа (без image_fs/ префикса)
                    image_path = file_path.replace(image_fs_dir, "", 1)
                    if not image_path.startswith("/"):
                        image_path = "/" + image_path

                    hits.append({
                        'severity': severity,
                        'title': f'{description}: {image_path}',
                        'details': (
                            f'Файл {image_path} содержит malware-паттерн. '
                            f'Совпадение: "{matched_line}". '
                            f'Контекст: {context_snippet}'
                        ),
                        'evidence': [
                            f'Файл: {image_path}',
                            f'Паттерн: {description}',
                            f'Совпадение: {matched_line}',
                        ],
                        'related_paths': [image_path],
                    })

    result = {
        "success": True,
        "hits": hits,
        "total_hits": len(hits),
        "files_scanned": files_scanned,
        "dirs_scanned": len(dirs_to_scan),
    }

    logger.info(f"scan_home_files_for_malware: {files_scanned} files scanned, {len(hits)} hits")
    return json.dumps(result, ensure_ascii=False)


def read_home_files_for_analysis(image_fs_dir: str = "image_fs") -> List[Dict[str, str]]:
    """Прочитать содержимое маленьких файлов из /root/ и /home/*/ для LLM-анализа.

    Не является @tool — вспомогательная функция для батчинга файлов
    перед отправкой субагенту file_content_analyzer.

    Args:
        image_fs_dir: Путь к директории с выгруженной ФС образа

    Returns:
        Список [{path, content, size}] для каждого прочитанного файла.
    """
    files: List[Dict[str, str]] = []
    max_files = 200
    max_file_size = 100_000  # 100KB — только маленькие текстовые файлы
    files_read = 0

    # Собираем директории: /root/ + /home/*/
    dirs_to_scan: List[str] = []

    root_home = os.path.join(image_fs_dir, "root")
    if os.path.isdir(root_home):
        dirs_to_scan.append(root_home)

    home_dir = os.path.join(image_fs_dir, "home")
    if os.path.isdir(home_dir):
        try:
            for entry in os.listdir(home_dir):
                entry_path = os.path.join(home_dir, entry)
                if os.path.isdir(entry_path) and not entry.startswith('.'):
                    dirs_to_scan.append(entry_path)
        except OSError:
            pass

    for scan_dir in dirs_to_scan:
        if files_read >= max_files:
            break

        try:
            entries = os.listdir(scan_dir)
        except OSError:
            continue

        for fname in entries:
            if files_read >= max_files:
                break

            file_path = os.path.join(scan_dir, fname)

            if os.path.isdir(file_path):
                continue

            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                continue

            if file_size > max_file_size or file_size == 0:
                continue

            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            if not content.strip():
                continue

            # Путь внутри образа
            image_path = file_path.replace(image_fs_dir, "", 1)
            if not image_path.startswith("/"):
                image_path = "/" + image_path

            files.append({
                'path': image_path,
                'content': content,
                'size': len(content),
            })
            files_read += 1

    logger.info(f"read_home_files_for_analysis: {files_read} files read from {len(dirs_to_scan)} dirs")
    return files
