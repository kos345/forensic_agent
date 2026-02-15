"""
Forensic Tools Module - Инструменты для AI-агента

Этот модуль содержит все инструменты (tools), которые AI-агент
может использовать для криминалистического анализа образов дисков.

Категории инструментов:
- image_tools: Работа с образом диска (открытие, чтение файлов, листинг директорий)
- artifact_tools: Сбор криминалистических артефактов (пользователи, сервисы, cron и т.д.)
- analysis_tools: Анализ данных (извлечение IOC, парсинг файлов)
- filesystem_tools: Утилиты для работы с локальной файловой системой
"""

from .image_manager import ImageManager, get_image_manager
from .extract_fs import extract_image_fs
from .image_tools import (
    open_disk_image,
    close_disk_image,
    get_os_info,
    read_file_from_image,
    list_directory_in_image,
    extract_file_from_image,
    get_file_metadata_from_image,
    search_in_image_files,
)
from .artifact_tools import (
    collect_os_info,
    collect_users_info,
    collect_command_history,
    clean_command_history,
    collect_services_info,
    collect_cron_info,
    collect_packages_info,
    collect_docker_info,
    collect_ssh_artifacts,
    collect_network_config,
    collect_auth_logs,
    collect_logs_info,
    extract_log_file,
    extract_home_files,
    clear_tool_cache,
    scan_home_files_for_malware,
    read_home_files_for_analysis,
)
from .analysis_tools import (
    extract_entities_from_text,
    parse_passwd_file,
    parse_services_list,
    generate_file_ioc,
    analyze_triage_data,
    generate_html_report,
)
from .filesystem_tools import (
    calculate_file_hashes,
    get_local_file_metadata,
    read_local_file,
    write_local_file,
    list_local_directory,
    search_in_local_files,
)
from .investigation_tools import (
    extract_public_ips,
    parse_ssh_successful_logins,
    get_investigation_context,
    record_finding,
    record_explored_path,
    get_investigation_store,
    InvestigationStore,
)
from .log_analyzers import (
    analyze_utmp_logs,
    analyze_auth_logs_detailed,
    analyze_lastlog,
    analyze_dpkg_logs,
    analyze_history_commands,
    analyze_alternatives_logs,
    clear_log_analyzer_cache,
)

__all__ = [
    # Image Manager
    'ImageManager',
    'get_image_manager',
    'extract_image_fs',
    
    # Image Tools
    'open_disk_image',
    'close_disk_image',
    'get_os_info',
    'read_file_from_image',
    'list_directory_in_image',
    'extract_file_from_image',
    'get_file_metadata_from_image',
    'search_in_image_files',
    
    # Artifact Tools
    'collect_os_info',
    'collect_users_info',
    'collect_command_history',
    'clean_command_history',
    'collect_services_info',
    'collect_cron_info',
    'collect_packages_info',
    'collect_docker_info',
    'collect_ssh_artifacts',
    'collect_network_config',
    'collect_auth_logs',
    'collect_logs_info',
    'extract_log_file',
    'extract_home_files',
    'clear_tool_cache',
    'scan_home_files_for_malware',
    'read_home_files_for_analysis',
    
    # Analysis Tools
    'extract_entities_from_text',
    'parse_passwd_file',
    'parse_services_list',
    'generate_file_ioc',
    'analyze_triage_data',
    'generate_html_report',
    
    # Filesystem Tools
    'calculate_file_hashes',
    'get_local_file_metadata',
    'read_local_file',
    'write_local_file',
    'list_local_directory',
    'search_in_local_files',
    
    # Investigation Tools (Deep Agent)
    'extract_public_ips',
    'parse_ssh_successful_logins',
    'get_investigation_context',
    'record_finding',
    'record_explored_path',
    'get_investigation_store',
    'InvestigationStore',

    # Log Analyzers
    'analyze_utmp_logs',
    'analyze_auth_logs_detailed',
    'analyze_lastlog',
    'analyze_dpkg_logs',
    'analyze_history_commands',
    'analyze_alternatives_logs',
    'clear_log_analyzer_cache',
]
