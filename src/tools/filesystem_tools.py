"""
Filesystem Tools - Инструменты для работы с локальной файловой системой.

Этот модуль содержит LangChain tools для:
- Вычисления хешей файлов
- Получения метаданных файлов
- Чтения/записи локальных файлов
- Листинга локальных директорий
- Поиска по содержимому файлов

Эти tools работают с ЛОКАЛЬНОЙ файловой системой,
а не с образом диска. Используйте их для работы с
извлечёнными файлами и генерации отчётов.
"""

import json
import re
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from langchain_core.tools import tool

from src.utils.logger import get_logger
from src.utils.filesystem import FileSystemUtils

logger = get_logger("FilesystemTools")
fs_utils = FileSystemUtils()


@tool
def calculate_file_hashes(file_path: str) -> str:
    """
    Вычислить криптографические хеши файла (MD5, SHA1, SHA256).
    
    Используется для:
    - Создания IOC (Indicators of Compromise)
    - Идентификации файлов по содержимому
    - Проверки целостности файлов
    - Поиска вредоносных файлов по известным хешам
    
    ВАЖНО: Работает с файлами в ЛОКАЛЬНОЙ файловой системе.
    Для работы с файлами из образа диска сначала извлеките их
    с помощью extract_file_from_image().
    
    Args:
        file_path: Путь к файлу в локальной файловой системе.
                  Пример: "extracted/etc_passwd" или "/tmp/suspicious.bin"
    
    Returns:
        JSON строка с хешами:
        - success: True если хеши вычислены
        - file_path: Путь к файлу
        - md5: MD5 хеш (32 символа)
        - sha1: SHA1 хеш (40 символов)
        - sha256: SHA256 хеш (64 символа)
        - size: Размер файла в байтах
        
    Example:
        >>> calculate_file_hashes("extracted/usr_local_bin_backdoor")
        '{"success": true, "md5": "d41d8cd98f00b204e9800998ecf8427e", "sha256": "e3b0c442...", ...}'
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
        hashes = fs_utils.calculate_hashes(path)
        size = path.stat().st_size
        
        result = {
            "success": True,
            "file_path": str(path),
            "md5": hashes['md5'],
            "sha1": hashes['sha1'],
            "sha256": hashes['sha256'],
            "size": size
        }
        
        logger.info(f"calculate_file_hashes: {path.name} - MD5: {hashes['md5'][:16]}...")
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error calculating hashes: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "file_path": file_path
        }, ensure_ascii=False)


@tool
def get_local_file_metadata(file_path: str) -> str:
    """
    Получить метаданные локального файла (размер, временные метки).
    
    Извлекает:
    - Имя файла
    - Размер в байтах
    - Время создания (ctime)
    - Время изменения (mtime)
    - Время последнего доступа (atime)
    
    Используется для:
    - Анализа timeline
    - Определения времени создания/изменения файлов
    - Выявления временных аномалий
    
    ВАЖНО: Работает с файлами в ЛОКАЛЬНОЙ файловой системе.
    
    Args:
        file_path: Путь к файлу в локальной файловой системе.
    
    Returns:
        JSON строка с метаданными:
        - success: True если метаданные получены
        - name: Имя файла
        - size: Размер в байтах
        - created: Время создания (ISO формат)
        - modified: Время изменения (ISO формат)
        - accessed: Время последнего доступа (ISO формат)
        
    Example:
        >>> get_local_file_metadata("extracted/var_log_auth.log")
        '{"success": true, "name": "var_log_auth.log", "size": 12345, "modified": "2024-01-15T10:30:00"}'
    """
    path = Path(file_path)
    
    if not path.exists():
        return json.dumps({
            "success": False,
            "error": f"File not found: {file_path}",
            "file_path": file_path
        }, ensure_ascii=False)
    
    try:
        metadata = fs_utils.get_file_metadata(path)
        
        result = {
            "success": True,
            "file_path": str(path),
            **metadata
        }
        
        logger.debug(f"get_local_file_metadata: {path}")
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error getting metadata: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "file_path": file_path
        }, ensure_ascii=False)


@tool
def read_local_file(file_path: str, encoding: str = "utf-8") -> str:
    """
    Прочитать содержимое локального файла.
    
    Используется для:
    - Чтения извлечённых файлов
    - Чтения конфигураций и отчётов
    - Анализа текстовых артефактов
    
    ВАЖНО: Работает с файлами в ЛОКАЛЬНОЙ файловой системе.
    Для чтения файлов из образа диска используйте read_file_from_image().
    
    Args:
        file_path: Путь к файлу в локальной файловой системе.
        encoding: Кодировка файла (по умолчанию utf-8).
    
    Returns:
        JSON строка с содержимым:
        - success: True если файл прочитан
        - content: Содержимое файла
        - size: Размер в байтах
        - file_path: Путь к файлу
        
    Example:
        >>> read_local_file("extracted/etc_passwd")
        '{"success": true, "content": "root:x:0:0:root:/root:/bin/bash\\n...", "size": 1234}'
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
        content = fs_utils.safe_read(path)
        
        if content is not None:
            result = {
                "success": True,
                "file_path": str(path),
                "content": content,
                "size": len(content)
            }
        else:
            result = {
                "success": False,
                "error": "Could not read file",
                "file_path": str(path)
            }
        
        logger.debug(f"read_local_file: {path}")
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "file_path": file_path
        }, ensure_ascii=False)


@tool
def write_local_file(file_path: str, content: str, append: bool = False) -> str:
    """
    Записать содержимое в локальный файл.
    
    Используется для:
    - Сохранения результатов анализа
    - Создания отчётов
    - Экспорта данных
    
    ВАЖНО: 
    - Автоматически создаёт родительские директории
    - Перезаписывает существующий файл (если append=False)
    - Добавляет к существующему файлу (если append=True)
    
    Args:
        file_path: Путь для сохранения файла.
                  Пример: "reports/analysis.json" или "extracted/notes.txt"
        content: Содержимое для записи.
        append: Если True, добавить к существующему файлу.
               Если False (по умолчанию), перезаписать файл.
    
    Returns:
        JSON строка с результатом:
        - success: True если файл записан
        - file_path: Путь к файлу
        - size: Размер записанных данных
        - mode: 'append' или 'write'
        
    Example:
        >>> write_local_file("reports/iocs.json", '{"ips": ["1.2.3.4"]}')
        '{"success": true, "file_path": "reports/iocs.json", "size": 23, "mode": "write"}'
    """
    # Защита от абсолютных путей (AI может передать /analysis и т.п.)
    if file_path.startswith('/'):
        logger.warning(f"Absolute file_path '{file_path}' rejected, using safe relative path")
        safe_name = file_path.replace('/', '_').lstrip('_')
        file_path = f"output/{safe_name}"
    
    path = Path(file_path)
    mode = 'a' if append else 'w'
    
    try:
        fs_utils.safe_write(path, content, mode=mode)
        
        result = {
            "success": True,
            "file_path": str(path),
            "size": len(content),
            "mode": "append" if append else "write"
        }
        
        logger.info(f"write_local_file: {path} ({len(content)} bytes, {result['mode']})")
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error writing file: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "file_path": file_path
        }, ensure_ascii=False)


@tool
def list_local_directory(dir_path: str, recursive: bool = False) -> str:
    """
    Получить список файлов и директорий в локальной директории.
    
    Используется для:
    - Просмотра извлечённых файлов
    - Навигации по локальной файловой системе
    - Поиска артефактов
    
    ВАЖНО: Работает с ЛОКАЛЬНОЙ файловой системой.
    Для листинга директорий в образе диска используйте list_directory_in_image().
    
    Args:
        dir_path: Путь к директории.
                 Пример: "extracted" или "reports"
        recursive: Если True, выполнить рекурсивный обход.
                  Если False (по умолчанию), только текущий уровень.
    
    Returns:
        JSON строка со списком:
        - success: True если директория прочитана
        - path: Путь к директории
        - count: Количество элементов
        - entries: Список элементов с информацией:
            - name: Имя
            - path: Полный путь
            - type: 'file' или 'directory'
            - size: Размер (для файлов)
            
    Example:
        >>> list_local_directory("extracted")
        '{"success": true, "count": 15, "entries": [{"name": "etc_passwd", "type": "file", "size": 1234}, ...]}'
    """
    path = Path(dir_path)
    
    if not path.exists():
        return json.dumps({
            "success": False,
            "error": f"Directory not found: {dir_path}",
            "path": dir_path
        }, ensure_ascii=False)
    
    if not path.is_dir():
        return json.dumps({
            "success": False,
            "error": f"Not a directory: {dir_path}",
            "path": dir_path
        }, ensure_ascii=False)
    
    try:
        entries = []
        
        if recursive:
            for item in path.rglob('*'):
                entry = {
                    "name": item.name,
                    "path": str(item),
                    "type": "directory" if item.is_dir() else "file"
                }
                if item.is_file():
                    entry["size"] = item.stat().st_size
                entries.append(entry)
        else:
            for item in path.iterdir():
                entry = {
                    "name": item.name,
                    "path": str(item),
                    "type": "directory" if item.is_dir() else "file"
                }
                if item.is_file():
                    entry["size"] = item.stat().st_size
                entries.append(entry)
        
        # Сортируем: сначала директории, потом файлы
        entries.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))
        
        result = {
            "success": True,
            "path": str(path),
            "count": len(entries),
            "entries": entries
        }
        
        logger.debug(f"list_local_directory: {path} - {len(entries)} entries")
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error listing directory: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "path": dir_path
        }, ensure_ascii=False)


@tool
def search_in_local_files(directory: str, pattern: str, file_extension: Optional[str] = None) -> str:
    """
    Поиск по содержимому файлов в локальной директории (grep-подобный).
    
    Ищет указанный паттерн (регулярное выражение) во всех файлах
    указанной директории и возвращает совпадения с контекстом.
    
    Используется для:
    - Поиска подозрительных строк в логах
    - Нахождения IP-адресов, доменов, команд
    - Выявления паттернов атак
    
    ВАЖНО: 
    - Работает с ЛОКАЛЬНОЙ файловой системой
    - Поддерживает регулярные выражения
    - Ограничивает количество результатов для производительности
    
    Args:
        directory: Директория для поиска.
                  Пример: "extracted" или "reports"
        pattern: Регулярное выражение для поиска.
                Пример: "192\\.168\\.1\\." или "wget|curl|nc"
        file_extension: Опциональное расширение файлов для фильтрации.
                       Пример: ".txt" или ".log"
    
    Returns:
        JSON строка с результатами:
        - success: True если поиск выполнен
        - pattern: Искомый паттерн
        - matches: Список совпадений:
            - file: Путь к файлу
            - line_number: Номер строки
            - line: Содержимое строки
            - match: Найденное совпадение
        - total_matches: Общее количество совпадений
        - files_searched: Количество проверенных файлов
        
    Example:
        >>> search_in_local_files("extracted", "Failed password", ".log")
        '{"success": true, "total_matches": 15, "matches": [{"file": "extracted/var_log_auth.log", "line": "Jan 15 Failed password for root", ...}]}'
    """
    dir_path = Path(directory)
    
    if not dir_path.exists():
        return json.dumps({
            "success": False,
            "error": f"Directory not found: {directory}",
            "directory": directory
        }, ensure_ascii=False)
    
    if not dir_path.is_dir():
        return json.dumps({
            "success": False,
            "error": f"Not a directory: {directory}",
            "directory": directory
        }, ensure_ascii=False)
    
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
    max_matches = 100  # Ограничение для производительности
    
    try:
        for file_path in dir_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Фильтр по расширению
            if file_extension and not file_path.suffix == file_extension:
                continue
            
            files_searched += 1
            
            # Пропускаем бинарные файлы
            try:
                content = fs_utils.safe_read(file_path)
                if content is None:
                    continue
            except Exception:
                continue
            
            # Ищем паттерн
            for line_num, line in enumerate(content.split('\n'), 1):
                match = regex.search(line)
                if match:
                    matches.append({
                        "file": str(file_path),
                        "line_number": line_num,
                        "line": line[:500],  # Ограничиваем длину строки
                        "match": match.group()
                    })
                    
                    if len(matches) >= max_matches:
                        break
            
            if len(matches) >= max_matches:
                break
        
        result = {
            "success": True,
            "pattern": pattern,
            "directory": str(dir_path),
            "total_matches": len(matches),
            "files_searched": files_searched,
            "matches": matches,
            "truncated": len(matches) >= max_matches
        }
        
        logger.info(f"search_in_local_files: found {len(matches)} matches in {files_searched} files")
        return json.dumps(result, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error searching files: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "directory": directory,
            "pattern": pattern
        }, ensure_ascii=False)
