"""
Filesystem utility functions for forensic toolkit.

Утилиты для работы с файловой системой:
- Расчёт хешей файлов (MD5, SHA1, SHA256)
- Получение метаданных файлов
- Безопасное чтение/запись файлов
"""

import os
import hashlib
from pathlib import Path
from typing import Optional, Dict, Tuple
from datetime import datetime


class FileSystemUtils:
    """
    Утилитарный класс для операций с файловой системой.
    
    Предоставляет статические методы для:
    - Расчёта хешей файлов
    - Получения метаданных файлов
    - Безопасного чтения/записи файлов
    - Создания директорий
    """
    
    @staticmethod
    def calculate_hashes(file_path: Path) -> Dict[str, str]:
        """
        Вычислить MD5, SHA1 и SHA256 хеши файла.
        
        Используется для создания IOC (Indicators of Compromise) и 
        идентификации файлов по их содержимому.
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Словарь с типами хешей как ключами и значениями хешей как значениями.
            Пример: {'md5': 'abc123...', 'sha1': 'def456...', 'sha256': 'ghi789...'}
            
        Raises:
            IOError: Если произошла ошибка при чтении файла
        """
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {
                'md5': hashes['md5'].hexdigest(),
                'sha1': hashes['sha1'].hexdigest(),
                'sha256': hashes['sha256'].hexdigest()
            }
        except Exception as e:
            raise IOError(f"Error calculating hashes for {file_path}: {e}")
    
    @staticmethod
    def get_file_metadata(file_path: Path) -> Dict:
        """
        Получить метаданные файла, включая временные метки и размер.
        
        Полезно для анализа timeline и определения времени создания/изменения файлов.
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Словарь с метаданными файла:
            - name: имя файла
            - size: размер в байтах
            - created: время создания (ISO формат)
            - modified: время изменения (ISO формат)
            - accessed: время последнего доступа (ISO формат)
            
        Raises:
            IOError: Если произошла ошибка при получении метаданных
        """
        try:
            stat = file_path.stat()
            return {
                'name': file_path.name,
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
            }
        except Exception as e:
            raise IOError(f"Error getting metadata for {file_path}: {e}")
    
    @staticmethod
    def ensure_directory(directory: Path) -> Path:
        """
        Убедиться, что директория существует, создать при необходимости.
        
        Args:
            directory: Путь к директории
            
        Returns:
            Path объект директории
        """
        directory.mkdir(parents=True, exist_ok=True)
        return directory
    
    @staticmethod
    def safe_write(file_path: Path, content: str, mode: str = 'w') -> bool:
        """
        Безопасно записать содержимое в файл.
        
        Автоматически создаёт родительские директории при необходимости.
        
        Args:
            file_path: Путь к файлу
            content: Содержимое для записи
            mode: Режим записи ('w' - перезапись, 'a' - добавление)
            
        Returns:
            True если запись успешна
            
        Raises:
            IOError: Если произошла ошибка при записи
        """
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, mode, encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            raise IOError(f"Error writing to {file_path}: {e}")
    
    @staticmethod
    def safe_read(file_path: Path) -> Optional[str]:
        """
        Безопасно прочитать содержимое файла.
        
        Обрабатывает ошибки кодировки и возвращает None при ошибках.
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Содержимое файла или None при ошибке
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return None
