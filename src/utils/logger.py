"""
Logging utility module for forensic image triage toolkit.

Предоставляет централизованное логирование для всех компонентов системы.
Логи записываются как в файл, так и в консоль.
"""

import logging
import os
from pathlib import Path
from datetime import datetime
from typing import Optional


class ForensicLogger:
    """
    Централизованная утилита логирования для криминалистического тулкита.
    
    Обеспечивает логирование в файл и консоль с настраиваемыми уровнями.
    
    Attributes:
        name: Имя логгера (обычно имя модуля)
        log_dir: Директория для файлов логов
        logger: Внутренний объект logging.Logger
    """
    
    def __init__(self, name: str, log_dir: str = "logs", log_level: int = logging.INFO):
        """
        Инициализация логгера.
        
        Args:
            name: Имя логгера (обычно имя модуля или класса)
            log_dir: Директория для файлов логов
            log_level: Уровень логирования (по умолчанию: INFO)
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Настройка обработчиков для файла и консоли."""
        # File handler
        log_file = self.log_dir / "forensic.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def debug(self, message: str):
        """Записать debug сообщение."""
        self.logger.debug(message)
    
    def info(self, message: str):
        """Записать info сообщение."""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Записать warning сообщение."""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Записать error сообщение."""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Записать critical сообщение."""
        self.logger.critical(message)
    
    def exception(self, message: str):
        """Записать exception с traceback."""
        self.logger.exception(message)


def get_logger(name: str, log_dir: str = "logs") -> ForensicLogger:
    """
    Получить или создать экземпляр логгера.
    
    Args:
        name: Имя логгера
        log_dir: Путь к директории логов
        
    Returns:
        Экземпляр ForensicLogger
    """
    return ForensicLogger(name, log_dir)
