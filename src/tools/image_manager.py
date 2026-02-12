"""
Image Manager - Менеджер для работы с образом диска.

Этот модуль предоставляет singleton-класс для управления открытым образом диска.
Все tools для работы с образом используют этот менеджер для доступа к файловой системе.

Почему singleton:
- Образ диска должен быть открыт один раз и использоваться всеми tools
- pytsk3 handles должны быть сохранены между вызовами tools
- Конфигурация загружается один раз при инициализации
"""

import pytsk3
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from src.utils.logger import get_logger
from src.utils.filesystem import FileSystemUtils


class ImageManager:
    """
    Singleton-менеджер для работы с образом диска.
    
    Хранит состояние открытого образа и предоставляет методы для:
    - Открытия/закрытия образа
    - Чтения файлов из образа
    - Листинга директорий
    - Получения метаданных файлов
    
    Attributes:
        image_path: Путь к открытому образу диска
        image_handle: pytsk3 handle образа
        fs_handle: pytsk3 handle файловой системы
        config: Загруженная конфигурация из triage.yaml
        is_open: Флаг, указывающий открыт ли образ
    """
    
    _instance = None
    
    def __new__(cls):
        """Реализация singleton паттерна."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config_path: str = "configs/triage.yaml", log_dir: str = "logs"):
        """
        Инициализация ImageManager.
        
        Args:
            config_path: Путь к файлу конфигурации triage.yaml
            log_dir: Директория для логов
        """
        if self._initialized:
            return
            
        self.logger = get_logger(self.__class__.__name__, log_dir)
        self.fs_utils = FileSystemUtils()
        self.config = self._load_config(config_path)
        
        self.image_path: Optional[Path] = None
        self.image_handle = None
        self.fs_handle = None
        self.is_open: bool = False
        
        self._initialized = True
        self.logger.info("ImageManager initialized")
    
    def _load_config(self, config_path: str) -> Dict:
        """
        Загрузить конфигурацию из YAML файла.
        
        Args:
            config_path: Путь к файлу конфигурации
            
        Returns:
            Словарь с конфигурацией
        """
        try:
            config_file = Path(config_path)
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {}
                    self.logger.info(f"Config loaded from: {config_path}")
                    return config
            else:
                self.logger.warning(f"Config file not found: {config_path}, using defaults")
                return self._get_default_config()
        except Exception as e:
            self.logger.error(f"Error loading config: {e}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Получить конфигурацию по умолчанию."""
        return {
            'artifacts': {
                'system': ['/etc/os-release', '/etc/issue'],
                'users': ['/etc/passwd', '/etc/shadow'],
                'history': ['/home/*/.bash_history', '/root/.bash_history'],
                'services': ['/etc/systemd/system', '/etc/init.d'],
                'cron': ['/etc/crontab', '/var/spool/cron'],
                'packages': ['/var/lib/dpkg/status'],
                'logs': {
                    'var': ['/var/log'],
                    'www': ['/var/www']
                },
                'docker': ['/var/lib/docker']
            },
            'settings': {
                'max_files_per_directory': 200,
                'max_log_files': 100
            }
        }
    
    def open_image(self, image_path: str) -> Dict[str, Any]:
        """
        Открыть образ диска для анализа.
        
        Поддерживает как RAW образы разделов, так и полные образы дисков
        с таблицами разделов (MBR/GPT).
        
        Args:
            image_path: Путь к образу диска (RAW формат)
            
        Returns:
            Словарь с результатом:
            - success: True/False
            - message: Описание результата
            - image_path: Путь к образу (если успешно)
        """
        try:
            self.logger.info(f"Opening image: {image_path}")
            
            # Закрыть предыдущий образ если открыт
            if self.is_open:
                self.close_image()
            
            path = Path(image_path)
            if not path.exists():
                return {
                    "success": False,
                    "message": f"Image file not found: {image_path}"
                }
            
            self.image_handle = pytsk3.Img_Info(str(path))
            
            # Попробовать прямой доступ к файловой системе (для образов разделов)
            try:
                self.fs_handle = pytsk3.FS_Info(self.image_handle)
                self.image_path = path
                self.is_open = True
                self.logger.info("Image opened successfully (direct filesystem)")
                return {
                    "success": True,
                    "message": "Image opened successfully (direct filesystem access)",
                    "image_path": str(path)
                }
            except Exception:
                pass
            
            # Попробовать прочитать таблицу разделов (для полных образов дисков)
            try:
                vol_info = pytsk3.Volume_Info(self.image_handle)
                
                # Найти раздел с файловой системой
                for partition in vol_info:
                    if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        offset = partition.start * 512  # размер сектора
                        try:
                            self.fs_handle = pytsk3.FS_Info(self.image_handle, offset=offset)
                            self.image_path = path
                            self.is_open = True
                            self.logger.info(f"Filesystem found at partition {partition.addr}, offset {offset}")
                            return {
                                "success": True,
                                "message": f"Image opened successfully (partition at offset {offset})",
                                "image_path": str(path),
                                "partition_offset": offset
                            }
                        except Exception:
                            continue
                            
            except Exception:
                pass
            
            self.logger.error("Could not open image: no valid filesystem found")
            return {
                "success": False,
                "message": "Could not open image: no valid filesystem found"
            }
            
        except Exception as e:
            self.logger.exception(f"Error opening image: {e}")
            return {
                "success": False,
                "message": f"Error opening image: {str(e)}"
            }
    
    def close_image(self) -> Dict[str, Any]:
        """
        Закрыть текущий образ диска.
        
        Returns:
            Словарь с результатом операции
        """
        try:
            self.fs_handle = None
            self.image_handle = None
            self.image_path = None
            self.is_open = False
            self.logger.info("Image closed")
            return {
                "success": True,
                "message": "Image closed successfully"
            }
        except Exception as e:
            self.logger.exception(f"Error closing image: {e}")
            return {
                "success": False,
                "message": f"Error closing image: {str(e)}"
            }
    
    def read_file(self, file_path: str) -> Optional[str]:
        """
        Прочитать файл из образа диска.
        
        Args:
            file_path: Путь к файлу внутри образа (например, '/etc/passwd')
            
        Returns:
            Содержимое файла как строка или None при ошибке
        """
        if not self.is_open:
            self.logger.error("Image not open")
            return None
            
        try:
            file_obj = self.fs_handle.open(file_path)
            if file_obj:
                size = file_obj.info.meta.size if file_obj.info.meta else 0
                if size > 0:
                    content = file_obj.read_random(0, size)
                    return content.decode('utf-8', errors='ignore')
        except Exception as e:
            self.logger.debug(f"Could not read {file_path}: {e}")
        return None
    
    def read_file_binary(self, file_path: str) -> Optional[bytes]:
        """
        Прочитать файл из образа диска в бинарном режиме.
        
        Args:
            file_path: Путь к файлу внутри образа
            
        Returns:
            Содержимое файла как bytes или None при ошибке
        """
        if not self.is_open:
            self.logger.error("Image not open")
            return None
            
        try:
            file_obj = self.fs_handle.open(file_path)
            if file_obj:
                size = file_obj.info.meta.size if file_obj.info.meta else 0
                if size > 0:
                    return file_obj.read_random(0, size)
        except Exception as e:
            self.logger.debug(f"Could not read {file_path}: {e}")
        return None
    
    def list_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        """
        Получить список файлов в директории образа.
        
        Args:
            dir_path: Путь к директории внутри образа
            
        Returns:
            Список словарей с информацией о файлах:
            - name: имя файла
            - path: полный путь
            - type: 'file' или 'directory'
            - size: размер (для файлов)
        """
        if not self.is_open:
            self.logger.error("Image not open")
            return []
            
        files = []
        try:
            directory = self.fs_handle.open_dir(dir_path)
            if directory:
                for entry in directory:
                    name = entry.info.name.name
                    # Пропустить . и ..
                    if name in [b'.', b'..', '.', '..']:
                        continue
                    
                    # Декодировать имя если bytes
                    if isinstance(name, bytes):
                        name = name.decode('utf-8', errors='ignore')
                    
                    full_path = f"{dir_path.rstrip('/')}/{name}"
                    
                    # Определить тип
                    entry_type = 'unknown'
                    size = 0
                    if entry.info.meta:
                        if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            entry_type = 'directory'
                        elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                            entry_type = 'file'
                            size = entry.info.meta.size
                    
                    files.append({
                        'name': name,
                        'path': full_path,
                        'type': entry_type,
                        'size': size
                    })
        except Exception as e:
            self.logger.debug(f"Could not list {dir_path}: {e}")
        return files
    
    def get_file_info(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Получить информацию о файле в образе.
        
        Args:
            file_path: Путь к файлу внутри образа
            
        Returns:
            Словарь с информацией о файле или None при ошибке:
            - name: имя файла
            - path: полный путь
            - size: размер в байтах
            - type: тип (file/directory)
            - created: время создания
            - modified: время изменения
            - accessed: время доступа
        """
        if not self.is_open:
            self.logger.error("Image not open")
            return None
            
        try:
            file_obj = self.fs_handle.open(file_path)
            if file_obj and file_obj.info.meta:
                meta = file_obj.info.meta
                
                # Определить тип
                file_type = 'unknown'
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    file_type = 'directory'
                elif meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    file_type = 'file'
                
                return {
                    'name': Path(file_path).name,
                    'path': file_path,
                    'size': meta.size,
                    'type': file_type,
                    'created': meta.crtime if hasattr(meta, 'crtime') else None,
                    'modified': meta.mtime if hasattr(meta, 'mtime') else None,
                    'accessed': meta.atime if hasattr(meta, 'atime') else None,
                }
        except Exception as e:
            self.logger.debug(f"Could not get info for {file_path}: {e}")
        return None
    
    def file_exists(self, file_path: str) -> bool:
        """
        Проверить существование файла в образе.
        
        Args:
            file_path: Путь к файлу внутри образа
            
        Returns:
            True если файл существует, False иначе
        """
        if not self.is_open:
            return False
            
        try:
            file_obj = self.fs_handle.open(file_path)
            return file_obj is not None
        except Exception:
            return False
    
    def get_config(self, key: str = None) -> Any:
        """
        Получить значение из конфигурации.
        
        Args:
            key: Ключ конфигурации (например, 'artifacts.system')
                 Если None, возвращается вся конфигурация
                 
        Returns:
            Значение конфигурации
        """
        if key is None:
            return self.config
            
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return None
        return value


# Глобальный экземпляр
_image_manager: Optional[ImageManager] = None


def get_image_manager() -> ImageManager:
    """
    Получить глобальный экземпляр ImageManager.
    
    Returns:
        Singleton экземпляр ImageManager
    """
    global _image_manager
    if _image_manager is None:
        _image_manager = ImageManager()
    return _image_manager
