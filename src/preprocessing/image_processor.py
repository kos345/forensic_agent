"""
Image Processor - Обработка и подготовка образов дисков.

Выполняется ПЕРЕД запуском агента для подготовки образа:
1. Определение типа образа (raw, vmdk, qcow2, vdi, vhd, ...)
2. Конвертация в RAW формат с помощью qemu-img
3. Получение метаданных образа (размер, хеши, timestamps)
4. Валидация образа для работы с pytsk3

Основан на tools_src/src/core/image_processor.py.
"""

import subprocess
import os
from pathlib import Path
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

from src.utils.logger import get_logger
from src.utils.filesystem import FileSystemUtils


class ImageFormat(Enum):
    """Поддерживаемые форматы образов дисков."""
    RAW = "raw"
    DD = "dd"
    IMG = "img"
    VMDK = "vmdk"
    VDI = "vdi"
    VHD = "vhd"
    VHDX = "vhdx"
    QCOW2 = "qcow2"
    QCOW = "qcow"
    VPC = "vpc"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_extension(cls, ext: str) -> 'ImageFormat':
        """Получить формат по расширению файла."""
        ext = ext.lower().lstrip('.')
        mapping = {
            'raw': cls.RAW,
            'dd': cls.DD,
            'img': cls.IMG,
            'vmdk': cls.VMDK,
            'vdi': cls.VDI,
            'vhd': cls.VHD,
            'vhdx': cls.VHDX,
            'qcow2': cls.QCOW2,
            'qcow': cls.QCOW,
            'vpc': cls.VPC,
        }
        return mapping.get(ext, cls.UNKNOWN)
    
    def is_raw(self) -> bool:
        """Проверить, является ли формат RAW."""
        return self in (ImageFormat.RAW, ImageFormat.DD, ImageFormat.IMG)


@dataclass
class ImageMetadata:
    """Метаданные образа диска."""
    path: Path
    name: str
    format: ImageFormat
    is_raw: bool
    size: int
    size_human: str
    raw_path: Optional[Path] = None
    hashes: Optional[Dict[str, str]] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None
    conversion_needed: bool = False
    conversion_done: bool = False
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Преобразовать в словарь."""
        return {
            'path': str(self.path),
            'name': self.name,
            'format': self.format.value,
            'is_raw': self.is_raw,
            'size': self.size,
            'size_human': self.size_human,
            'raw_path': str(self.raw_path) if self.raw_path else None,
            'hashes': self.hashes,
            'created': self.created,
            'modified': self.modified,
            'accessed': self.accessed,
            'conversion_needed': self.conversion_needed,
            'conversion_done': self.conversion_done,
            'error': self.error,
        }


class ImageProcessor:
    """
    Процессор для подготовки образов дисков.
    
    Выполняет все необходимые операции для подготовки образа к анализу:
    - Определение типа образа
    - Конвертация в RAW (если нужно)
    - Получение метаданных
    """
    
    def __init__(self, log_dir: str = "logs"):
        """
        Инициализация процессора.
        
        Args:
            log_dir: Директория для логов
        """
        self.logger = get_logger(self.__class__.__name__, log_dir)
        self.fs_utils = FileSystemUtils()
    
    def detect_format(self, image_path: Path) -> ImageFormat:
        """
        Определить формат образа диска.
        
        Сначала проверяет расширение, затем использует qemu-img для точного определения.
        
        Args:
            image_path: Путь к образу диска
            
        Returns:
            ImageFormat - определённый формат образа
        """
        self.logger.info(f"Detecting image format: {image_path}")
        
        if not image_path.exists():
            self.logger.error(f"Image file not found: {image_path}")
            return ImageFormat.UNKNOWN
        
        # Проверяем по расширению
        ext = image_path.suffix.lower().lstrip('.')
        format_by_ext = ImageFormat.from_extension(ext)
        
        if format_by_ext != ImageFormat.UNKNOWN:
            self.logger.info(f"Detected format by extension: {format_by_ext.value}")
            return format_by_ext
        
        # Пробуем qemu-img для точного определения
        try:
            result = subprocess.run(
                ['qemu-img', 'info', str(image_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'file format:' in line.lower():
                        format_name = line.split(':')[-1].strip().lower()
                        detected = ImageFormat.from_extension(format_name)
                        if detected != ImageFormat.UNKNOWN:
                            self.logger.info(f"Detected format by qemu-img: {detected.value}")
                            return detected
                        # Возможно формат известен, но не в enum
                        self.logger.info(f"qemu-img detected: {format_name}")
                        return ImageFormat.RAW if format_name == 'raw' else ImageFormat.UNKNOWN
                        
        except subprocess.TimeoutExpired:
            self.logger.warning("qemu-img timeout")
        except FileNotFoundError:
            self.logger.warning("qemu-img not found")
        except Exception as e:
            self.logger.warning(f"Could not detect format using qemu-img: {e}")
        
        self.logger.warning(f"Unknown image format: {image_path}")
        return ImageFormat.UNKNOWN
    
    def is_raw(self, image_path: Path) -> bool:
        """
        Проверить, является ли образ RAW форматом.
        
        Args:
            image_path: Путь к образу
            
        Returns:
            True если образ в RAW формате
        """
        return self.detect_format(image_path).is_raw()
    
    def convert_to_raw(
        self, 
        image_path: Path, 
        output_path: Optional[Path] = None,
        timeout: int = 3600
    ) -> Tuple[bool, Optional[Path], Optional[str]]:
        """
        Конвертировать образ в RAW формат с помощью qemu-img.
        
        Args:
            image_path: Путь к исходному образу
            output_path: Путь для выходного RAW файла (опционально)
            timeout: Таймаут в секундах (по умолчанию 1 час)
            
        Returns:
            Tuple[success, raw_path, error_message]
        """
        self.logger.info(f"Converting image to RAW: {image_path}")
        
        if not image_path.exists():
            return False, None, f"Image file not found: {image_path}"
        
        # Проверяем, не RAW ли уже
        if self.is_raw(image_path):
            self.logger.info("Image is already in RAW format")
            return True, image_path, None
        
        # Определяем выходной путь
        if output_path is None:
            output_path = image_path.parent / f"{image_path.stem}.raw"
        
        self.logger.info(f"Output RAW file: {output_path}")
        
        try:
            result = subprocess.run(
                ['qemu-img', 'convert', '-f', 'auto', '-O', 'raw', 
                 str(image_path), str(output_path)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                self.logger.info(f"Successfully converted to RAW: {output_path}")
                return True, output_path, None
            else:
                error = f"Conversion failed: {result.stderr}"
                self.logger.error(error)
                return False, None, error
                
        except subprocess.TimeoutExpired:
            error = f"Conversion timeout exceeded ({timeout} seconds)"
            self.logger.error(error)
            return False, None, error
        except FileNotFoundError:
            error = "qemu-img not found. Please install QEMU tools: apt install qemu-utils"
            self.logger.error(error)
            return False, None, error
        except Exception as e:
            error = f"Conversion error: {e}"
            self.logger.exception(error)
            return False, None, error
    
    def get_metadata(
        self, 
        image_path: Path, 
        calculate_hashes: bool = True
    ) -> ImageMetadata:
        """
        Получить метаданные образа диска.
        
        Args:
            image_path: Путь к образу
            calculate_hashes: Вычислять хеши (может занять много времени)
            
        Returns:
            ImageMetadata с информацией об образе
        """
        self.logger.info(f"Getting metadata for: {image_path}")
        
        if not image_path.exists():
            return ImageMetadata(
                path=image_path,
                name=image_path.name,
                format=ImageFormat.UNKNOWN,
                is_raw=False,
                size=0,
                size_human="0 B",
                error=f"File not found: {image_path}"
            )
        
        # Определяем формат
        img_format = self.detect_format(image_path)
        is_raw = img_format.is_raw()
        
        # Получаем размер
        size = image_path.stat().st_size
        size_human = self._format_size(size)
        
        # Получаем метаданные файла
        try:
            file_meta = self.fs_utils.get_file_metadata(image_path)
            created = file_meta.get('created')
            modified = file_meta.get('modified')
            accessed = file_meta.get('accessed')
        except Exception as e:
            self.logger.warning(f"Could not get file metadata: {e}")
            created = modified = accessed = None
        
        # Вычисляем хеши (опционально)
        hashes = None
        if calculate_hashes:
            try:
                self.logger.info("Calculating hashes (this may take a while)...")
                hashes = self.fs_utils.calculate_hashes(image_path)
            except Exception as e:
                self.logger.warning(f"Could not calculate hashes: {e}")
        
        return ImageMetadata(
            path=image_path,
            name=image_path.name,
            format=img_format,
            is_raw=is_raw,
            size=size,
            size_human=size_human,
            raw_path=image_path if is_raw else None,
            hashes=hashes,
            created=created,
            modified=modified,
            accessed=accessed,
            conversion_needed=not is_raw,
        )
    
    def prepare_for_analysis(
        self,
        image_path: Path,
        output_dir: Optional[Path] = None,
        calculate_hashes: bool = False,
        force_convert: bool = False
    ) -> ImageMetadata:
        """
        Полная подготовка образа для анализа агентом.
        
        Выполняет все необходимые шаги:
        1. Получает метаданные образа
        2. Конвертирует в RAW если необходимо
        3. Валидирует результат
        
        Args:
            image_path: Путь к образу диска
            output_dir: Директория для RAW файла (опционально)
            calculate_hashes: Вычислять хеши исходного образа
            force_convert: Принудительная конвертация даже если RAW
            
        Returns:
            ImageMetadata с информацией об образе и путём к RAW версии
        """
        self.logger.info(f"Preparing image for analysis: {image_path}")
        
        # Получаем метаданные
        metadata = self.get_metadata(image_path, calculate_hashes=calculate_hashes)
        
        if metadata.error:
            return metadata
        
        # Если уже RAW и не нужна принудительная конвертация
        if metadata.is_raw and not force_convert:
            self.logger.info("Image is already in RAW format, ready for analysis")
            metadata.raw_path = image_path
            return metadata
        
        # Конвертируем в RAW
        if output_dir:
            raw_path = output_dir / f"{image_path.stem}.raw"
        else:
            raw_path = None  # будет создан рядом с исходным
        
        success, converted_path, error = self.convert_to_raw(image_path, raw_path)
        
        if success:
            metadata.raw_path = converted_path
            metadata.conversion_done = True
            self.logger.info(f"Image prepared successfully: {converted_path}")
        else:
            metadata.error = error
            self.logger.error(f"Failed to prepare image: {error}")
        
        return metadata
    
    def validate_for_pytsk3(self, raw_path: Path) -> Tuple[bool, Optional[str]]:
        """
        Валидировать RAW образ для работы с pytsk3.
        
        Проверяет, можно ли открыть образ с помощью pytsk3.
        
        Args:
            raw_path: Путь к RAW образу
            
        Returns:
            Tuple[is_valid, error_message]
        """
        self.logger.info(f"Validating image for pytsk3: {raw_path}")
        
        if not raw_path.exists():
            return False, f"File not found: {raw_path}"
        
        try:
            import pytsk3
            
            # Пробуем открыть образ
            img_info = pytsk3.Img_Info(str(raw_path))
            
            # Пробуем открыть файловую систему
            try:
                fs_info = pytsk3.FS_Info(img_info)
                self.logger.info(f"Valid filesystem found, type: {fs_info.info.ftype}")
                return True, None
            except Exception as e:
                # Возможно образ с таблицей разделов
                self.logger.warning(f"Direct FS open failed: {e}")
                
                # Пробуем с offset (пропускаем MBR/GPT)
                # Типичные offset для первого раздела: 63*512, 2048*512
                for offset in [0, 63*512, 2048*512, 1048576]:
                    try:
                        fs_info = pytsk3.FS_Info(img_info, offset=offset)
                        self.logger.info(f"Valid filesystem found at offset {offset}")
                        return True, None
                    except:
                        continue
                
                return False, f"Could not find valid filesystem: {e}"
                
        except ImportError:
            return False, "pytsk3 not installed: pip install pytsk3"
        except Exception as e:
            return False, f"Validation error: {e}"
    
    def _format_size(self, size: int) -> str:
        """Форматировать размер в человекочитаемый вид."""
        if size >= 1024**4:
            return f"{size / 1024**4:.2f} TB"
        elif size >= 1024**3:
            return f"{size / 1024**3:.2f} GB"
        elif size >= 1024**2:
            return f"{size / 1024**2:.2f} MB"
        elif size >= 1024:
            return f"{size / 1024:.2f} KB"
        else:
            return f"{size} B"


def prepare_image(
    image_path: str,
    output_dir: str = None,
    calculate_hashes: bool = False,
    validate: bool = True,
    log_dir: str = "logs"
) -> Dict:
    """
    Удобная функция для подготовки образа из CLI или других модулей.
    
    Args:
        image_path: Путь к образу диска
        output_dir: Директория для RAW файла
        calculate_hashes: Вычислять хеши
        validate: Валидировать для pytsk3
        log_dir: Директория для логов
        
    Returns:
        Словарь с результатом подготовки
    """
    processor = ImageProcessor(log_dir=log_dir)
    
    path = Path(image_path)
    out_dir = Path(output_dir) if output_dir else None
    
    # Подготавливаем образ
    metadata = processor.prepare_for_analysis(
        path,
        output_dir=out_dir,
        calculate_hashes=calculate_hashes
    )
    
    result = metadata.to_dict()
    
    # Валидируем если нужно
    if validate and metadata.raw_path and not metadata.error:
        is_valid, error = processor.validate_for_pytsk3(metadata.raw_path)
        result['pytsk3_valid'] = is_valid
        if error:
            result['validation_error'] = error
    
    return result
