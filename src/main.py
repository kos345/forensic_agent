"""
Forseti Forensic Agent - Главная точка входа.

Полный пайплайн обработки образа диска:
1. Preprocessing: определение типа, конвертация в RAW
2. Открытие образа для агентских tools
3. Запуск AI-агента для анализа (когда будет реализован)
4. Генерация отчёта

Использование:
    python -m src.main --image /path/to/disk.img
    python -m src.main --image /path/to/disk.vmdk --output-dir ./converted
"""

import argparse
import sys
import json
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

from src.utils.logger import get_logger
from src.preprocessing.image_processor import ImageProcessor, prepare_image
from src.tools.image_manager import get_image_manager


@dataclass
class PipelineConfig:
    """Конфигурация пайплайна."""
    image_path: Path
    output_dir: Optional[Path] = None
    log_dir: str = "logs"
    calculate_hashes: bool = False
    validate_image: bool = True
    auto_open: bool = True


@dataclass  
class PipelineResult:
    """Результат выполнения пайплайна."""
    success: bool
    image_path: Path
    raw_path: Optional[Path]
    image_format: str
    image_size: str
    os_info: Optional[Dict] = None
    is_ready_for_agent: bool = False
    error: Optional[str] = None
    metadata: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return {
            'success': self.success,
            'image_path': str(self.image_path),
            'raw_path': str(self.raw_path) if self.raw_path else None,
            'image_format': self.image_format,
            'image_size': self.image_size,
            'os_info': self.os_info,
            'is_ready_for_agent': self.is_ready_for_agent,
            'error': self.error,
            'metadata': self.metadata
        }


class ForensicPipeline:
    """
    Пайплайн подготовки образа для AI-агента.
    
    Выполняет все необходимые шаги перед запуском агента:
    1. Валидация и определение типа образа
    2. Конвертация в RAW (если необходимо)
    3. Открытие образа через ImageManager
    4. Определение ОС
    5. Подготовка контекста для агента
    """
    
    def __init__(self, config: PipelineConfig):
        """
        Инициализация пайплайна.
        
        Args:
            config: Конфигурация пайплайна
        """
        self.config = config
        self.logger = get_logger("ForensicPipeline", config.log_dir)
        self.image_processor = ImageProcessor(config.log_dir)
        self.image_manager = get_image_manager()
    
    def run(self) -> PipelineResult:
        """
        Выполнить полный пайплайн подготовки.
        
        Returns:
            PipelineResult с результатом выполнения
        """
        self.logger.info("=" * 60)
        self.logger.info("Starting Forensic Pipeline")
        self.logger.info(f"Image: {self.config.image_path}")
        self.logger.info("=" * 60)
        
        # Проверяем существование файла
        if not self.config.image_path.exists():
            return PipelineResult(
                success=False,
                image_path=self.config.image_path,
                raw_path=None,
                image_format="unknown",
                image_size="0 B",
                error=f"Image file not found: {self.config.image_path}"
            )
        
        # ========== ЭТАП 1: Подготовка образа ==========
        self.logger.info("[1/4] Preparing image...")
        
        metadata = self.image_processor.prepare_for_analysis(
            self.config.image_path,
            output_dir=self.config.output_dir,
            calculate_hashes=self.config.calculate_hashes
        )
        
        if metadata.error:
            return PipelineResult(
                success=False,
                image_path=self.config.image_path,
                raw_path=None,
                image_format=metadata.format.value,
                image_size=metadata.size_human,
                error=metadata.error,
                metadata=metadata.to_dict()
            )
        
        self.logger.info(f"  Format: {metadata.format.value}")
        self.logger.info(f"  Size: {metadata.size_human}")
        self.logger.info(f"  RAW path: {metadata.raw_path}")
        
        if metadata.conversion_done:
            self.logger.info("  [✓] Converted to RAW")
        elif metadata.is_raw:
            self.logger.info("  [✓] Already in RAW format")
        
        # ========== ЭТАП 2: Валидация для pytsk3 ==========
        self.logger.info("[2/4] Validating for pytsk3...")
        
        if self.config.validate_image and metadata.raw_path:
            is_valid, validation_error = self.image_processor.validate_for_pytsk3(
                metadata.raw_path
            )
            
            if not is_valid:
                self.logger.warning(f"  Validation warning: {validation_error}")
                # Не прерываем, агент может попробовать разные offset
            else:
                self.logger.info("  [✓] Valid filesystem detected")
        
        # ========== ЭТАП 3: Открытие образа ==========
        os_info = None
        if self.config.auto_open and metadata.raw_path:
            self.logger.info("[3/4] Opening image...")
            
            result = self.image_manager.open_image(str(metadata.raw_path))
            
            if not result.get('success'):
                return PipelineResult(
                    success=False,
                    image_path=self.config.image_path,
                    raw_path=metadata.raw_path,
                    image_format=metadata.format.value,
                    image_size=metadata.size_human,
                    error=f"Failed to open image: {result.get('error')}",
                    metadata=metadata.to_dict()
                )
            
            self.logger.info(f"  [✓] Image opened successfully")
            
            # ========== ЭТАП 4: Определение ОС ==========
            self.logger.info("[4/4] Detecting OS...")
            
            os_info = self._detect_os()
            if os_info:
                self.logger.info(f"  OS: {os_info.get('os_name', 'unknown')}")
                self.logger.info(f"  Is Linux: {os_info.get('is_linux', False)}")
            else:
                self.logger.warning("  Could not detect OS")
        else:
            self.logger.info("[3/4] Skipping image open (auto_open=False)")
            self.logger.info("[4/4] Skipping OS detection")
        
        # ========== РЕЗУЛЬТАТ ==========
        self.logger.info("=" * 60)
        self.logger.info("[✓] Pipeline completed successfully")
        self.logger.info("    Image is ready for agent analysis")
        self.logger.info("=" * 60)
        
        return PipelineResult(
            success=True,
            image_path=self.config.image_path,
            raw_path=metadata.raw_path,
            image_format=metadata.format.value,
            image_size=metadata.size_human,
            os_info=os_info,
            is_ready_for_agent=True,
            metadata=metadata.to_dict()
        )
    
    def _detect_os(self) -> Optional[Dict]:
        """Определить ОС в образе."""
        result = {
            "os_name": None,
            "os_release": None,
            "issue": None,
            "is_linux": False
        }
        
        # Читаем /etc/os-release
        os_release = self.image_manager.read_file('/etc/os-release')
        if os_release:
            result["os_release"] = os_release
            for line in os_release.split('\n'):
                if line.startswith('ID='):
                    result["os_name"] = line.split('=')[1].strip().strip('"').lower()
                    result["is_linux"] = True
                    break
        
        # Читаем /etc/issue как fallback
        issue = self.image_manager.read_file('/etc/issue')
        if issue:
            result["issue"] = issue
            if 'linux' in issue.lower() and not result["is_linux"]:
                result["is_linux"] = True
                result["os_name"] = "linux"
        
        return result if result["os_name"] else None
    
    def cleanup(self):
        """Очистить ресурсы (закрыть образ)."""
        if self.image_manager.is_open:
            self.image_manager.close_image()
            self.logger.info("Image closed")


def run_pipeline(
    image_path: str,
    output_dir: str = None,
    calculate_hashes: bool = False,
    auto_open: bool = True,
    log_dir: str = "logs"
) -> Dict[str, Any]:
    """
    Удобная функция для запуска пайплайна.
    
    Args:
        image_path: Путь к образу диска
        output_dir: Директория для RAW файла
        calculate_hashes: Вычислять хеши
        auto_open: Автоматически открыть образ
        log_dir: Директория для логов
        
    Returns:
        Словарь с результатом пайплайна
    """
    config = PipelineConfig(
        image_path=Path(image_path),
        output_dir=Path(output_dir) if output_dir else None,
        log_dir=log_dir,
        calculate_hashes=calculate_hashes,
        auto_open=auto_open
    )
    
    pipeline = ForensicPipeline(config)
    result = pipeline.run()
    
    return result.to_dict()


def get_agent_context() -> Dict[str, Any]:
    """
    Получить контекст для запуска агента.
    
    Возвращает информацию о текущем состоянии:
    - Открыт ли образ
    - Путь к образу
    - Информация об ОС
    - Доступные tools
    
    Returns:
        Словарь с контекстом для агента
    """
    manager = get_image_manager()
    
    context = {
        "image_open": manager.is_open,
        "image_path": manager.image_path,
        "os_info": None,
        "available_tools": [
            # Image Tools
            "open_disk_image",
            "close_disk_image", 
            "get_os_info",
            "read_file_from_image",
            "list_directory_in_image",
            "extract_file_from_image",
            "get_file_metadata_from_image",
            
            # Artifact Tools
            "collect_os_info",
            "collect_users_info",
            "collect_command_history",
            "clean_command_history",
            "collect_services_info",
            "collect_cron_info",
            "collect_packages_info",
            "collect_docker_info",
            "collect_ssh_artifacts",
            "collect_network_config",
            "collect_auth_logs",
            "collect_logs_info",
            "extract_log_file",
            "extract_home_files",
            
            # Analysis Tools
            "extract_entities_from_text",
            "parse_passwd_file",
            "parse_services_list",
            "generate_file_ioc",
            "analyze_triage_data",
            "generate_html_report",
            
            # Filesystem Tools
            "calculate_file_hashes",
            "get_local_file_metadata",
            "read_local_file",
            "write_local_file",
            "list_local_directory",
            "search_in_local_files",
        ]
    }
    
    # Добавляем информацию об ОС если образ открыт
    if manager.is_open:
        os_release = manager.read_file('/etc/os-release')
        if os_release:
            for line in os_release.split('\n'):
                if line.startswith('ID='):
                    context["os_info"] = {
                        "os_name": line.split('=')[1].strip().strip('"').lower(),
                        "is_linux": True
                    }
                    break
    
    return context


def main():
    """CLI точка входа."""
    parser = argparse.ArgumentParser(
        description='Forseti Forensic Agent - Image Preparation Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Подготовить RAW образ
  python -m src.main --image disk.raw
  
  # Конвертировать VMDK в RAW и подготовить
  python -m src.main --image disk.vmdk --output-dir ./converted
  
  # Подготовить с вычислением хешей
  python -m src.main --image disk.raw --hashes
  
  # Только подготовка, без открытия образа
  python -m src.main --image disk.raw --no-open

После подготовки образ будет открыт и готов для запуска AI-агента.
        """
    )
    
    parser.add_argument(
        '--image', '-i',
        type=str,
        required=True,
        help='Путь к образу диска (raw, vmdk, qcow2, vdi, vhd)'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        type=str,
        default=None,
        help='Директория для конвертированного RAW файла'
    )
    
    parser.add_argument(
        '--hashes',
        action='store_true',
        help='Вычислить хеши образа (MD5, SHA1, SHA256)'
    )
    
    parser.add_argument(
        '--no-open',
        action='store_true',
        help='Не открывать образ автоматически'
    )
    
    parser.add_argument(
        '--log-dir',
        type=str,
        default='logs',
        help='Директория для логов (default: logs)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Вывести результат в формате JSON'
    )
    
    args = parser.parse_args()
    
    # Проверяем путь к образу
    image_path = Path(args.image)
    if not image_path.exists():
        print(f"Error: Image file not found: {image_path}")
        sys.exit(1)
    
    # Создаём конфигурацию
    config = PipelineConfig(
        image_path=image_path,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        log_dir=args.log_dir,
        calculate_hashes=args.hashes,
        auto_open=not args.no_open
    )
    
    # Запускаем пайплайн
    pipeline = ForensicPipeline(config)
    
    try:
        result = pipeline.run()
        
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        else:
            print()
            if result.success:
                print("✓ Pipeline completed successfully!")
                print(f"  Image: {result.image_path}")
                print(f"  Format: {result.image_format}")
                print(f"  Size: {result.image_size}")
                if result.raw_path and result.raw_path != result.image_path:
                    print(f"  RAW path: {result.raw_path}")
                if result.os_info:
                    print(f"  OS: {result.os_info.get('os_name', 'unknown')}")
                print()
                print("  Image is ready for agent analysis.")
                print("  Agent tools are available via src.tools module.")
            else:
                print("✗ Pipeline failed!")
                print(f"  Error: {result.error}")
        
        sys.exit(0 if result.success else 1)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        pipeline.cleanup()
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        pipeline.cleanup()
        sys.exit(1)


if __name__ == '__main__':
    main()
