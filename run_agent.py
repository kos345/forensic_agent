#!/usr/bin/env python3
"""
Forseti Forensic Agent - Скрипт запуска.

Полный пайплайн:
1. Подготовка образа (preprocessing)
2. Запуск AI-агента (GigaChat LLM)
3. Сбор артефактов и анализ
4. Генерация отчёта

Использование:
    python run_agent.py --image /path/to/disk.raw
    python run_agent.py --image /path/to/disk.vmdk --convert

Требуется .env файл с GIGACHAT_CREDENTIALS (см. .env.example)
"""

import argparse
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv('.env')


def main():
    parser = argparse.ArgumentParser(
        description='Forseti Forensic Agent - AI анализ образов дисков',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Анализ RAW образа
  python run_agent.py --image /data/server.raw
  
  # Анализ VMDK с конвертацией в RAW
  python run_agent.py --image /data/server.vmdk --convert
  
  # Только подготовка образа (без агента)
  python run_agent.py --image /data/server.vmdk --prepare-only

Результаты сохраняются в директории output/<timestamp>/
        """
    )
    
    parser.add_argument(
        '--image', '-i',
        type=str,
        required=True,
        help='Путь к образу диска (RAW формат)'
    )
    
    parser.add_argument(
        '--convert', '-c',
        action='store_true',
        help='Конвертировать в RAW перед анализом (для vmdk, qcow2, vdi)'
    )
    
    parser.add_argument(
        '--prepare-only',
        action='store_true',
        help='Только подготовить образ, без запуска агента'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        type=str,
        default=None,
        help='Директория для выходных файлов'
    )
    
    args = parser.parse_args()
    
    # Проверяем путь к образу
    image_path = Path(args.image)
    if not image_path.exists():
        print(f"❌ Error: Image file not found: {image_path}")
        return 1
    
    print(f"\n{'='*60}")
    print(f"🔍 FORSETI FORENSIC AGENT")
    print(f"{'='*60}")
    print(f"Image: {image_path}")
    print(f"{'='*60}\n")
    
    # ========== Этап 1: Подготовка образа ==========
    if args.convert or not image_path.suffix.lower() in ['.raw', '.dd', '.img']:
        print("📦 Stage 1: Preparing image...")
        
        from src.preprocessing import ImageProcessor
        
        processor = ImageProcessor()
        metadata = processor.prepare_for_analysis(
            image_path,
            output_dir=Path(args.output_dir) if args.output_dir else None
        )
        
        if metadata.error:
            print(f"❌ Preparation failed: {metadata.error}")
            return 1
        
        print(f"  Format: {metadata.format.value}")
        print(f"  Size: {metadata.size_human}")
        
        if metadata.raw_path and metadata.raw_path != image_path:
            print(f"  RAW path: {metadata.raw_path}")
            image_path = metadata.raw_path
        
        print("✓ Image prepared\n")
    
    if args.prepare_only:
        print("✓ Preparation complete (--prepare-only mode)")
        return 0
    
    # ========== Проверка GigaChat ==========
    if not os.getenv("GIGACHAT_CREDENTIALS"):
        print("❌ Error: GIGACHAT_CREDENTIALS not found!")
        print("   Please create .env file with your GigaChat API key.")
        print("   See .env.example for reference.")
        print("\n   Example .env file:")
        print("   GIGACHAT_CREDENTIALS=your_api_key_here")
        print("   GIGACHAT_MODEL=GigaChat-2-Max")
        return 1
    
    print(f"✓ GigaChat credentials found")
    print(f"  Model: {os.getenv('GIGACHAT_MODEL', 'GigaChat-2-Max')}")
    
    # ========== Этап 2: Запуск агента ==========
    print("\n🤖 Stage 2: Running forensic agent (GigaChat LLM)...")
    print()
    
    from src.agent import run_agent
    
    result = run_agent(str(image_path))
    
    # ========== Итоги ==========
    print(f"\n{'='*60}")
    print("📊 RESULTS")
    print(f"{'='*60}")
    
    if result.get('report_path'):
        print(f"✓ Report: {result['report_path']}")
        
        # Пытаемся найти другие сохранённые файлы
        report_dir = Path(result['report_path']).parent
        if (report_dir / "triage_data.json").exists():
            print(f"✓ Triage data: {report_dir / 'triage_data.json'}")
        if (report_dir / "analysis_result.json").exists():
            print(f"✓ Analysis result: {report_dir / 'analysis_result.json'}")
        
        print(f"\nОткройте отчёт в браузере:")
        print(f"  file://{Path(result['report_path']).absolute()}")
        return 0
    else:
        print("❌ Agent failed to generate report")
        if result.get('errors'):
            print("\nErrors:")
            for error in result['errors']:
                print(f"  - {error}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
