#!/usr/bin/env python3
"""
Forseti Deep Forensic Agent — Entry Point.

Запуск из PyCharm: просто нажмите Run (▶).
Запуск из CLI:     python run_deep_agent.py [--image PATH] [--output-dir DIR]

Конфигурация задаётся:
  1. Через переменные ниже (секция CONFIGURATION)
  2. Через аргументы командной строки (перекрывают defaults)
  3. Через .env файл (GIGACHAT_CREDENTIALS и др.)
"""

import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# ===================== CONFIGURATION =====================
# Измените эти значения под свой проект.
# При запуске из PyCharm используются именно они.

DEFAULT_IMAGE_PATH = None  # Укажите путь к образу или передайте через --image

DEFAULT_OUTPUT_DIR = None  # None = автоматически output/<timestamp>/
USE_DEEP_AGENT = True  # False = использовать fallback (прямой LLM-анализ)

# ===================== PATH SETUP ========================
# Гарантируем, что рабочая директория — корень проекта,
# независимо от того, откуда запущен скрипт.

PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))


def check_prerequisites():
    """Проверить наличие необходимых зависимостей и конфигурации."""
    errors = []

    # Проверка .env
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        errors.append(
            "Файл .env не найден.\n"
            "Создайте .env с GIGACHAT_CREDENTIALS=<your_key>"
        )

    # Проверка основных зависимостей
    required_packages = {
        'langchain_core': 'langchain-core',
        'langgraph': 'langgraph',
        'yaml': 'pyyaml',
        'dotenv': 'python-dotenv',
    }

    for module, package in required_packages.items():
        try:
            __import__(module)
        except ImportError:
            errors.append(f"Пакет {package} не установлен. pip install {package}")

    # Проверка GigaChat
    try:
        import langchain_gigachat  # noqa: F401
    except ImportError:
        errors.append("Пакет langchain-gigachat не установлен. pip install langchain-gigachat")

    # Проверка pytsk3
    try:
        import pytsk3  # noqa: F401
    except ImportError:
        errors.append("Пакет pytsk3 не установлен. pip install pytsk3")

    # Проверка deep agents (опционально — будет fallback)
    try:
        import deepagents  # noqa: F401
        print("✓ Deep Agents SDK доступен")
    except ImportError:
        print("⚠ Deep Agents SDK не установлен — будет использован fallback (прямой LLM-анализ)")

    return errors


def parse_args():
    """
    Парсинг CLI-аргументов.

    Все аргументы опциональные — defaults берутся из секции CONFIGURATION.
    Если скрипт запущен без аргументов (из PyCharm), используются defaults.
    """
    parser = argparse.ArgumentParser(
        description="Forseti Deep Forensic Agent — Интеллектуальный анализ образов дисков",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python run_deep_agent.py                          # defaults из CONFIGURATION
  python run_deep_agent.py --image /data/disk.raw   # указать образ
  python run_deep_agent.py --no-deep-agent          # без Deep Agent SDK
        """
    )
    parser.add_argument(
        "--image",
        type=str,
        default=DEFAULT_IMAGE_PATH,
        required=DEFAULT_IMAGE_PATH is None,
        help="Путь к образу диска (RAW формат)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help="Директория для сохранения отчёта (по умолчанию output/<timestamp>/)",
    )
    parser.add_argument(
        "--no-deep-agent",
        action="store_true",
        default=not USE_DEEP_AGENT,
        help="Использовать только fallback (прямой LLM-анализ) вместо Deep Agent",
    )
    return parser.parse_args()


def run(image_path: str, output_dir: str = None):
    """
    Основная логика запуска агента.

    Вынесена из main() чтобы можно было вызывать программно:
        from run_deep_agent import run
        result = run("/path/to/disk.raw")
    """
    image_path = Path(image_path).resolve()

    if not image_path.exists():
        print(f"✗ Файл образа не найден: {image_path}")
        return None

    file_size_gb = image_path.stat().st_size / (1024 ** 3)
    print(f"\n{'=' * 60}")
    print(f"🔬 FORSETI DEEP FORENSIC AGENT")
    print(f"   Образ: {image_path}")
    print(f"   Размер: {file_size_gb:.2f} GB")
    print(f"   Рабочая директория: {Path.cwd()}")
    print(f"{'=' * 60}\n")

    # Проверка зависимостей
    print("Проверка зависимостей...")
    errors = check_prerequisites()
    if errors:
        print("\n✗ Обнаружены проблемы:")
        for error in errors:
            print(f"  - {error}")
        return None
    print("✓ Все зависимости доступны\n")

    # Запуск агента
    start_time = datetime.now()
    print(f"Начало анализа: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─' * 60}\n")

    try:
        from src.agent.forensic_deep_agent import ForensicDeepAgent, run_deep_agent

        result = run_deep_agent(str(image_path))

        end_time = datetime.now()
        duration = end_time - start_time

        print(f"\n{'─' * 60}")
        print(f"Окончание: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Длительность: {duration}")

        if result.get('report_path'):
            print(f"\n📄 Отчёт: {result['report_path']}")

        if result.get('errors'):
            print(f"\n⚠ Ошибки ({len(result['errors'])}):")
            for err in result['errors'][:5]:
                print(f"  - {err}")

        return result

    except KeyboardInterrupt:
        print("\n\n⚠ Анализ прерван пользователем")
        return None
    except Exception as e:
        print(f"\n✗ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """Точка входа — работает и из CLI, и из PyCharm."""
    args = parse_args()
    result = run(args.image, args.output_dir)
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()