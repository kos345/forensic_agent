#!/usr/bin/env python3
"""
Тест функции search_in_image_files.

Проверяет работоспособность поиска по содержимому файлов в образе диска.

Запуск:
    python test_search_in_image.py
"""

import json
import os
import sys
from pathlib import Path

# Добавляем путь к модулям
sys.path.insert(0, str(Path(__file__).parent))

from src.tools import (
    open_disk_image,
    close_disk_image,
    search_in_image_files,
    list_directory_in_image,
)


# Путь к образу
IMAGE_PATH = os.environ.get("FORSETI_IMAGE_PATH", "/path/to/disk.raw")


def print_separator(title: str):
    """Печать разделителя."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def test_search():
    """Тестирование функции search_in_image_files."""
    
    print_separator("1. Открытие образа")
    result = open_disk_image.invoke({"image_path": IMAGE_PATH})
    print(f"Результат: {result}")
    
    data = json.loads(result)
    if not data.get("success"):
        print(f"❌ Ошибка открытия образа: {data.get('error')}")
        return
    print("✅ Образ открыт успешно")
    
    # Тест 1: Поиск в /var/log
    print_separator("2. Поиск 'Failed' в /var/log")
    result = search_in_image_files.invoke({
        "directory": "/var/log",
        "pattern": "Failed",
        "max_depth": 2
    })
    data = json.loads(result)
    print(f"Файлов проверено: {data.get('files_searched', 0)}")
    print(f"Совпадений найдено: {data.get('total_matches', 0)}")
    if data.get('matches'):
        print("\nПервые 5 совпадений:")
        for m in data['matches'][:5]:
            print(f"  📄 {m['file']}:{m['line_number']}")
            print(f"     {m['line'][:80]}...")
    
    # Тест 2: Поиск подозрительных команд в /home
    print_separator("3. Поиск 'wget|curl|nc' в /home")
    result = search_in_image_files.invoke({
        "directory": "/home",
        "pattern": "wget|curl|nc\\s",
        "max_depth": 3
    })
    data = json.loads(result)
    print(f"Файлов проверено: {data.get('files_searched', 0)}")
    print(f"Совпадений найдено: {data.get('total_matches', 0)}")
    if data.get('matches'):
        print("\nНайденные совпадения:")
        for m in data['matches'][:10]:
            print(f"  📄 {m['file']}:{m['line_number']}")
            print(f"     Совпадение: '{m['match']}'")
            print(f"     Строка: {m['line'][:100]}")
    
    # Тест 3: Поиск root в /etc
    print_separator("4. Поиск 'root' в /etc/passwd")
    result = search_in_image_files.invoke({
        "directory": "/etc",
        "pattern": "^root:",
        "file_extension": None,
        "max_depth": 1
    })
    data = json.loads(result)
    print(f"Файлов проверено: {data.get('files_searched', 0)}")
    print(f"Совпадений найдено: {data.get('total_matches', 0)}")
    if data.get('matches'):
        print("\nНайдено:")
        for m in data['matches'][:5]:
            print(f"  📄 {m['file']}:{m['line_number']}: {m['line']}")
    
    # Тест 4: Поиск SSH ключей
    print_separator("5. Поиск SSH ключей 'ssh-rsa|ssh-ed25519'")
    result = search_in_image_files.invoke({
        "directory": "/home",
        "pattern": "ssh-rsa|ssh-ed25519",
        "max_depth": 4
    })
    data = json.loads(result)
    print(f"Файлов проверено: {data.get('files_searched', 0)}")
    print(f"Совпадений найдено: {data.get('total_matches', 0)}")
    if data.get('matches'):
        print("\nНайденные SSH ключи:")
        for m in data['matches'][:5]:
            print(f"  📄 {m['file']}")
            print(f"     {m['line'][:80]}...")
    
    # Тест 5: Поиск в конфигурационных файлах
    print_separator("6. Поиск 'password|secret|token' в /etc")
    result = search_in_image_files.invoke({
        "directory": "/etc",
        "pattern": "password|secret|token",
        "file_extension": ".conf",
        "max_depth": 3
    })
    data = json.loads(result)
    print(f"Файлов проверено: {data.get('files_searched', 0)}")
    print(f"Совпадений найдено: {data.get('total_matches', 0)}")
    if data.get('matches'):
        print("\nНайдено:")
        for m in data['matches'][:5]:
            print(f"  📄 {m['file']}:{m['line_number']}")
            print(f"     {m['line'][:100]}")
    
    # Закрываем образ
    print_separator("7. Закрытие образа")
    result = close_disk_image.invoke({})
    print(f"Результат: {result}")
    print("✅ Тест завершён")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  ТЕСТ ФУНКЦИИ search_in_image_files")
    print("="*60)
    print(f"\nОбраз: {IMAGE_PATH}\n")
    
    try:
        test_search()
    except KeyboardInterrupt:
        print("\n\n⚠️ Прервано пользователем")
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
