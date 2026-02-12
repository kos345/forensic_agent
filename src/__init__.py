"""
Forseti - Forensic Image Triage & Analysis Toolkit with AI Agent.

Модули:
- preprocessing: Подготовка образа (определение типа, конвертация в RAW)
- tools: LangChain tools для AI-агента
- utils: Утилиты (логирование, работа с файлами)

Использование:
    # Запуск пайплайна подготовки
    python -m src.main --image /path/to/disk.img
    
    # Использование в коде
    from src.main import run_pipeline, get_agent_context
    from src.tools import (
        open_disk_image,
        collect_users_info,
        analyze_triage_data,
    )
"""

__version__ = "2.0.0"
__author__ = "Forseti Team"

# Экспорт основных функций
from src.main import run_pipeline, get_agent_context, ForensicPipeline, PipelineConfig
from src.preprocessing import ImageProcessor

__all__ = [
    'run_pipeline',
    'get_agent_context', 
    'ForensicPipeline',
    'PipelineConfig',
    'ImageProcessor',
]