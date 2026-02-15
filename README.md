# 🔬 Forensic Agent — AI-агент для криминалистического анализа образов дисков

**Forensic Agent** — интеллектуальный агент на базе LangGraph и GigaChat LLM для автоматизированного криминалистического анализа образов дисков Linux-серверов. Агент самостоятельно собирает артефакты, выявляет аномалии, ищет следы компрометации и генерирует подробный HTML-отчёт.

## 📋 Возможности

- **Автоматический сбор артефактов** — пользователи, сервисы, cron, пакеты, SSH, Docker, история команд, логи авторизации
- **Алгоритмический анализ** — выявление аномалий (подозрительные команды, UID 0, нестандартные сервисы и т.д.)
- **Интеллектуальный анализ (LLM)** — экспертный анализ собранных данных с помощью GigaChat-2-Max
- **Глубокий анализ логов** — статистический анализ btmp/wtmp, auth.log, lastlog, dpkg, bash_history, alternatives
- **Детекция malware** — детерминированный regex-сканер файлов в /home/ и /root/ (reverse shell, backdoor, криптомайнеры)
- **Deep Agent** — многоитерационное расследование с 5 субагентами + general-purpose
- **Chain of Thought + Reflection** — методичный пошаговый анализ с самопроверкой
- **HTML-отчёт** — всеобъемлющий отчёт с находками, статистикой и экспертным заключением

## 🏗 Архитектура

```
┌──────────────────────────────────────────────────────────────┐
│                  LangGraph Orchestrator                        │
│                                                                │
│  open_image → collect_baseline → deep_analysis → evaluate     │
│                                       ↑              ↓        │
│                                       └── continue ──┘        │
│                                              ↓ sufficient     │
│                                       generate_report → END   │
│                                                                │
│  Layer 2: Deep Agent (deepagents SDK)                         │
│    ├── service_analyzer      (сервисы, пакеты, cron)          │
│    ├── file_explorer         (файловая структура, скрытые)    │
│    ├── connection_analyzer   (SSH, сетевая активность)        │
│    ├── history_analyzer      (история команд, IoC)            │
│    └── file_content_analyzer (содержимое файлов, malware)     │
└──────────────────────────────────────────────────────────────┘
```

## 📁 Структура проекта

```
Forensic Agent/
├── run_agent.py                 # Запуск простого агента
├── run_deep_agent.py            # Запуск Deep Agent (рекомендуется)
├── requirements.txt             # Зависимости Python
├── configs/
│   └── triage.yaml              # Конфигурация путей для сбора артефактов
├── src/
│   ├── __init__.py
│   ├── main.py                  # Pipeline подготовки образа
│   ├── agent/
│   │   ├── simple_agent.py      # Простой LangGraph-агент
│   │   ├── forensic_deep_agent.py  # Deep Forensic Agent
│   │   ├── prompts.py           # Промпты для LLM
│   │   ├── report_generator.py  # Генератор HTML-отчёта
│   │   └── state.py             # Состояние агента (LangGraph State)
│   ├── preprocessing/
│   │   └── image_processor.py   # Обработка образов (определение типа, конвертация)
│   ├── tools/
│   │   ├── image_manager.py     # ImageManager (pytsk3) — доступ к образу
│   │   ├── image_tools.py       # Работа с образом диска (pytsk3)
│   │   ├── artifact_tools.py    # Сбор криминалистических артефактов
│   │   ├── analysis_tools.py    # Анализ данных (IoC, парсинг)
│   │   ├── investigation_tools.py  # InvestigationStore + управление расследованием
│   │   ├── filesystem_tools.py  # Утилиты локальной ФС
│   │   ├── log_analyzers.py     # 6 анализаторов логов (btmp/wtmp, auth, lastlog, dpkg, history, alternatives)
│   │   └── extract_fs.py        # Выгрузка ФС образа в локальную директорию
│   └── utils/
│       ├── logger.py            # Логирование
│       ├── filesystem.py        # Утилиты файловой системы
│       └── message_history.py   # Callback для перехвата LLM-сообщений
├── output/                      # Результаты анализа (создаётся автоматически)
├── extracted/                   # Извлечённые файлы (создаётся автоматически)
├── image_fs/                    # Выгруженная файловая система образа (создаётся автоматически)
└── logs/                        # Логи (создаётся автоматически)
```

## 🚀 Установка

### Требования

- **Python 3.11+**
- **pytsk3** — для доступа к файловым системам образов дисков
- **qemu-utils** — для конвертации образов (VMDK → RAW и т.д.)
- **Ключ GigaChat API** — для работы LLM

### Установка системных зависимостей

```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y qemu-utils libtsk-dev

# CentOS / RHEL
sudo yum install -y qemu-img sleuthkit-devel
```

### Установка Python-зависимостей

```bash
# Создать виртуальное окружение
python -m venv venv
source venv/bin/activate

# Установить зависимости
pip install -r requirements.txt
```

Или с использованием conda:

```bash
conda create -n forensic_agent_env python=3.11
conda activate forensic_agent_env
pip install -r requirements.txt
```

### Настройка GigaChat

Создайте файл `.env` в корне проекта:

```env
GIGACHAT_CREDENTIALS=ваш_api_ключ
GIGACHAT_MODEL=GigaChat-2-Max
GIGACHAT_TEMPERATURE=0.2
GIGACHAT_MAX_TOKENS=8192
GIGACHAT_VERIFY_SSL=true
# GIGACHAT_TIMEOUT=1800
# GIGACHAT_BASE_URL=
# GIGACHAT_SCOPE=
# GIGACHAT_CA_BUNDLE=
```

## 📖 Использование

Предварительно необходимо указать GIGACHAT_CREDENTIALS в файле .env

### Deep Agent (рекомендуется)

```bash
# Анализ образа диска
python run_deep_agent.py --image /path/to/disk.raw

# С указанием директории для результатов
python run_deep_agent.py --image /path/to/disk.raw --output-dir ./results

# С указанием включения логирования сообщений LLM
python run_deep_agent.py --image /path/to/disk.raw --message-history
```

### Простой агент

```bash
# Анализ RAW образа
python run_agent.py --image /path/to/disk.raw

# Конвертация VMDK → RAW и анализ
python run_agent.py --image /path/to/disk.vmdk --convert

# Только подготовка образа (без запуска агента)
python run_agent.py --image /path/to/disk.vmdk --prepare-only
```

### Pipeline подготовки (без агента)

```bash
python -m src.main --image /path/to/disk.raw
python -m src.main --image /path/to/disk.vmdk --output-dir ./converted --hashes
```

### Программное использование

```python
# Deep Agent
from src.agent.forensic_deep_agent import run_deep_agent
result = run_deep_agent("/path/to/disk.raw")

# Простой агент
from src.agent import run_agent
result = run_agent("/path/to/disk.raw")

# Только pipeline
from src.main import run_pipeline
result = run_pipeline("/path/to/disk.raw")
```

## ⚙️ Конфигурация

### Конфигурация сбора артефактов

Файл `configs/triage.yaml` определяет, какие пути проверяются при сборе артефактов:

```yaml
artifacts:
  system:
    - /etc/os-release
    - /etc/issue
  users:
    - /etc/passwd
    - /etc/shadow
  history:
    - /home/*/.bash_history
    - /root/.bash_history
  # ... и т.д.
```

## 📊 Результаты

После анализа в директории `output/<timestamp>/` создаются:

| Файл | Описание |
|------|----------|
| `comprehensive_report.html` | Полный HTML-отчёт (Deep Agent) |
| `report.html` | HTML-отчёт (простой агент) |
| `triage_data.json` | Собранные артефакты |
| `analysis_result.json` | Результат алгоритмического анализа |
| `report_data.json` | Полные данные для отчёта (Deep Agent) |

### Секции HTML-отчёта

1. **Общая картина** — статистика, аномалии, рекомендации
2. **Сведения о системе** — ОС, пользователи, сервисы, cron, пакеты, Docker
3. **Информация о файлах** — нестандартные файлы в корне, /home/, /root/
4. **Подключения (SSH)** — успешные SSH-входы, IP-адреса
4a. **Детальный анализ логов** — btmp/wtmp, auth.log, lastlog, dpkg, bash_history, alternatives
5. **Активность пользователей** — история команд, публичные IP, саммари
6. **Подозрительные находки** — все обнаруженные IoC с severity-уровнем
7. **Экспертное заключение** — анализ от LLM
8. **Исследованные пути** — полный лог исследования

## 🔧 Индикаторы компрометации (IoC)

Агент ищет следующие индикаторы:

- Пользователи с UID 0 (кроме root)
- Подозрительные команды: `wget`, `curl`, `nc`, `base64`, `chmod 777`, `nmap`, `masscan`
- Нестандартные системные сервисы
- Подозрительные cron-задачи
- Неизвестные SSH-ключи в `authorized_keys`
- Криптомайнеры (`xmrig`, `stratum`, `pool`)
- Обратные шеллы (`bash -i`, `/dev/tcp`)
- Скрытые файлы и директории в нестандартных местах
- Файлы в `/tmp/`, `/var/tmp/`, `/dev/shm/`

## 🛠 Стек технологий

- **[LangGraph](https://github.com/langchain-ai/langgraph)** — оркестрация workflow агента
- **[Deep Agents SDK](https://docs.langchain.com/oss/python/deepagents/overview)** — субагенты, планирование, middleware
- **[GigaChat](https://developers.sber.ru/portal/products/gigachat)** — LLM для интеллектуального анализа
- **[pytsk3](https://github.com/py4n6/pytsk)** — доступ к файловым системам образов дисков
- **[LangChain](https://www.langchain.com/)** — фреймворк для работы с LLM
- **[pandas](https://pandas.pydata.org/)** — статистический анализ логов

