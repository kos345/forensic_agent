"""
Message History — LangChain Callback для перехвата всех LLM-сообщений в реальном времени.

Реализован как BaseCallbackHandler, который автоматически вызывается LangChain/LangGraph
при каждом обращении к LLM и при каждом вызове инструмента:
  - on_chat_model_start  → входные сообщения (system, user)
  - on_llm_end           → ответ LLM (assistant, tool_calls)
  - on_tool_start        → вызов инструмента (имя, аргументы)
  - on_tool_end          → результат инструмента
  - on_llm_error         → ошибка LLM
  - on_tool_error        → ошибка инструмента

Источник имени в логах:
  - Deep Agent (главный): metadata["checkpoint_ns"] → имя внешнего узла графа
    ("deep_analysis", и т.д.)
  - Субагенты: metadata["lc_agent_name"] → имя субагента
    ("service_analyzer", "file_explorer", ...)
  - Прямые LLM-вызовы (evaluate, fallback): set_current_node() → имя текущего узла

Подключение:
  1. При инициализации: init_message_history(enabled=True)
  2. Callback автоматически привязывается к LLM через create_gigachat_llm()
  3. Для Deep Agent передаётся в config: deep_agent.invoke(..., config={"callbacks": [handler]})

Сохранение: output/message_history/{yyyymmdd_hhmmss}/
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import BaseMessage
from langchain_core.outputs import LLMResult


# ==================== ANSI COLORS ====================

class _Colors:
    """ANSI-цвета для терминала."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    SYSTEM = "\033[95m"       # Magenta
    USER = "\033[94m"         # Blue
    ASSISTANT = "\033[92m"    # Green
    TOOL_CALL = "\033[93m"    # Yellow
    TOOL_RESULT = "\033[33m"  # Dark Yellow
    ERROR = "\033[91m"        # Red
    LLM = "\033[96m"          # Cyan
    SEPARATOR = "\033[90m"    # Gray
    AGENT = "\033[36m"        # Cyan (для имени агента/ноды)


_ROLE_COLORS = {
    "system": _Colors.SYSTEM,
    "human": _Colors.USER,
    "user": _Colors.USER,
    "ai": _Colors.ASSISTANT,
    "assistant": _Colors.ASSISTANT,
    "tool_call": _Colors.TOOL_CALL,
    "tool_result": _Colors.TOOL_RESULT,
    "error": _Colors.ERROR,
}

# Нормализация ролей LangChain → человекочитаемые
_ROLE_DISPLAY = {
    "system": "SYSTEM",
    "human": "USER",
    "user": "USER",
    "ai": "ASSISTANT",
    "assistant": "ASSISTANT",
    "tool_call": "TOOL_CALL",
    "tool_result": "TOOL_RESULT",
    "error": "ERROR",
}

_MAX_DISPLAY_LEN = 2000


# ==================== CALLBACK HANDLER ====================

class MessageHistoryHandler(BaseCallbackHandler):
    """
    LangChain callback handler — перехватывает все LLM- и tool-взаимодействия
    в реальном времени, выводит в терминал и накапливает для сохранения на диск.
    """

    name: str = "ForensicMessageHistory"

    def __init__(self) -> None:
        super().__init__()
        self.messages: List[Dict[str, Any]] = []
        self.start_time: datetime = datetime.now()

        # Дедупликация: system и human сообщения логируются 1 раз
        self._seen_system: set = set()
        self._seen_human: set = set()

        # run_id → tool_name (для on_tool_end, где serialized недоступен)
        self._run_to_tool: Dict[str, str] = {}
        # run_id → source_label (для on_llm_end / on_tool_end, где metadata недоступен)
        self._run_to_source: Dict[str, str] = {}

        # Имя главного агента (первый увиденный lc_agent_name); субагенты отличаются
        self._main_agent_name: str = ""

        # Текущая нода графа — fallback для прямых llm.invoke() без LangGraph metadata
        self._current_node: str = ""

    # ─────────── Контекст текущего узла ───────────

    def set_current_node(self, node: str) -> None:
        """
        Установить имя текущего узла графа.

        Вызывать перед прямыми llm.invoke() в graph-нодах, где нет LangGraph metadata:
            handler.set_current_node("evaluate_analysis")
        """
        self._current_node = node

    # ─────────── Извлечение source label ───────────

    def _resolve_source(self, metadata: Optional[Dict[str, Any]]) -> str:
        """
        Определить читаемое имя источника сообщения.

        Логика:
          1. metadata есть (Deep Agent / LangGraph):
             - lc_agent_name != главный агент → субагент → "service_analyzer"
             - lc_agent_name == главный агент → внешний узел из checkpoint_ns → "deep_analysis"
          2. metadata нет (прямой llm.invoke()) → _current_node → "evaluate_analysis"
        """
        if not metadata:
            return self._current_node

        agent_name = metadata.get("lc_agent_name", "")
        checkpoint_ns = metadata.get("checkpoint_ns", "")

        # Запоминаем первый увиденный agent_name как главного
        if agent_name and not self._main_agent_name:
            self._main_agent_name = agent_name

        # Субагент — имя отличается от главного
        if agent_name and agent_name != self._main_agent_name:
            return agent_name  # "service_analyzer", "file_explorer", ...

        # Главный агент — извлекаем имя внешнего узла из checkpoint_ns
        # Формат: "deep_analysis:31be23bd-dd31-..." → "deep_analysis"
        if checkpoint_ns:
            outer_node = checkpoint_ns.split(":")[0]
            if outer_node:
                return outer_node  # "deep_analysis"

        # Если ничего не нашли в metadata, используем fallback
        return self._current_node

    # ─────────── Нормализация content ───────────

    @staticmethod
    def _normalize_content(content: Any) -> str:
        """Нормализация content из BaseMessage в строку."""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    if item.get("type") == "text":
                        parts.append(item.get("text", ""))
                    else:
                        parts.append(f"[{item.get('type', 'unknown')}]")
                else:
                    parts.append(str(item))
            return "\n".join(parts)
        return str(content)

    # ─────────── Chat model input ───────────

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[BaseMessage]],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Перехват входных сообщений, отправляемых в чат-модель."""
        source = self._resolve_source(metadata)
        self._run_to_source[str(run_id)] = source

        for msg_list in messages:
            for msg in msg_list:
                role = getattr(msg, "type", "unknown")
                raw_content = getattr(msg, "content", "")
                content = self._normalize_content(raw_content)

                if role == "system":
                    _key = hash(content)
                    if _key in self._seen_system:
                        continue
                    self._seen_system.add(_key)
                    self._record("system", content, source=source)

                elif role == "human":
                    _key = hash(content)
                    if _key in self._seen_human:
                        continue
                    self._seen_human.add(_key)
                    self._record("human", content, source=source)

    # ─────────── LLM response ───────────

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Перехват ответа LLM (ai-сообщение, возможно с tool_calls)."""
        source = self._run_to_source.pop(str(run_id), "")

        for gen_list in response.generations:
            for gen in gen_list:
                msg = getattr(gen, "message", None)
                if msg is not None:
                    content = getattr(msg, "content", "")
                    tool_calls = getattr(msg, "tool_calls", [])
                    entry: Dict[str, Any] = {
                        "timestamp": datetime.now().isoformat(),
                        "role": "ai",
                        "content": content,
                        "source": source,
                    }
                    if tool_calls:
                        entry["tool_calls"] = [
                            {
                                "name": tc.get("name", ""),
                                "args": tc.get("args", {}),
                                "id": tc.get("id", ""),
                            }
                            for tc in tool_calls
                        ]
                    self.messages.append(entry)
                    self._print_entry(entry)
                else:
                    text = getattr(gen, "text", str(gen))
                    if text:
                        entry = {
                            "timestamp": datetime.now().isoformat(),
                            "role": "ai",
                            "content": text,
                            "source": source,
                        }
                        self.messages.append(entry)
                        self._print_entry(entry)

    # ─────────── Tool calls ───────────

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Перехват вызова инструмента (tool_call)."""
        source = self._resolve_source(metadata)
        tool_name = serialized.get("name", "unknown_tool")

        self._run_to_tool[str(run_id)] = tool_name
        self._run_to_source[str(run_id)] = source

        if isinstance(input_str, dict):
            content = json.dumps(input_str, ensure_ascii=False, default=str)
        else:
            content = str(input_str)

        self._record("tool_call", content, tool=tool_name, source=source)

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Перехват результата инструмента (tool_result)."""
        tool_name = self._run_to_tool.pop(str(run_id), "unknown_tool")
        source = self._run_to_source.pop(str(run_id), "")

        if hasattr(output, "content"):
            content = output.content
        elif isinstance(output, str):
            content = output
        else:
            content = str(output)

        self._record("tool_result", content, tool=tool_name, source=source)

    # ─────────── Errors ───────────

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        source = self._run_to_source.pop(str(run_id), "")
        self._record("error", f"LLM Error: {error}", source=source)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        tool_name = self._run_to_tool.pop(str(run_id), "unknown_tool")
        source = self._run_to_source.pop(str(run_id), "")
        self._record("error", f"Tool Error [{tool_name}]: {error}", tool=tool_name, source=source)

    # ─────────── Internal helpers ───────────

    def _record(self, role: str, content: str, **extra: Any) -> None:
        """Добавить запись в историю и вывести в терминал."""
        entry: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "role": role,
            "content": content,
        }
        entry.update(extra)
        self.messages.append(entry)
        self._print_entry(entry)

    def _print_entry(self, entry: Dict[str, Any]) -> None:
        """Вывести запись в терминал с ANSI-раскраской."""
        role = entry.get("role", "unknown")
        content = entry.get("content", "")
        tool_calls = entry.get("tool_calls", [])
        tool_name = entry.get("tool", "")
        source = entry.get("source", "")
        timestamp = entry.get("timestamp", "")

        color = _ROLE_COLORS.get(role, _Colors.LLM)
        display_role = _ROLE_DISPLAY.get(role, role.upper())

        # Метка: ROLE [tool] @source
        label = display_role
        if tool_name:
            label += f" [{tool_name}]"
        if source:
            label += f" {_Colors.AGENT}@{source}{_Colors.RESET}{color}{_Colors.BOLD}"

        ts_short = timestamp[11:19] if len(timestamp) >= 19 else timestamp

        print(f"\n{_Colors.SEPARATOR}{'─' * 60}{_Colors.RESET}")
        print(f"{_Colors.DIM}[{ts_short}]{_Colors.RESET} {color}{_Colors.BOLD}{label}{_Colors.RESET}")

        if content:
            display = content
            if len(display) > _MAX_DISPLAY_LEN:
                display = display[:_MAX_DISPLAY_LEN] + (
                    f"\n... [{len(content)} символов, усечено для отображения]"
                )
            print(f"{color}{display}{_Colors.RESET}")

        for tc in tool_calls:
            tc_name = tc.get("name", "?")
            tc_args = tc.get("args", {})
            args_str = json.dumps(tc_args, ensure_ascii=False, default=str)
            if len(args_str) > 500:
                args_str = args_str[:500] + "..."
            print(f"  {_Colors.TOOL_CALL}⚡ tool_call: {tc_name}({args_str}){_Colors.RESET}")

    # ─────────── Save to disk ───────────

    def save_to_disk(self) -> Optional[str]:
        """
        Сохранить полную историю на диск.

        Каталог: output/message_history/{yyyymmdd_hhmmss}/
          - messages.json
          - messages.txt
        """
        if not self.messages:
            return None

        ts = self.start_time.strftime("%Y%m%d_%H%M%S")
        out_dir = Path("output") / "message_history" / ts
        out_dir.mkdir(parents=True, exist_ok=True)

        # JSON
        json_path = out_dir / "messages.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.messages, f, ensure_ascii=False, indent=2, default=str)

        # TXT (человекочитаемый)
        txt_path = out_dir / "messages.txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"Message History — {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total messages: {len(self.messages)}\n")
            f.write("=" * 60 + "\n\n")

            for i, entry in enumerate(self.messages, 1):
                role = entry.get("role", "unknown")
                content = entry.get("content", "")
                timestamp = entry.get("timestamp", "")
                tool_calls = entry.get("tool_calls", [])
                tool_name = entry.get("tool", "")
                source = entry.get("source", "")

                display_role = _ROLE_DISPLAY.get(role, role.upper())
                label = display_role
                if tool_name:
                    label += f" [{tool_name}]"
                if source:
                    label += f" @{source}"

                f.write(f"--- Message {i} [{timestamp}] ---\n")
                f.write(f"Role: {label}\n")
                if content:
                    f.write(f"Content:\n{content}\n")
                for tc in tool_calls:
                    f.write(f"Tool Call: {tc.get('name', '?')}\n")
                    args_str = json.dumps(tc.get("args", {}), ensure_ascii=False, default=str)
                    f.write(f"  Args: {args_str}\n")
                f.write("\n")

        print(f"\n{'=' * 60}")
        print(f"📋 История сообщений сохранена:")
        print(f"   JSON: {json_path}")
        print(f"   TXT:  {txt_path}")
        print(f"   Всего сообщений: {len(self.messages)}")
        print(f"{'=' * 60}")

        return str(out_dir)


# ==================== GLOBAL INSTANCE ====================

_handler: Optional[MessageHistoryHandler] = None


def init_message_history(enabled: bool = False) -> Optional[MessageHistoryHandler]:
    """
    Инициализировать глобальный callback handler.

    Args:
        enabled: True — создать handler, False — отключить (None).

    Returns:
        MessageHistoryHandler или None.
    """
    global _handler
    _handler = MessageHistoryHandler() if enabled else None
    return _handler


def get_message_history() -> Optional[MessageHistoryHandler]:
    """Получить глобальный callback handler (None если отключён)."""
    return _handler
