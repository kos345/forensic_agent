"""
Log Analyzers — Детальные анализаторы логов (адаптировано из проекта KovalevE).

Содержит 6 анализаторов:
1. analyze_utmp_logs     — btmp/wtmp: успешные/неуспешные входы, корреляции, статистика
2. analyze_auth_logs_detailed — auth.log: SSH/sudo, brute-force detection
3. analyze_lastlog       — lastlog: последние успешные входы
4. analyze_dpkg_logs     — dpkg.log: установка/удаление пакетов
5. analyze_history_commands — .bash_history: подозрительные команды
6. analyze_alternatives_logs — alternatives.log: изменения ПО

Все функции читают файлы из образа диска через ImageManager.
Бинарные файлы (utmp/lastlog) читаются через read_file_binary().
Текстовые файлы и gzip-архивы обрабатываются в памяти.
Используется pandas для статистического анализа.
"""

import io
import gzip
import json
import re
import struct
from datetime import datetime
from typing import Optional, List, Dict, Any

import pandas as pd
from langchain_core.tools import tool

from .image_manager import get_image_manager
from src.utils.logger import get_logger

logger = get_logger("LogAnalyzers")

# ==================== CACHE ====================
_log_analyzer_cache: Dict[str, str] = {}


def clear_log_analyzer_cache():
    """Очистить кеш анализаторов логов."""
    _log_analyzer_cache.clear()


# ==================== HELPERS ====================

def _read_binary_from_image(path: str) -> Optional[bytes]:
    """Прочитать бинарный файл из образа."""
    manager = get_image_manager()
    return manager.read_file_binary(path)


def _read_text_from_image(path: str) -> Optional[str]:
    """Прочитать текстовый файл из образа."""
    manager = get_image_manager()
    return manager.read_file(path)


def _read_gz_text_from_image(path: str) -> Optional[str]:
    """Прочитать gzip-сжатый текстовый файл из образа."""
    manager = get_image_manager()
    data = manager.read_file_binary(path)
    if data is None:
        return None
    try:
        return gzip.decompress(data).decode('utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f"Failed to decompress {path}: {e}")
        return None


def _find_files_in_dir(dir_path: str, name_pattern: str) -> List[str]:
    """Найти файлы в директории образа по паттерну имени."""
    manager = get_image_manager()
    entries = manager.list_directory(dir_path)
    result = []
    for entry in entries:
        if entry['type'] == 'file' and re.search(name_pattern, entry['name']):
            result.append(entry['path'])
    return result


def _truncate_result(result_str: str, max_len: int = 8000) -> str:
    """Обрезать JSON-результат если он слишком большой."""
    if len(result_str) > max_len:
        return result_str[:max_len - 200] + \
            f'\n... [ОБРЕЗАНО: показано {max_len - 200} из {len(result_str)} символов] ...'
    return result_str


def _safe_date_serializer(obj):
    """JSON serializer для datetime/date объектов."""
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    return str(obj)


# ==================== UTMP STRUCTURES ====================

UTMP_STRUCT = "hi32s4s32s256shhiii4i20s"
UTMP_SIZE = struct.calcsize(UTMP_STRUCT)

LASTLOG_STRUCT = "i32s256s"
LASTLOG_SIZE = struct.calcsize(LASTLOG_STRUCT)


# ==================== 1. UTMP ANALYSIS (btmp/wtmp) ====================

def _utmp_analysis_impl(
    btmp_paths: List[str],
    wtmp_paths: List[str],
) -> str:
    """Внутренняя реализация анализа btmp/wtmp."""
    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    failed_logins = []
    successful_logins = []
    files_analyzed = []

    def parse_utmp_data(data: bytes, is_btmp: bool):
        """Распарсить бинарные utmp-данные из буфера."""
        buf = io.BytesIO(data)
        while True:
            chunk = buf.read(UTMP_SIZE)
            if len(chunk) < UTMP_SIZE:
                break
            unpacked = struct.unpack(UTMP_STRUCT, chunk)
            (
                ut_type, ut_pid, ut_line, ut_id, ut_user, ut_host,
                ut_exit_termination, ut_exit_exit, ut_session,
                ut_tv_sec, ut_tv_usec, *_, ut_addr_v6, __unused
            ) = unpacked

            if not ut_user.strip(b"\x00"):
                continue

            entry = {
                "user": ut_user.decode(errors="ignore").replace('\x00', '').strip(),
                "tty": ut_line.decode(errors="ignore").replace('\x00', '').strip(),
                "host": ut_host.decode(errors="ignore").replace('\x00', '').strip(),
                "pid": ut_pid,
                "session": ut_session,
                "time": datetime.fromtimestamp(ut_tv_sec).isoformat() if ut_tv_sec > 0 else None,
            }

            if is_btmp:
                failed_logins.append(entry)
            else:
                successful_logins.append(entry)

    # Читаем btmp файлы
    for path in btmp_paths:
        data = None
        if path.endswith('.gz'):
            raw = _read_binary_from_image(path)
            if raw:
                try:
                    data = gzip.decompress(raw)
                except Exception:
                    pass
        else:
            data = _read_binary_from_image(path)
        if data:
            parse_utmp_data(data, is_btmp=True)
            files_analyzed.append(path)

    # Читаем wtmp файлы
    for path in wtmp_paths:
        data = None
        if path.endswith('.gz'):
            raw = _read_binary_from_image(path)
            if raw:
                try:
                    data = gzip.decompress(raw)
                except Exception:
                    pass
        else:
            data = _read_binary_from_image(path)
        if data:
            parse_utmp_data(data, is_btmp=False)
            files_analyzed.append(path)

    if not failed_logins and not successful_logins:
        return json.dumps({
            "success": True,
            "files_analyzed": files_analyzed,
            "message": "Файлы btmp/wtmp не найдены или пусты",
            "failed_logins_count": 0,
            "successful_logins_count": 0,
        }, ensure_ascii=False)

    result = {
        "success": True,
        "files_analyzed": files_analyzed,
        "failed_logins_count": len(failed_logins),
        "successful_logins_count": len(successful_logins),
    }

    # --- Pandas-анализ неуспешных входов (btmp) ---
    if failed_logins:
        df_btmp = pd.DataFrame(failed_logins)
        df_btmp['time_dt'] = pd.to_datetime(df_btmp['time'], errors='coerce')
        df_btmp['date'] = df_btmp['time_dt'].dt.date

        # Статистика по пользователям
        df_user = df_btmp.groupby('user').agg(
            unique_hosts=pd.NamedAgg(column='host', aggfunc=lambda x: x.nunique()),
            active_days=pd.NamedAgg(column='date', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='user', aggfunc='count')
        ).reset_index()
        # Ограничиваем размер
        i = 0
        while len(df_user) > 100:
            df_user = df_user[df_user['total_attempts'] > i]
            i += 1
        result['failed_by_user'] = df_user.to_dict(orient="records")

        # Статистика по хостам
        df_host = df_btmp.groupby('host').agg(
            unique_users=pd.NamedAgg(column='user', aggfunc=lambda x: x.nunique()),
            active_days=pd.NamedAgg(column='date', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='host', aggfunc='count')
        ).reset_index()
        i = 0
        while len(df_host) > 100:
            df_host = df_host[df_host['active_days'] > i]
            i += 1
        result['failed_by_host'] = df_host.to_dict(orient="records")

        # Статистика по дням
        df_date = df_btmp.groupby('date').agg(
            unique_users=pd.NamedAgg(column='user', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='user', aggfunc='count')
        ).reset_index().sort_values('date', ascending=False)
        result['failed_by_date'] = df_date.to_dict(orient="records")

    # --- Pandas-анализ успешных входов (wtmp) ---
    if successful_logins:
        df_wtmp = pd.DataFrame(successful_logins)
        df_wtmp['time_dt'] = pd.to_datetime(df_wtmp['time'], errors='coerce')
        df_wtmp['date'] = df_wtmp['time_dt'].dt.date

        # Статистика по пользователям
        df_user_s = df_wtmp.groupby('user').agg(
            unique_hosts=pd.NamedAgg(column='host', aggfunc=lambda x: x.nunique()),
            active_days=pd.NamedAgg(column='date', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='user', aggfunc='count')
        ).reset_index()
        i = 0
        while len(df_user_s) > 100:
            df_user_s = df_user_s[df_user_s['total_attempts'] > i]
            i += 1
        result['successful_by_user'] = df_user_s.to_dict(orient="records")

        # Статистика по хостам
        df_host_s = df_wtmp.groupby('host').agg(
            unique_users=pd.NamedAgg(column='user', aggfunc=lambda x: x.nunique()),
            active_days=pd.NamedAgg(column='date', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='host', aggfunc='count')
        ).reset_index()
        i = 0
        while len(df_host_s) > 100:
            df_host_s = df_host_s[df_host_s['unique_users'] > i]
            i += 1
        result['successful_by_host'] = df_host_s.to_dict(orient="records")

        # Статистика по дням
        df_date_s = df_wtmp.groupby('date').agg(
            unique_users=pd.NamedAgg(column='user', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='user', aggfunc='count')
        ).reset_index().sort_values('date', ascending=False)
        result['successful_by_date'] = df_date_s.to_dict(orient="records")

    # --- Корреляции btmp/wtmp ---
    if failed_logins and successful_logins:
        df_btmp_c = pd.DataFrame(failed_logins)
        df_btmp_c['time_dt'] = pd.to_datetime(df_btmp_c['time'], errors='coerce')
        df_btmp_c['date'] = df_btmp_c['time_dt'].dt.date
        df_wtmp_c = pd.DataFrame(successful_logins)
        df_wtmp_c['time_dt'] = pd.to_datetime(df_wtmp_c['time'], errors='coerce')
        df_wtmp_c['date'] = df_wtmp_c['time_dt'].dt.date

        try:
            max_btmp = df_btmp_c['date'].max()
            max_wtmp = df_wtmp_c['date'].max()
            if pd.notna(max_btmp) and pd.notna(max_wtmp):
                result['btmp_wtmp_date_difference_days'] = (max_wtmp - max_btmp).days
        except Exception:
            pass

        # Совпадения по хосту
        try:
            host_matches = set(df_btmp_c['host'].unique()) & set(df_wtmp_c['host'].unique())
            if host_matches:
                result['hosts_in_both_btmp_wtmp'] = list(host_matches)[:50]
        except Exception:
            pass

        # Совпадения по пользователю+дата
        try:
            merged = pd.merge(
                df_wtmp_c[['user', 'date', 'host', 'time']],
                df_btmp_c[['user', 'date', 'host', 'time']],
                on=['user', 'date'],
                suffixes=('_success', '_fail')
            )
            if not merged.empty:
                result['user_date_matches_btmp_wtmp'] = merged.head(50).to_dict(orient="records")
        except Exception:
            pass

    return json.dumps(result, ensure_ascii=False, default=_safe_date_serializer)


@tool
def analyze_utmp_logs(
    btmp_paths: Optional[List[str]] = None,
    wtmp_paths: Optional[List[str]] = None,
) -> str:
    """
    Анализ файлов btmp/wtmp (бинарные utmp) — попытки входа в систему.

    Ищет и анализирует:
    - btmp: неуспешные попытки входа (brute-force, перебор учётных записей)
    - wtmp: успешные входы (подозрительные пользователи, хосты, время)

    Генерирует статистику через pandas:
    - Группировка по пользователям, хостам и дням
    - Корреляции между btmp и wtmp (совпадения хостов и пользователей)
    - Разница дат между логами (признак чистки)

    ВАЖНО: Образ диска должен быть предварительно открыт.

    Args:
        btmp_paths: Список путей к btmp файлам в образе.
                   Если None, автоматически ищет /var/log/btmp*.
        wtmp_paths: Список путей к wtmp файлам в образе.
                   Если None, автоматически ищет /var/log/wtmp*.

    Returns:
        JSON строка со статистикой входов:
        - success: True если анализ выполнен
        - files_analyzed: Список проанализированных файлов
        - failed_logins_count / successful_logins_count: количество записей
        - failed_by_user / failed_by_host / failed_by_date: статистика неуспешных
        - successful_by_user / successful_by_host / successful_by_date: статистика успешных
        - btmp_wtmp_date_difference_days: разница дат (признак чистки логов)
        - hosts_in_both_btmp_wtmp: хосты с обоими типами попыток
        - user_date_matches_btmp_wtmp: совпадения пользователь+дата

    Example:
        >>> analyze_utmp_logs()
        >>> analyze_utmp_logs(btmp_paths=["/var/log/btmp"], wtmp_paths=["/var/log/wtmp"])
    """
    cache_key = f"analyze_utmp_logs:{btmp_paths}:{wtmp_paths}"
    if cache_key in _log_analyzer_cache:
        return json.dumps({"cached": True, "message": "utmp анализ уже выполнен"}, ensure_ascii=False)

    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    # Автоматический поиск файлов если пути не указаны
    if btmp_paths is None:
        btmp_paths = _find_files_in_dir('/var/log', r'^btmp')
    if wtmp_paths is None:
        wtmp_paths = _find_files_in_dir('/var/log', r'^wtmp')

    logger.info(f"analyze_utmp_logs: btmp={btmp_paths}, wtmp={wtmp_paths}")

    result = _utmp_analysis_impl(btmp_paths, wtmp_paths)
    _log_analyzer_cache[cache_key] = result
    return _truncate_result(result)


# ==================== 2. AUTH.LOG ANALYSIS ====================

def _auth_analysis_impl(auth_paths: List[str]) -> str:
    """Внутренняя реализация анализа auth.log."""
    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    base_pattern = re.compile(
        r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<proc>[\w\-\/]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<msg>.*)$"
    )
    ssh_pattern = re.compile(
        r"(Accepted|Failed) \S+ for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
    )
    sudo_success = re.compile(
        r"(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)$"
    )
    sudo_failure = re.compile(
        r"authentication failure.*user=(?P<user>\S+)"
    )

    CURRENT_YEAR = datetime.now().year
    auth_rows = []
    files_analyzed = []

    def process_lines(lines: List[str]):
        for line in lines:
            m = base_pattern.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(
                    f"{CURRENT_YEAR} {m.group('ts')}", "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                continue

            proc = m.group("proc")
            msg = m.group("msg")

            # SSH
            if proc == "sshd":
                m_ssh = ssh_pattern.search(msg)
                if m_ssh:
                    outcome = "success" if "Accepted" in msg else "failure"
                    auth_rows.append({
                        "time": ts,
                        "service": "ssh",
                        "outcome": outcome,
                        "user": m_ssh.group("user"),
                        "ip": m_ssh.group("ip"),
                        "command": None,
                    })

            # sudo
            if proc == "sudo":
                if sudo_success.search(msg):
                    m_sudo = sudo_success.search(msg)
                    auth_rows.append({
                        "time": ts,
                        "service": "sudo",
                        "outcome": "success",
                        "user": m_sudo.group("user"),
                        "ip": None,
                        "command": m_sudo.group("cmd"),
                    })
                elif sudo_failure.search(msg):
                    m_sudo = sudo_failure.search(msg)
                    auth_rows.append({
                        "time": ts,
                        "service": "sudo",
                        "outcome": "failure",
                        "user": m_sudo.group("user"),
                        "ip": None,
                        "command": None,
                    })

    for path in auth_paths:
        content = None
        if path.endswith('.gz'):
            content = _read_gz_text_from_image(path)
        else:
            content = _read_text_from_image(path)
        if content:
            process_lines(content.splitlines())
            files_analyzed.append(path)

    if not auth_rows:
        return json.dumps({
            "success": True,
            "files_analyzed": files_analyzed,
            "message": "Файлы auth.log не найдены или не содержат записей SSH/sudo",
            "total_events": 0,
        }, ensure_ascii=False)

    df = pd.DataFrame(auth_rows)
    df['date'] = df['time'].dt.date

    result = {
        "success": True,
        "files_analyzed": files_analyzed,
        "total_events": len(auth_rows),
        "ssh_events": int((df['service'] == 'ssh').sum()),
        "sudo_events": int((df['service'] == 'sudo').sum()),
    }

    # Статистика по неуспешным попыткам (SSH)
    df_fail = df[df['outcome'] == 'failure']
    if not df_fail.empty:
        df_fail_user = df_fail.groupby('user').agg(
            unique_hosts=pd.NamedAgg(column='ip', aggfunc=lambda x: x.nunique()),
            active_days=pd.NamedAgg(column='date', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='user', aggfunc='count')
        ).reset_index()
        i = 0
        while len(df_fail_user) > 100:
            df_fail_user = df_fail_user[df_fail_user['total_attempts'] > i]
            i += 1
        result['failed_by_user'] = df_fail_user.to_dict(orient="records")

        df_fail_host = df_fail[df_fail['ip'].notna()].groupby('ip').agg(
            unique_users=pd.NamedAgg(column='user', aggfunc=lambda x: x.nunique()),
            active_days=pd.NamedAgg(column='date', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='ip', aggfunc='count')
        ).reset_index()
        i = 0
        while len(df_fail_host) > 100:
            df_fail_host = df_fail_host[df_fail_host['active_days'] > i]
            i += 1
        result['failed_by_host'] = df_fail_host.to_dict(orient="records")

        df_fail_date = df_fail.groupby('date').agg(
            unique_users=pd.NamedAgg(column='user', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='user', aggfunc='count')
        ).reset_index().sort_values('date', ascending=False)
        result['failed_by_date'] = df_fail_date.to_dict(orient="records")

    # Статистика по успешным входам (SSH)
    df_succ = df[df['outcome'] == 'success']
    if not df_succ.empty:
        df_succ_user = df_succ.groupby('user').agg(
            unique_hosts=pd.NamedAgg(column='ip', aggfunc=lambda x: x.nunique()),
            active_days=pd.NamedAgg(column='date', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='user', aggfunc='count')
        ).reset_index()
        i = 0
        while len(df_succ_user) > 100:
            df_succ_user = df_succ_user[df_succ_user['total_attempts'] > i]
            i += 1
        result['successful_by_user'] = df_succ_user.to_dict(orient="records")

        df_succ_host = df_succ[df_succ['ip'].notna()].groupby('ip').agg(
            unique_users=pd.NamedAgg(column='user', aggfunc=lambda x: x.nunique()),
            active_days=pd.NamedAgg(column='date', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='ip', aggfunc='count')
        ).reset_index()
        i = 0
        while len(df_succ_host) > 100:
            df_succ_host = df_succ_host[df_succ_host['unique_users'] > i]
            i += 1
        result['successful_by_host'] = df_succ_host.to_dict(orient="records")

        df_succ_date = df_succ.groupby('date').agg(
            unique_users=pd.NamedAgg(column='user', aggfunc=lambda x: x.nunique()),
            total_attempts=pd.NamedAgg(column='user', aggfunc='count')
        ).reset_index().sort_values('date', ascending=False)
        result['successful_by_date'] = df_succ_date.to_dict(orient="records")

    # Разница дат
    try:
        max_fail_date = df_fail['date'].max() if not df_fail.empty else None
        max_succ_date = df_succ['date'].max() if not df_succ.empty else None
        if max_fail_date and max_succ_date and pd.notna(max_fail_date) and pd.notna(max_succ_date):
            result['success_fail_date_difference_days'] = (max_succ_date - max_fail_date).days
    except Exception:
        pass

    # Brute-force detection: 4+ неуспешных → успешный вход для одного пользователя
    try:
        df_sorted = df.sort_values("time").reset_index(drop=True)
        brute_results = []
        for _, g in df_sorted.groupby('user'):
            g = g.sort_values("time")
            fail_count = 0
            for _, row in g.iterrows():
                if row["outcome"] == "failure":
                    fail_count += 1
                elif row["outcome"] == "success":
                    if fail_count >= 4:
                        brute_results.append({
                            "user": row["user"],
                            "ip": row.get("ip"),
                            "time": row["time"].isoformat() if hasattr(row["time"], 'isoformat') else str(row["time"]),
                            "failed_attempts_before": fail_count,
                        })
                    fail_count = 0
        if brute_results:
            result['potentially_bruted_accounts'] = brute_results
    except Exception as e:
        logger.debug(f"Brute-force detection error: {e}")

    # Sudo команды
    df_sudo = df[df['service'] == 'sudo']
    if not df_sudo.empty:
        sudo_cmds = df_sudo[df_sudo['command'].notna()][['user', 'command', 'time']].head(50)
        result['sudo_commands'] = sudo_cmds.to_dict(orient="records")

    return json.dumps(result, ensure_ascii=False, default=_safe_date_serializer)


@tool
def analyze_auth_logs_detailed(
    auth_paths: Optional[List[str]] = None,
) -> str:
    """
    Детальный анализ auth.log — SSH-входы, sudo-команды, brute-force detection.

    Парсит auth.log и auth.log.*.gz файлы из образа диска.
    Извлекает:
    - Успешные/неуспешные SSH-входы с IP-адресами
    - Sudo-команды (успешные и неуспешные)
    - Обнаружение brute-force: 4+ неуспешных входа → успешный вход

    Генерирует статистику по пользователям, хостам и дням (pandas).

    ВАЖНО: Образ диска должен быть предварительно открыт.

    Args:
        auth_paths: Список путей к auth.log файлам в образе.
                   Если None, автоматически ищет /var/log/auth.log*.

    Returns:
        JSON строка с результатами анализа:
        - success: True если анализ выполнен
        - files_analyzed: Список файлов
        - total_events / ssh_events / sudo_events: счётчики
        - failed_by_user / failed_by_host / failed_by_date: статистика неуспешных
        - successful_by_user / successful_by_host / successful_by_date: статистика успешных
        - potentially_bruted_accounts: обнаруженные brute-force атаки
        - sudo_commands: список sudo-команд

    Example:
        >>> analyze_auth_logs_detailed()
        >>> analyze_auth_logs_detailed(auth_paths=["/var/log/auth.log", "/var/log/auth.log.1"])
    """
    cache_key = f"analyze_auth_logs_detailed:{auth_paths}"
    if cache_key in _log_analyzer_cache:
        return json.dumps({"cached": True, "message": "auth.log анализ уже выполнен"}, ensure_ascii=False)

    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    if auth_paths is None:
        auth_paths = _find_files_in_dir('/var/log', r'^auth\.log')
        # Также ищем /var/log/secure для RHEL
        auth_paths += _find_files_in_dir('/var/log', r'^secure')

    logger.info(f"analyze_auth_logs_detailed: paths={auth_paths}")
    result = _auth_analysis_impl(auth_paths)
    _log_analyzer_cache[cache_key] = result
    return _truncate_result(result)


# ==================== 3. LASTLOG ANALYSIS ====================

def _lastlog_analysis_impl(lastlog_paths: List[str]) -> str:
    """Внутренняя реализация анализа lastlog."""
    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    lastlog_entries = []
    files_analyzed = []

    # Читаем passwd для маппинга UID→username
    passwd_content = _read_text_from_image('/etc/passwd')
    uid_to_user = {}
    if passwd_content:
        for line in passwd_content.splitlines():
            parts = line.strip().split(':')
            if len(parts) >= 3 and parts[2].isdigit():
                uid_to_user[int(parts[2])] = parts[0]

    for path in lastlog_paths:
        data = _read_binary_from_image(path)
        if not data:
            continue
        files_analyzed.append(path)

        buf = io.BytesIO(data)
        uid = 0
        while True:
            chunk = buf.read(LASTLOG_SIZE)
            if len(chunk) < LASTLOG_SIZE:
                break

            ll_time, ll_line, ll_host = struct.unpack(LASTLOG_STRUCT, chunk)

            if ll_time > 0:
                username = uid_to_user.get(uid, f"uid_{uid}")
                try:
                    ts = datetime.fromtimestamp(ll_time).isoformat()
                except (OSError, OverflowError, ValueError):
                    ts = str(ll_time)

                lastlog_entries.append({
                    "uid": uid,
                    "user": username,
                    "time": ts,
                    "tty": ll_line.rstrip(b"\x00").decode(errors="ignore"),
                    "host": ll_host.rstrip(b"\x00").decode(errors="ignore"),
                })
            uid += 1

    result = {
        "success": True,
        "files_analyzed": files_analyzed,
        "total_entries": len(lastlog_entries),
        "entries": lastlog_entries[:200],  # Ограничиваем
    }

    return json.dumps(result, ensure_ascii=False, default=_safe_date_serializer)


@tool
def analyze_lastlog(
    lastlog_paths: Optional[List[str]] = None,
) -> str:
    """
    Анализ файла lastlog — последние успешные входы пользователей.

    Читает бинарный файл /var/log/lastlog из образа диска.
    Извлекает UID, имя пользователя (из /etc/passwd), время, TTY и хост.

    Используйте для:
    - Определения когда последний раз входили пользователи
    - Выявления подозрительных входов (нестандартные хосты/время)
    - Обнаружения неожиданных активных пользователей

    ВАЖНО: Образ диска должен быть предварительно открыт.

    Args:
        lastlog_paths: Список путей к файлам lastlog.
                      Если None, используется /var/log/lastlog.

    Returns:
        JSON строка с результатами:
        - success: True если анализ выполнен
        - files_analyzed: Список файлов
        - total_entries: Количество записей
        - entries: Список записей [{uid, user, time, tty, host}, ...]

    Example:
        >>> analyze_lastlog()
        >>> analyze_lastlog(lastlog_paths=["/var/log/lastlog"])
    """
    cache_key = f"analyze_lastlog:{lastlog_paths}"
    if cache_key in _log_analyzer_cache:
        return json.dumps({"cached": True, "message": "lastlog анализ уже выполнен"}, ensure_ascii=False)

    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    if lastlog_paths is None:
        lastlog_paths = ['/var/log/lastlog']

    logger.info(f"analyze_lastlog: paths={lastlog_paths}")
    result = _lastlog_analysis_impl(lastlog_paths)
    _log_analyzer_cache[cache_key] = result
    return _truncate_result(result)


# ==================== 4. DPKG ANALYSIS ====================

def _dpkg_analysis_impl(dpkg_paths: List[str]) -> str:
    """Внутренняя реализация анализа dpkg.log."""
    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    dpkg_data = []
    files_analyzed = []

    def parse_dpkg_lines(lines: List[str]):
        for line in lines:
            try:
                parts = line.strip().split()
                if len(parts) >= 4:
                    date_str = parts[0] + " " + parts[1]
                    action = parts[2]
                    package_info = parts[3]
                    if ':' in package_info:
                        package_name = package_info.split(':')[0]
                    else:
                        package_name = package_info
                    dpkg_data.append({
                        "date": date_str,
                        "action": action,
                        "package_name": package_name,
                    })
            except Exception:
                pass

    for path in dpkg_paths:
        content = None
        if path.endswith('.gz'):
            content = _read_gz_text_from_image(path)
        else:
            content = _read_text_from_image(path)
        if content:
            parse_dpkg_lines(content.splitlines())
            files_analyzed.append(path)

    if not dpkg_data:
        return json.dumps({
            "success": True,
            "files_analyzed": files_analyzed,
            "message": "Файлы dpkg.log не найдены или пусты",
            "packages_by_action": {},
        }, ensure_ascii=False)

    df = pd.DataFrame(dpkg_data)
    # Фильтруем только install/remove/purge
    df = df[df['action'].isin(['install', 'remove', 'purge'])]
    df_unique = df[['action', 'package_name']].drop_duplicates()
    packages_by_action = df_unique.groupby('action')['package_name'].apply(list).to_dict()

    result = {
        "success": True,
        "files_analyzed": files_analyzed,
        "total_records": len(dpkg_data),
        "packages_by_action": packages_by_action,
        "installed_count": len(packages_by_action.get('install', [])),
        "removed_count": len(packages_by_action.get('remove', [])),
        "purged_count": len(packages_by_action.get('purge', [])),
    }

    return json.dumps(result, ensure_ascii=False, default=_safe_date_serializer)


@tool
def analyze_dpkg_logs(
    dpkg_paths: Optional[List[str]] = None,
) -> str:
    """
    Анализ dpkg.log — установка/удаление пакетов.

    Парсит файлы dpkg.log и dpkg.log.*.gz для выявления:
    - Установленных пакетов (install) — возможно вредоносное ПО
    - Удалённых пакетов (remove/purge) — возможно удаление защитного ПО

    Используйте для:
    - Обнаружения установки хакерских инструментов (nmap, netcat, hydra и т.д.)
    - Выявления удаления защитного ПО (fail2ban, ufw, apparmor и т.д.)
    - Анализа хронологии изменений системы

    ВАЖНО: Образ диска должен быть предварительно открыт.

    Args:
        dpkg_paths: Список путей к dpkg.log файлам в образе.
                   Если None, автоматически ищет /var/log/dpkg.log*.

    Returns:
        JSON строка с результатами:
        - success: True если анализ выполнен
        - files_analyzed: Список файлов
        - packages_by_action: {install: [...], remove: [...], purge: [...]}
        - installed_count / removed_count / purged_count: счётчики

    Example:
        >>> analyze_dpkg_logs()
        >>> analyze_dpkg_logs(dpkg_paths=["/var/log/dpkg.log", "/var/log/dpkg.log.1"])
    """
    cache_key = f"analyze_dpkg_logs:{dpkg_paths}"
    if cache_key in _log_analyzer_cache:
        return json.dumps({"cached": True, "message": "dpkg анализ уже выполнен"}, ensure_ascii=False)

    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    if dpkg_paths is None:
        dpkg_paths = _find_files_in_dir('/var/log', r'^dpkg\.log')

    logger.info(f"analyze_dpkg_logs: paths={dpkg_paths}")
    result = _dpkg_analysis_impl(dpkg_paths)
    _log_analyzer_cache[cache_key] = result
    return _truncate_result(result)


# ==================== 5. HISTORY ANALYSIS ====================

def _history_analysis_impl(history_paths: List[str]) -> str:
    """Внутренняя реализация анализа .bash_history."""
    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    data = {}
    files_analyzed = []

    # Паттерны подозрительных команд
    suspicious_patterns = [
        # Сканирование
        r'nmap\b', r'masscan\b', r'zmap\b', r'nikto\b',
        # Опасные утилиты
        r'nc\s', r'ncat\b', r'netcat\b', r'socat\b',
        r'curl\b.*\|\s*(ba)?sh', r'wget\b.*\|\s*(ba)?sh',
        # Повышение привилегий
        r'sudo\s+su\b', r'chmod\s+(u\+s|4[0-7]{3}|777)',
        r'/dev/tcp/', r'/dev/udp/',
        # Деструктивные действия
        r'rm\s+-rf\s+/', r'mkfs\b', r'dd\s+if=',
        # Сокрытие следов
        r'history\s+-[cwd]', r'shred\b', r'unset\s+HISTFILE',
        r'export\s+HISTSIZE=0',
        # Закрепление
        r'crontab\s+-[elr]', r'\.bashrc', r'\.profile',
        r'authorized_keys', r'base64\b', r'eval\b',
        # Тоннели
        r'ssh\s+-[RLD]', r'chisel\b', r'ngrok\b',
        # Крипто-майнеры
        r'xmrig\b', r'minerd\b', r'cryptonight',
    ]
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in suspicious_patterns]

    for path in history_paths:
        content = _read_text_from_image(path)
        if not content:
            continue
        files_analyzed.append(path)

        suspicious_commands = []
        all_interesting = []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            # Фильтруем простые ls/cd команды (как в KovalevE)
            if (line.startswith('ls') or line.startswith('cd')) and '|' not in line and '&&' not in line:
                continue

            all_interesting.append(line)

            # Проверяем на подозрительность
            for pattern in compiled_patterns:
                if pattern.search(line):
                    suspicious_commands.append(line)
                    break

        data[path] = {
            "total_commands": len(content.splitlines()),
            "interesting_commands": len(all_interesting),
            "suspicious_commands": suspicious_commands[:100],  # Ограничиваем
            "suspicious_count": len(suspicious_commands),
        }

    total_suspicious = sum(v['suspicious_count'] for v in data.values())
    result = {
        "success": True,
        "files_analyzed": files_analyzed,
        "total_files": len(files_analyzed),
        "total_suspicious_commands": total_suspicious,
        "analysis": data,
    }

    return json.dumps(result, ensure_ascii=False, default=_safe_date_serializer)


@tool
def analyze_history_commands(
    history_paths: Optional[List[str]] = None,
) -> str:
    """
    Анализ .bash_history и других файлов истории команд.

    Фильтрует простые ls/cd команды и ищет подозрительные паттерны:
    - Сканирование инфраструктуры (nmap, masscan, nikto)
    - Опасные утилиты (nc, ncat, socat, curl|sh)
    - Повышение привилегий (sudo su, chmod 777, /dev/tcp)
    - Деструктивные действия (rm -rf /, mkfs, dd)
    - Сокрытие следов (history -c, shred, unset HISTFILE)
    - Закрепление злоумышленника (crontab, authorized_keys, base64)
    - Тоннели (ssh -R/-L, chisel, ngrok)
    - Крипто-майнеры (xmrig, minerd)

    ВАЖНО: Образ диска должен быть предварительно открыт.

    Args:
        history_paths: Список путей к файлам истории в образе.
                      Если None, автоматически ищет в /root/ и /home/*/.

    Returns:
        JSON строка с результатами:
        - success: True если анализ выполнен
        - files_analyzed: Список файлов
        - total_suspicious_commands: Общее число подозрительных команд
        - analysis: {путь: {total_commands, interesting_commands, suspicious_commands, suspicious_count}}

    Example:
        >>> analyze_history_commands()
        >>> analyze_history_commands(history_paths=["/root/.bash_history", "/home/admin/.bash_history"])
    """
    cache_key = f"analyze_history_commands:{history_paths}"
    if cache_key in _log_analyzer_cache:
        return json.dumps({"cached": True, "message": "history анализ уже выполнен"}, ensure_ascii=False)

    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    if history_paths is None:
        # Собираем пути из /root/ и /home/*/
        history_paths = []
        for name in ['.bash_history', '.zsh_history', '.history']:
            root_path = f'/root/{name}'
            if manager.file_exists(root_path):
                history_paths.append(root_path)

        # Ищем в /home/
        home_entries = manager.list_directory('/home')
        for entry in home_entries:
            if entry['type'] == 'directory' and entry['name'] not in ('.', '..'):
                for name in ['.bash_history', '.zsh_history', '.history']:
                    user_path = f"/home/{entry['name']}/{name}"
                    if manager.file_exists(user_path):
                        history_paths.append(user_path)

    logger.info(f"analyze_history_commands: paths={history_paths}")
    result = _history_analysis_impl(history_paths)
    _log_analyzer_cache[cache_key] = result
    return _truncate_result(result)


# ==================== 6. ALTERNATIVES ANALYSIS ====================

def _alternatives_analysis_impl(alt_paths: List[str]) -> str:
    """Внутренняя реализация анализа alternatives.log."""
    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    alt_rows = []
    files_analyzed = []

    pattern = re.compile(
        r"^(?P<tool>\S+)\s+"
        r"(?P<date>\d{4}-\d{2}-\d{2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2}):\s+"
        r"(?P<message>.*)$"
    )

    def process_lines(lines: List[str]):
        for line in lines:
            m = pattern.match(line.strip())
            if not m:
                continue
            try:
                dt = datetime.fromisoformat(f"{m.group('date')} {m.group('time')}")
            except ValueError:
                continue
            alt_rows.append({
                "time": dt.isoformat(),
                "tool": m.group("tool"),
                "message": m.group("message"),
            })

    for path in alt_paths:
        content = None
        if path.endswith('.gz'):
            content = _read_gz_text_from_image(path)
        else:
            content = _read_text_from_image(path)
        if content:
            process_lines(content.splitlines())
            files_analyzed.append(path)

    if not alt_rows:
        return json.dumps({
            "success": True,
            "files_analyzed": files_analyzed,
            "message": "Файлы alternatives.log не найдены или пусты",
            "total_changes": 0,
        }, ensure_ascii=False)

    df = pd.DataFrame(alt_rows)
    unique_messages = df["message"].unique().tolist()

    # Группировка по инструменту
    changes_by_tool = {}
    for tool_name, group in df.groupby('tool'):
        changes_by_tool[tool_name] = group['message'].unique().tolist()

    result = {
        "success": True,
        "files_analyzed": files_analyzed,
        "total_changes": len(alt_rows),
        "unique_changes": len(unique_messages),
        "alternatives_messages": unique_messages[:200],
        "changes_by_tool": changes_by_tool,
    }

    return json.dumps(result, ensure_ascii=False, default=_safe_date_serializer)


@tool
def analyze_alternatives_logs(
    alt_paths: Optional[List[str]] = None,
) -> str:
    """
    Анализ alternatives.log — изменения в update-alternatives.

    Парсит файлы alternatives.log и alternatives.log.*.gz.
    Выявляет критичные изменения в системном ПО, которые могут
    повлиять на безопасность ОС (подмена компиляторов, редакторов,
    интерпретаторов и т.д.).

    ВАЖНО: Образ диска должен быть предварительно открыт.

    Args:
        alt_paths: Список путей к файлам alternatives.log.
                  Если None, автоматически ищет /var/log/alternatives.log*.

    Returns:
        JSON строка с результатами:
        - success: True если анализ выполнен
        - files_analyzed: Список файлов
        - total_changes / unique_changes: счётчики
        - alternatives_messages: Список уникальных сообщений
        - changes_by_tool: Группировка по инструменту

    Example:
        >>> analyze_alternatives_logs()
        >>> analyze_alternatives_logs(alt_paths=["/var/log/alternatives.log"])
    """
    cache_key = f"analyze_alternatives_logs:{alt_paths}"
    if cache_key in _log_analyzer_cache:
        return json.dumps({"cached": True, "message": "alternatives анализ уже выполнен"}, ensure_ascii=False)

    manager = get_image_manager()
    if not manager.is_open:
        return json.dumps({"success": False, "error": "Image not open"}, ensure_ascii=False)

    if alt_paths is None:
        alt_paths = _find_files_in_dir('/var/log', r'^alternatives\.log')

    logger.info(f"analyze_alternatives_logs: paths={alt_paths}")
    result = _alternatives_analysis_impl(alt_paths)
    _log_analyzer_cache[cache_key] = result
    return _truncate_result(result)
