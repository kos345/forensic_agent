"""
Report Generator — Генерация всеобъемлющего HTML-отчёта.

Формирует отчёт со следующими секциями:
1. Общая картина (аномалии, статистика, рекомендации)
2. Сведения о системе (ОС, пользователи, shadow, сервисы, cron, пакеты, Docker)
3. Информация о файлах (корень, /home/, /root/, нестандартные)
4. Подключения к системе (SSH successful logins)
5. Данные об активности пользователей (история, публичные IP, саммари)
6. Подозрительные находки (из расследования)
7. Экспертное заключение (Deep Agent / LLM)
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import html as html_lib

from src.utils.logger import get_logger

logger = get_logger("ReportGenerator")


def _escape(text: str) -> str:
    """HTML-экранирование текста."""
    if not isinstance(text, str):
        text = str(text)
    return html_lib.escape(text)


def _try_parse_json(data) -> Any:
    """Попытаться распарсить JSON-строку, иначе вернуть как есть."""
    if isinstance(data, str):
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return data
    return data


def _severity_badge(severity: str) -> str:
    """HTML-бейдж для уровня severity."""
    colors = {
        'critical': ('#ff4757', '#fff'),
        'high': ('#ff6b6b', '#1a1a2e'),
        'medium': ('#feca57', '#1a1a2e'),
        'low': ('#1dd1a1', '#1a1a2e'),
        'info': ('#00d9ff', '#1a1a2e'),
    }
    bg, fg = colors.get(severity.lower(), ('#888', '#fff'))
    return f'<span style="background:{bg};color:{fg};padding:2px 10px;border-radius:12px;font-size:11px;font-weight:bold;text-transform:uppercase;">{_escape(severity)}</span>'


def generate_comprehensive_html_report(report_data: Dict[str, Any]) -> str:
    """
    Генерация всеобъемлющего HTML-отчёта.
    
    Args:
        report_data: Словарь с полными данными отчёта:
            - triage_data: baseline артефакты
            - analysis_result: результат алгоритмического анализа
            - llm_analyses: результаты LLM-анализа по секциям
            - investigated_paths: исследованные пути
            - suspicious_findings: подозрительные находки
            - deep_agent_output: текст экспертного заключения
    
    Returns:
        HTML строка
    """
    triage_data = report_data.get('triage_data', {}) or {}
    analysis_result = report_data.get('analysis_result', {}) or {}
    llm_analyses = report_data.get('llm_analyses', {}) or {}
    investigated_paths = report_data.get('investigated_paths', []) or []
    suspicious_findings = report_data.get('suspicious_findings', []) or []
    deep_agent_output = report_data.get('deep_agent_output', '') or ''
    
    summary = analysis_result.get('summary', {})
    stats = analysis_result.get('statistics', {})
    anomalies = analysis_result.get('anomalies', [])
    recommendations = analysis_result.get('recommendations', [])
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # ==================== HTML ====================
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forseti — Comprehensive Forensic Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0; padding: 20px;
            background-color: #1a1a2e; color: #eaeaea;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; background-color: #16213e;
            padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }}
        h1 {{ color: #00d9ff; border-bottom: 3px solid #00d9ff; padding-bottom: 15px; margin-bottom: 30px; }}
        h2 {{ color: #ff6b6b; margin-top: 40px; margin-bottom: 20px; border-left: 4px solid #ff6b6b; padding-left: 15px; }}
        h3 {{ color: #feca57; margin-top: 20px; }}
        h4 {{ color: #00d9ff; margin-top: 15px; }}
        .meta {{ color: #888; margin-bottom: 30px; }}
        .summary {{ display: flex; flex-wrap: wrap; gap: 15px; margin: 25px 0; }}
        .stat {{ flex: 1; min-width: 150px; padding: 20px; background: linear-gradient(135deg, #1f4068 0%, #162447 100%);
            border-radius: 10px; text-align: center; border: 1px solid #2d4a6f; }}
        .stat-label {{ font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #00d9ff; }}
        .stat-value.warning {{ color: #feca57; }}
        .stat-value.danger {{ color: #ff6b6b; }}
        .stat-value.success {{ color: #1dd1a1; }}
        .anomaly {{ padding: 15px 20px; margin: 10px 0; border-radius: 8px; border-left: 4px solid; }}
        .anomaly.high, .anomaly.critical {{ background-color: rgba(255,107,107,0.15); border-color: #ff6b6b; }}
        .anomaly.medium {{ background-color: rgba(254,202,87,0.15); border-color: #feca57; }}
        .anomaly.low {{ background-color: rgba(29,209,161,0.15); border-color: #1dd1a1; }}
        .anomaly.info {{ background-color: rgba(0,217,255,0.1); border-color: #00d9ff; }}
        .anomaly-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .anomaly-type {{ font-weight: bold; color: #fff; }}
        .finding {{ padding: 15px 20px; margin: 10px 0; border-radius: 8px; border-left: 4px solid; }}
        .finding.critical {{ background-color: rgba(255,71,87,0.2); border-color: #ff4757; }}
        .finding.high {{ background-color: rgba(255,107,107,0.15); border-color: #ff6b6b; }}
        .finding.medium {{ background-color: rgba(254,202,87,0.15); border-color: #feca57; }}
        .finding.low {{ background-color: rgba(29,209,161,0.15); border-color: #1dd1a1; }}
        .finding.info {{ background-color: rgba(0,217,255,0.1); border-color: #00d9ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background-color: #1f4068;
            border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #2d4a6f; }}
        th {{ background-color: #0f3460; color: #00d9ff; font-weight: 600; text-transform: uppercase;
            font-size: 12px; letter-spacing: 0.5px; }}
        tr:hover {{ background-color: rgba(0,217,255,0.05); }}
        td code, p code {{ background-color: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;
            font-family: 'Consolas', monospace; font-size: 12px; }}
        .code-block {{ background-color: #0f0f23; padding: 15px; border-radius: 8px; overflow-x: auto;
            font-family: 'Consolas', monospace; font-size: 13px; line-height: 1.5;
            border: 1px solid #2d4a6f; color: #00ff00; white-space: pre-wrap; word-break: break-all; }}
        .recommendation {{ padding: 12px 20px; margin: 8px 0; background-color: rgba(0,217,255,0.1);
            border-left: 4px solid #00d9ff; border-radius: 0 8px 8px 0; }}
        .recommendation.critical {{ background-color: rgba(255,107,107,0.15); border-color: #ff6b6b; }}
        .info-box {{ padding: 15px 20px; margin: 15px 0; border-radius: 8px;
            background-color: rgba(29,209,161,0.1); border: 1px solid #1dd1a1; }}
        .info-box.docker {{ background-color: rgba(0,150,255,0.1); border-color: #0096ff; }}
        .info-box.ssh {{ background-color: rgba(255,159,67,0.1); border-color: #ff9f43; }}
        .info-box.expert {{ background-color: rgba(0,217,255,0.08); border-color: #00d9ff; }}
        .llm-text {{ background-color: #0f0f23; padding: 15px; border-radius: 8px;
            border: 1px solid #2d4a6f; color: #eaeaea; white-space: pre-wrap; line-height: 1.6; }}
        .tag {{ display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 4px;
            font-size: 11px; background-color: rgba(0,217,255,0.2); color: #00d9ff; }}
        .tag.suspicious {{ background-color: rgba(255,107,107,0.2); color: #ff6b6b; }}
        .toc {{ background-color: #1f4068; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .toc a {{ color: #00d9ff; text-decoration: none; }}
        .toc a:hover {{ text-decoration: underline; }}
        .toc ul {{ list-style: none; padding-left: 20px; }}
        .toc > ul {{ padding-left: 0; }}
        .toc li {{ margin: 5px 0; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #2d4a6f;
            text-align: center; color: #666; font-size: 12px; }}
        .section-divider {{ height: 2px; background: linear-gradient(90deg, transparent, #2d4a6f, transparent);
            margin: 40px 0; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔬 Forseti — Comprehensive Forensic Report</h1>
    <p class="meta">
        <strong>Дата генерации:</strong> {now} |
        <strong>Дата анализа:</strong> {_escape(summary.get('analysis_date', now))} |
        <strong>Находок:</strong> {len(suspicious_findings)} |
        <strong>Исследовано путей:</strong> {len(investigated_paths)}
    </p>
"""
    
    # ==================== TABLE OF CONTENTS ====================
    html += """
    <div class="toc">
        <h3 style="margin-top:0;">📑 Содержание</h3>
        <ul>
            <li><a href="#overview">1. Общая картина</a></li>
            <li><a href="#system-info">2. Сведения о системе</a>
                <ul>
                    <li><a href="#os-info">2.1 Версия ОС</a></li>
                    <li><a href="#users">2.2 Пользователи и хеши паролей</a></li>
                    <li><a href="#services">2.3 Системные сервисы</a></li>
                    <li><a href="#cron">2.4 Запланированные задачи (cron)</a></li>
                    <li><a href="#packages">2.5 Подозрительные пакеты</a></li>
                    <li><a href="#web-software">2.6 Веб-серверы и ПО</a></li>
                    <li><a href="#docker">2.7 Docker</a></li>
                </ul>
            </li>
            <li><a href="#files">3. Информация о файлах</a>
                <ul>
                    <li><a href="#root-files">3.1 Нестандартные файлы в корне</a></li>
                    <li><a href="#home-files">3.2 Файловая структура /home/</a></li>
                    <li><a href="#root-home">3.3 Файловая структура /root/</a></li>
                    <li><a href="#nonstandard-home">3.4 Нестандартные файлы пользователей</a></li>
                </ul>
            </li>
            <li><a href="#connections">4. Подключения к системе (SSH)</a></li>
            <li><a href="#user-activity">5. Активность пользователей</a>
                <ul>
                    <li><a href="#cmd-history">5.1 История команд</a></li>
                    <li><a href="#public-ips">5.2 Публичные IP-адреса</a></li>
                    <li><a href="#user-summaries">5.3 Саммари по пользователям</a></li>
                </ul>
            </li>
            <li><a href="#findings">6. Подозрительные находки</a></li>
            <li><a href="#expert">7. Экспертное заключение</a></li>
            <li><a href="#explored">8. Исследованные пути</a></li>
        </ul>
    </div>
"""
    
    # ==================== 1. ОБЩАЯ КАРТИНА ====================
    html += '<div class="section-divider"></div>'
    html += '<h2 id="overview">1. 🔍 Общая картина</h2>'
    
    anomaly_count = len(anomalies)
    findings_count = len(suspicious_findings)
    anomaly_class = "danger" if anomaly_count > 5 else ("warning" if anomaly_count > 0 else "success")
    findings_class = "danger" if findings_count > 3 else ("warning" if findings_count > 0 else "success")
    
    html += f"""
    <div class="summary">
        <div class="stat">
            <div class="stat-label">Пользователей</div>
            <div class="stat-value">{summary.get('total_users', 0)}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Команд</div>
            <div class="stat-value">{summary.get('total_commands', 0)}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Сервисов</div>
            <div class="stat-value">{summary.get('total_services', 0)}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Аномалий</div>
            <div class="stat-value {anomaly_class}">{anomaly_count}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Находок</div>
            <div class="stat-value {findings_class}">{findings_count}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Исследовано</div>
            <div class="stat-value success">{len(investigated_paths)}</div>
        </div>
    </div>
"""
    
    # Аномалии
    if anomalies:
        html += '<h3>⚠️ Обнаруженные аномалии</h3><div class="anomalies">'
        for a in anomalies:
            sev = a.get('severity', 'medium')
            atype = a.get('type', 'unknown')
            html += f'<div class="anomaly {sev}">'
            html += f'<div class="anomaly-header"><span class="anomaly-type">{_escape(atype.replace("_"," ").title())}</span>{_severity_badge(sev)}</div>'
            if a.get('description'):
                html += f'<p>{_escape(a["description"])}</p>'
            if a.get('user'):
                html += f'<p><strong>User:</strong> <code>{_escape(a["user"])}</code></p>'
            if a.get('command'):
                html += f'<p><strong>Command:</strong> <code>{_escape(a["command"])}</code></p>'
            if a.get('service'):
                html += f'<p><strong>Service:</strong> <code>{_escape(a["service"])}</code></p>'
            html += '</div>'
        html += '</div>'
    
    # Рекомендации
    if recommendations:
        html += '<h3>📋 Рекомендации</h3><div class="recommendations">'
        for rec in recommendations:
            css = "critical" if "CRITICAL" in rec.upper() else ""
            html += f'<div class="recommendation {css}">{_escape(rec)}</div>'
        html += '</div>'
    
    # ==================== 2. СВЕДЕНИЯ О СИСТЕМЕ ====================
    html += '<div class="section-divider"></div>'
    html += '<h2 id="system-info">2. 🖥️ Сведения о системе</h2>'
    
    # 2.1 ОС
    html += '<h3 id="os-info">2.1 Версия ОС</h3>'
    os_info = triage_data.get('os_info', {})
    if os_info:
        for file_path, content in os_info.items():
            if content:
                html += f'<h4>{_escape(file_path)}</h4><div class="code-block">{_escape(str(content))}</div>'
    else:
        html += '<p><em>Информация об ОС не собрана</em></p>'
    
    # 2.2 Пользователи и shadow
    html += '<h3 id="users">2.2 Пользователи и хеши паролей</h3>'
    
    passwd = triage_data.get('passwd', '')
    if passwd:
        # Парсим пользователей в таблицу
        html += '<h4>/etc/passwd</h4><table><tr><th>Имя</th><th>UID</th><th>GID</th><th>Home</th><th>Shell</th></tr>'
        for line in passwd.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 7:
                    user, _, uid, gid, _, home, shell = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
                    row_style = ' style="background-color:rgba(255,107,107,0.2);"' if uid == '0' and user != 'root' else ''
                    html += f'<tr{row_style}><td><code>{_escape(user)}</code></td><td>{_escape(uid)}</td><td>{_escape(gid)}</td><td><code>{_escape(home)}</code></td><td><code>{_escape(shell)}</code></td></tr>'
        html += '</table>'
    
    shadow = triage_data.get('shadow', '')
    if shadow:
        html += '<h4>/etc/shadow (хеши паролей)</h4><table><tr><th>Пользователь</th><th>Хеш пароля</th></tr>'
        for line in shadow.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 2:
                    user = parts[0]
                    pwd_hash = parts[1]
                    if pwd_hash and pwd_hash not in ('*', '!', '!!', ''):
                        html += f'<tr><td><code>{_escape(user)}</code></td><td><code>{_escape(pwd_hash[:60])}{"..." if len(pwd_hash)>60 else ""}</code></td></tr>'
        html += '</table>'
    else:
        html += '<p><em>/etc/shadow не доступен</em></p>'
    
    # 2.3 Сервисы
    html += '<h3 id="services">2.3 Системные сервисы</h3>'
    services_analysis = _try_parse_json(llm_analyses.get('services', ''))
    services_data = triage_data.get('services', {})
    
    if services_analysis:
        if isinstance(services_analysis, list):
            html += '<table><tr><th>Сервис</th><th>Описание</th><th>Статус</th></tr>'
            for svc in services_analysis:
                name = svc.get('name', '') if isinstance(svc, dict) else str(svc)
                desc = svc.get('description', '') if isinstance(svc, dict) else ''
                suspicious = svc.get('suspicious', False) if isinstance(svc, dict) else False
                tag = '<span class="tag suspicious">подозрительный</span>' if suspicious else '<span class="tag">нестандартный</span>'
                html += f'<tr><td><code>{_escape(str(name))}</code></td><td>{_escape(str(desc))}</td><td>{tag}</td></tr>'
            html += '</table>'
        else:
            html += f'<div class="llm-text">{_escape(str(services_analysis))}</div>'
    elif services_data:
        # Fallback: raw services data
        systemd = services_data.get('systemd', [])
        if systemd:
            html += f'<p>Всего сервисов: <strong>{services_data.get("total_services", len(systemd))}</strong></p>'
            html += '<div class="code-block">'
            for svc in systemd[:50]:
                html += _escape(str(svc)) + '\n'
            if len(systemd) > 50:
                html += f'... и ещё {len(systemd)-50} сервисов\n'
            html += '</div>'
    else:
        html += '<p><em>Данные о сервисах не собраны</em></p>'
    
    # 2.4 Cron
    html += '<h3 id="cron">2.4 Запланированные задачи (cron)</h3>'
    cron_analysis = _try_parse_json(llm_analyses.get('cron', ''))
    cron_data = triage_data.get('cron', {})
    
    if cron_analysis:
        if isinstance(cron_analysis, list):
            html += '<table><tr><th>Расписание</th><th>Команда</th><th>Описание</th><th>Статус</th></tr>'
            for job in cron_analysis:
                sched = job.get('schedule', '') if isinstance(job, dict) else ''
                cmd = job.get('command', '') if isinstance(job, dict) else str(job)
                desc = job.get('description', '') if isinstance(job, dict) else ''
                suspicious = job.get('suspicious', False) if isinstance(job, dict) else False
                tag = '<span class="tag suspicious">подозрительный</span>' if suspicious else ''
                html += f'<tr><td><code>{_escape(str(sched))}</code></td><td><code>{_escape(str(cmd)[:80])}</code></td><td>{_escape(str(desc))}</td><td>{tag}</td></tr>'
            html += '</table>'
        else:
            html += f'<div class="llm-text">{_escape(str(cron_analysis))}</div>'
    elif cron_data:
        html += f'<div class="code-block">{_escape(json.dumps(cron_data, ensure_ascii=False, indent=2)[:3000])}</div>'
    else:
        html += '<p><em>Данные cron не собраны</em></p>'
    
    # 2.5 Пакеты
    html += '<h3 id="packages">2.5 Подозрительные пакеты</h3>'
    packages_analysis = _try_parse_json(llm_analyses.get('packages', ''))
    
    if packages_analysis:
        if isinstance(packages_analysis, list):
            html += '<table><tr><th>Пакет</th><th>Описание</th><th>Причина</th></tr>'
            for pkg in packages_analysis:
                name = pkg.get('name', '') if isinstance(pkg, dict) else str(pkg)
                desc = pkg.get('description', '') if isinstance(pkg, dict) else ''
                reason = pkg.get('reason', '') if isinstance(pkg, dict) else ''
                html += f'<tr><td><code>{_escape(str(name))}</code></td><td>{_escape(str(desc))}</td><td>{_escape(str(reason))}</td></tr>'
            html += '</table>'
        else:
            html += f'<div class="llm-text">{_escape(str(packages_analysis))}</div>'
    else:
        html += '<p><em>Анализ пакетов не выполнен</em></p>'
    
    # 2.6 Веб-серверы и ПО
    html += '<h3 id="web-software">2.6 Веб-серверы и специализированное ПО</h3>'
    web_analysis = _try_parse_json(llm_analyses.get('web_software', ''))
    
    if web_analysis:
        if isinstance(web_analysis, list):
            html += '<table><tr><th>Название</th><th>Тип</th><th>Описание</th></tr>'
            for sw in web_analysis:
                name = sw.get('name', '') if isinstance(sw, dict) else str(sw)
                stype = sw.get('type', '') if isinstance(sw, dict) else ''
                desc = sw.get('description', '') if isinstance(sw, dict) else ''
                html += f'<tr><td><code>{_escape(str(name))}</code></td><td>{_escape(str(stype))}</td><td>{_escape(str(desc))}</td></tr>'
            html += '</table>'
        else:
            html += f'<div class="llm-text">{_escape(str(web_analysis))}</div>'
    else:
        html += '<p><em>Анализ ПО не выполнен</em></p>'
    
    # 2.7 Docker
    html += '<h3 id="docker">2.7 Docker</h3>'
    docker_data = triage_data.get('docker', {})
    if docker_data and docker_data.get('docker_installed'):
        containers = docker_data.get('containers', [])
        images = docker_data.get('images', [])
        html += f"""
        <div class="info-box docker">
            <p><strong>Docker установлен:</strong> Да</p>
            <p><strong>Контейнеров:</strong> {len(containers)}</p>
            <p><strong>Образов:</strong> {len(images)}</p>
        </div>
"""
        if containers:
            html += '<h4>Контейнеры</h4><div class="code-block">'
            for c in containers:
                html += _escape(json.dumps(c, ensure_ascii=False)) + '\n'
            html += '</div>'
        if images:
            html += '<h4>Образы</h4><div class="code-block">'
            for img in images:
                html += _escape(json.dumps(img, ensure_ascii=False)) + '\n'
            html += '</div>'
    elif docker_data:
        html += '<div class="info-box"><p>Docker не установлен в системе</p></div>'
    else:
        html += '<p><em>Данные Docker не собраны</em></p>'
    
    # ==================== 3. ИНФОРМАЦИЯ О ФАЙЛАХ ====================
    html += '<div class="section-divider"></div>'
    html += '<h2 id="files">3. 📁 Информация о файлах</h2>'
    
    # 3.1 Нестандартные файлы в корне
    html += '<h3 id="root-files">3.1 Нестандартные директории и файлы в корневой директории</h3>'
    root_analysis = _try_parse_json(llm_analyses.get('nonstandard_root', ''))
    
    if root_analysis:
        if isinstance(root_analysis, list):
            html += '<table><tr><th>Имя</th><th>Тип</th><th>Описание</th><th>Статус</th></tr>'
            for item in root_analysis:
                name = item.get('name', '') if isinstance(item, dict) else str(item)
                itype = item.get('type', '') if isinstance(item, dict) else ''
                desc = item.get('description', '') if isinstance(item, dict) else ''
                suspicious = item.get('suspicious', False) if isinstance(item, dict) else False
                tag = '<span class="tag suspicious">подозрительный</span>' if suspicious else ''
                html += f'<tr><td><code>{_escape(str(name))}</code></td><td>{_escape(str(itype))}</td><td>{_escape(str(desc))}</td><td>{tag}</td></tr>'
            html += '</table>'
        else:
            html += f'<div class="llm-text">{_escape(str(root_analysis))}</div>'
    else:
        html += '<p><em>Анализ корневой директории не выполнен</em></p>'
    
    # 3.2 /home/
    html += '<h3 id="home-files">3.2 Файловая структура /home/</h3>'
    extracted_files = triage_data.get('extracted_files', {})
    if extracted_files:
        html += f'<div class="code-block">{_escape(json.dumps(extracted_files, ensure_ascii=False, indent=2)[:5000])}</div>'
    else:
        # Try to show from investigated paths
        home_paths = [p for p in investigated_paths if p.get('path', '').startswith('/home')]
        if home_paths:
            html += '<table><tr><th>Путь</th><th>Описание</th><th>Подозрительно</th></tr>'
            for p in home_paths:
                susp = '⚠️ Да' if p.get('suspicious') else 'Нет'
                html += f'<tr><td><code>{_escape(p.get("path",""))}</code></td><td>{_escape(p.get("description",""))}</td><td>{susp}</td></tr>'
            html += '</table>'
        else:
            html += '<p><em>Файловая структура /home/ не исследована</em></p>'
    
    # 3.3 /root/
    html += '<h3 id="root-home">3.3 Файловая структура /root/</h3>'
    root_paths = [p for p in investigated_paths if p.get('path', '').startswith('/root')]
    if root_paths:
        html += '<table><tr><th>Путь</th><th>Описание</th><th>Подозрительно</th></tr>'
        for p in root_paths:
            susp = '⚠️ Да' if p.get('suspicious') else 'Нет'
            html += f'<tr><td><code>{_escape(p.get("path",""))}</code></td><td>{_escape(p.get("description",""))}</td><td>{susp}</td></tr>'
        html += '</table>'
    else:
        html += '<p><em>Файловая структура /root/ не исследована</em></p>'
    
    # 3.4 Нестандартные файлы пользователей
    html += '<h3 id="nonstandard-home">3.4 Нестандартные файлы в директориях пользователей</h3>'
    home_analysis = _try_parse_json(llm_analyses.get('nonstandard_home', ''))
    
    if home_analysis:
        if isinstance(home_analysis, list):
            html += '<table><tr><th>Путь</th><th>Тип</th><th>Описание</th><th>Статус</th></tr>'
            for item in home_analysis:
                name = item.get('name', item.get('path', '')) if isinstance(item, dict) else str(item)
                itype = item.get('type', '') if isinstance(item, dict) else ''
                desc = item.get('description', '') if isinstance(item, dict) else ''
                suspicious = item.get('suspicious', False) if isinstance(item, dict) else False
                tag = '<span class="tag suspicious">подозрительный</span>' if suspicious else ''
                html += f'<tr><td><code>{_escape(str(name))}</code></td><td>{_escape(str(itype))}</td><td>{_escape(str(desc))}</td><td>{tag}</td></tr>'
            html += '</table>'
        else:
            html += f'<div class="llm-text">{_escape(str(home_analysis))}</div>'
    else:
        html += '<p><em>Анализ нестандартных файлов пользователей не выполнен</em></p>'
    
    # ==================== 4. ПОДКЛЮЧЕНИЯ (SSH) ====================
    html += '<div class="section-divider"></div>'
    html += '<h2 id="connections">4. 🌐 Подключения к системе (SSH)</h2>'
    
    ssh_logins = _try_parse_json(llm_analyses.get('ssh_logins', ''))
    
    if ssh_logins and isinstance(ssh_logins, dict):
        logins = ssh_logins.get('logins', [])
        total = ssh_logins.get('total_logins', len(logins))
        unique_users = ssh_logins.get('unique_users', [])
        unique_ips = ssh_logins.get('unique_ips', [])
        
        html += f"""
        <div class="info-box ssh">
            <p><strong>Успешных SSH-входов:</strong> {total}</p>
            <p><strong>Уникальных пользователей:</strong> {len(unique_users)} ({', '.join(f'<code>{_escape(u)}</code>' for u in unique_users[:10])})</p>
            <p><strong>Уникальных IP:</strong> {len(unique_ips)} ({', '.join(f'<code>{_escape(ip)}</code>' for ip in unique_ips[:10])})</p>
        </div>
"""
        if logins:
            html += '<table><tr><th>Время</th><th>Пользователь</th><th>IP</th><th>Порт</th><th>Метод</th></tr>'
            for login in logins[:100]:
                html += f'<tr><td>{_escape(str(login.get("timestamp","")))}</td>'
                html += f'<td><code>{_escape(str(login.get("user","")))}</code></td>'
                html += f'<td><code>{_escape(str(login.get("ip","")))}</code></td>'
                html += f'<td>{_escape(str(login.get("port","")))}</td>'
                html += f'<td>{_escape(str(login.get("method","")))}</td></tr>'
            if len(logins) > 100:
                html += f'<tr><td colspan="5" style="text-align:center;color:#888;">... и ещё {len(logins)-100} записей</td></tr>'
            html += '</table>'
        
        # Summary by IP
        summary_by_ip = ssh_logins.get('summary_by_ip', {})
        if summary_by_ip:
            html += '<h4>Сводка по IP-адресам</h4><table><tr><th>IP</th><th>Количество входов</th></tr>'
            for ip, cnt in sorted(summary_by_ip.items(), key=lambda x: x[1], reverse=True):
                html += f'<tr><td><code>{_escape(ip)}</code></td><td>{cnt}</td></tr>'
            html += '</table>'
    else:
        html += '<p><em>Данные об SSH-подключениях не доступны</em></p>'
    
    # ==================== 5. АКТИВНОСТЬ ПОЛЬЗОВАТЕЛЕЙ ====================
    html += '<div class="section-divider"></div>'
    html += '<h2 id="user-activity">5. 👤 Активность пользователей</h2>'
    
    # 5.1 История команд
    html += '<h3 id="cmd-history">5.1 История команд</h3>'
    history_data = triage_data.get('history', {})
    if history_data:
        for user, commands in history_data.items():
            if not commands:
                continue
            cmd_list = commands if isinstance(commands, list) else [c.strip() for c in str(commands).split('\n') if c.strip()]
            html += f'<h4>Пользователь: {_escape(user)} ({len(cmd_list)} команд)</h4>'
            display = cmd_list[:50]
            html += '<div class="code-block">'
            html += '\n'.join(f'$ {_escape(cmd)}' for cmd in display)
            if len(cmd_list) > 50:
                html += f'\n\n... и ещё {len(cmd_list)-50} команд'
            html += '</div>'
    else:
        html += '<p><em>История команд не собрана</em></p>'
    
    # 5.2 Публичные IP
    html += '<h3 id="public-ips">5.2 Публичные IP-адреса из команд</h3>'
    public_ips = _try_parse_json(llm_analyses.get('public_ips', ''))
    
    if public_ips and isinstance(public_ips, dict):
        ips = public_ips.get('public_ips', [])
        if ips:
            html += f'<p>Обнаружено <strong>{len(ips)}</strong> публичных IP-адресов:</p>'
            html += '<table><tr><th>IP-адрес</th></tr>'
            for ip in ips:
                html += f'<tr><td><code>{_escape(str(ip))}</code></td></tr>'
            html += '</table>'
        else:
            html += '<p>Публичных IP-адресов не обнаружено</p>'
    else:
        html += '<p><em>Извлечение IP-адресов не выполнено</em></p>'
    
    # 5.3 Саммари по пользователям
    html += '<h3 id="user-summaries">5.3 Саммари по пользователям (LLM)</h3>'
    user_summaries = _try_parse_json(llm_analyses.get('user_summaries', ''))
    
    if user_summaries and isinstance(user_summaries, dict):
        for user, summary_text in user_summaries.items():
            html += f'<h4>Пользователь: {_escape(user)}</h4>'
            html += f'<div class="llm-text">{_escape(str(summary_text))}</div>'
    else:
        html += '<p><em>Саммари по пользователям не сформированы</em></p>'
    
    # ==================== 6. ПОДОЗРИТЕЛЬНЫЕ НАХОДКИ ====================
    html += '<div class="section-divider"></div>'
    html += '<h2 id="findings">6. 🚨 Подозрительные находки</h2>'
    
    if suspicious_findings:
        # Сортируем по severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(suspicious_findings, key=lambda f: severity_order.get(f.get('severity', 'info'), 5))
        
        html += f'<p>Всего находок: <strong>{len(sorted_findings)}</strong></p>'
        
        for f in sorted_findings:
            sev = f.get('severity', 'info')
            html += f'<div class="finding {sev}">'
            html += f'<div style="display:flex;justify-content:space-between;align-items:center;">'
            html += f'<strong>[{_escape(f.get("id",""))}] {_escape(f.get("title",""))}</strong>'
            html += f'{_severity_badge(sev)}'
            html += '</div>'
            html += f'<p><strong>Категория:</strong> {_escape(f.get("category",""))}</p>'
            html += f'<p>{_escape(f.get("details",""))}</p>'
            
            evidence = f.get('evidence', [])
            if evidence:
                html += '<p><strong>Доказательства:</strong></p><div class="code-block">'
                for e in evidence:
                    html += _escape(str(e)) + '\n'
                html += '</div>'
            
            related_paths = f.get('related_paths', [])
            if related_paths:
                html += '<p><strong>Связанные пути:</strong> '
                html += ', '.join(f'<code>{_escape(str(p))}</code>' for p in related_paths)
                html += '</p>'
            
            related_findings = f.get('related_findings', [])
            if related_findings:
                html += '<p><strong>Связанные находки:</strong> '
                html += ', '.join(f'<code>{_escape(str(rf))}</code>' for rf in related_findings)
                html += '</p>'
            
            html += '</div>'
    else:
        html += '<p><em>Подозрительных находок не зарегистрировано</em></p>'
    
    # ==================== 7. ЭКСПЕРТНОЕ ЗАКЛЮЧЕНИЕ ====================
    html += '<div class="section-divider"></div>'
    html += '<h2 id="expert">7. 🧠 Экспертное заключение</h2>'
    
    expert_analysis = llm_analyses.get('expert_analysis', '')
    if expert_analysis:
        html += f'<div class="info-box expert"><div class="llm-text">{_escape(str(expert_analysis))}</div></div>'
    elif deep_agent_output:
        html += f'<div class="info-box expert"><div class="llm-text">{_escape(str(deep_agent_output)[:10000])}</div></div>'
    else:
        html += '<p><em>Экспертное заключение не сформировано</em></p>'
    
    # Correlation
    correlation = _try_parse_json(llm_analyses.get('correlation', ''))
    if correlation:
        html += '<h3>Взаимосвязи и хронология</h3>'
        if isinstance(correlation, dict):
            html += f'<div class="llm-text">{_escape(json.dumps(correlation, ensure_ascii=False, indent=2))}</div>'
        else:
            html += f'<div class="llm-text">{_escape(str(correlation))}</div>'
    
    # ==================== 8. ИССЛЕДОВАННЫЕ ПУТИ ====================
    html += '<div class="section-divider"></div>'
    html += '<h2 id="explored">8. 🗺️ Исследованные пути</h2>'
    
    if investigated_paths:
        html += f'<p>Всего исследовано: <strong>{len(investigated_paths)}</strong> путей</p>'
        html += '<table><tr><th>Путь</th><th>Описание</th><th>Подозрительно</th><th>Время</th></tr>'
        for p in investigated_paths:
            susp = '⚠️ Да' if p.get('suspicious') else '✓ Нет'
            susp_style = ' style="color:#ff6b6b;"' if p.get('suspicious') else ' style="color:#1dd1a1;"'
            html += f'<tr><td><code>{_escape(str(p.get("path","")))}</code></td>'
            html += f'<td>{_escape(str(p.get("description","")))}</td>'
            html += f'<td{susp_style}>{susp}</td>'
            html += f'<td>{_escape(str(p.get("timestamp","")))}</td></tr>'
        html += '</table>'
    else:
        html += '<p><em>Исследованные пути не зафиксированы</em></p>'
    
    # ==================== FOOTER ====================
    html += f"""
    <div class="footer">
        <p>Сгенерировано <strong>Forseti Deep Forensic Agent</strong> | GigaChat-2-Max | {now}</p>
        <p>LangGraph + Deep Agents + Chain of Thought + Reflection</p>
    </div>
</div>
</body>
</html>
"""
    
    logger.info(f"Generated comprehensive HTML report: {len(html)} bytes")
    return html
