"""
Utilities to extract image filesystem to local host.

This module adapts the standalone extract_image_fs.py script for the current
project and reuses the already opened ImageManager filesystem handle.
"""

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional

import pytsk3

from .image_manager import get_image_manager
from src.utils.logger import get_logger

logger = get_logger("ExtractImageFS")


@dataclass
class Stats:
    """Counters for extraction summary."""

    dirs_created: int = 0
    files_extracted: int = 0
    files_failed: int = 0
    bytes_written: int = 0
    skipped_depth: int = 0


def _extract_file(
    fs: pytsk3.FS_Info,
    image_file_path: str,
    local_file_path: Path,
    size: int,
    stats: Stats,
) -> None:
    """Extract a single file from image to local path."""
    try:
        file_obj = fs.open(image_file_path)
    except Exception as exc:
        logger.debug(f"Cannot open image file {image_file_path}: {exc}")
        stats.files_failed += 1
        return

    local_file_path.parent.mkdir(parents=True, exist_ok=True)

    if size == 0:
        try:
            local_file_path.touch()
            stats.files_extracted += 1
        except Exception as exc:
            logger.debug(f"Cannot create empty local file {local_file_path}: {exc}")
            stats.files_failed += 1
        return

    chunk_size = 1024 * 1024
    written = 0
    try:
        with local_file_path.open("wb") as out:
            offset = 0
            while offset < size:
                to_read = min(chunk_size, size - offset)
                data = file_obj.read_random(offset, to_read)
                if not data:
                    break
                out.write(data)
                delta = len(data)
                offset += delta
                written += delta

        stats.files_extracted += 1
        stats.bytes_written += written
    except Exception as exc:
        logger.debug(f"Cannot extract file {image_file_path}: {exc}")
        stats.files_failed += 1


def _extract_directory(
    fs: pytsk3.FS_Info,
    image_dir_path: str,
    local_dir_path: Path,
    current_depth: int,
    max_depth: int,
    stats: Stats,
) -> None:
    """Recursively extract image directory content with depth limit."""
    if current_depth > max_depth:
        stats.skipped_depth += 1
        return

    local_dir_path.mkdir(parents=True, exist_ok=True)

    try:
        directory = fs.open_dir(image_dir_path)
    except Exception as exc:
        logger.debug(f"Cannot open image directory {image_dir_path}: {exc}")
        return

    for entry in directory:
        name = entry.info.name.name
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")

        if name in (".", ".."):
            continue

        meta = entry.info.meta
        if meta is None:
            continue

        entry_image_path = f"{image_dir_path.rstrip('/')}/{name}"
        entry_local_path = local_dir_path / name

        if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            stats.dirs_created += 1
            _extract_directory(
                fs=fs,
                image_dir_path=entry_image_path,
                local_dir_path=entry_local_path,
                current_depth=current_depth + 1,
                max_depth=max_depth,
                stats=stats,
            )
        elif meta.type == pytsk3.TSK_FS_META_TYPE_REG:
            _extract_file(
                fs=fs,
                image_file_path=entry_image_path,
                local_file_path=entry_local_path,
                size=meta.size,
                stats=stats,
            )


def extract_image_fs(output_dir: str = "image_fs", max_depth: int = 5) -> Dict[str, Any]:
    """
    Extract image filesystem to local host directory.

    Args:
        output_dir: Local output directory path.
        max_depth: Max recursive depth to extract (0 means only root entries).

    Returns:
        Result dict with extraction status and stats.
    """
    if max_depth < 0:
        return {
            "success": False,
            "error": "Depth cannot be negative",
            "output_dir": str(Path(output_dir).resolve()),
        }

    manager = get_image_manager()
    if not manager.is_open or manager.fs_handle is None:
        return {
            "success": False,
            "error": "Image is not open. Open image before extraction.",
            "output_dir": str(Path(output_dir).resolve()),
        }

    fs: Optional[pytsk3.FS_Info] = manager.fs_handle
    target_dir = Path(output_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    stats = Stats()
    logger.info(f"Starting image FS extraction to {target_dir} (depth={max_depth})")

    _extract_directory(
        fs=fs,
        image_dir_path="/",
        local_dir_path=target_dir,
        current_depth=0,
        max_depth=max_depth,
        stats=stats,
    )

    result = {
        "success": True,
        "output_dir": str(target_dir),
        "max_depth": max_depth,
        "stats": asdict(stats),
    }
    logger.info(
        f"Image FS extraction completed: dirs={stats.dirs_created} files={stats.files_extracted} "
        f"failed={stats.files_failed} bytes={stats.bytes_written} skipped_depth={stats.skipped_depth}"
    )
    return result
