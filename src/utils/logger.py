import logging
import logging.handlers
import os
import sys
from pathlib import Path


def _resolve_log_file() -> str | None:
    override = os.getenv("OBSCURA_LOG_FILE")
    if override is not None:
        if override.strip().lower() in ("", "0", "false", "off", "none"):
            return None
        return os.path.expanduser(override)
    log_dir = Path(os.path.expanduser(os.getenv("OBSCURA_LOG_DIR", "~/.obscura47/logs")))
    # Per-process file so multiple roles on one box don't fight over rollover.
    role = Path(sys.argv[0]).stem or "obscura47"
    return str(log_dir / f"{role}.log")


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level = os.getenv("OBSCURA_LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level, logging.INFO))

    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    formatter = logging.Formatter(fmt)

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    log_file = _resolve_log_file()
    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=int(os.getenv("OBSCURA_LOG_MAX_BYTES", str(5 * 1024 * 1024))),
                backupCount=int(os.getenv("OBSCURA_LOG_BACKUPS", "5")),
                encoding="utf-8",
            )
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            # Logger init must never crash the process. Surface the reason
            # on stderr so silent file-log loss is at least visible.
            stream.handle(logging.LogRecord(
                name, logging.WARNING, __file__, 0,
                f"file logging disabled ({log_file}): {e}", None, None,
            ))

    logger.propagate = False
    return logger


