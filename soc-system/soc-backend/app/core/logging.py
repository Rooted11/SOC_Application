import logging
import os
from logging.handlers import RotatingFileHandler

from app.core.config import settings


def configure_logging() -> None:
    os.makedirs(settings.log_dir, exist_ok=True)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        filename=os.path.join(settings.log_dir, "app.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(settings.log_level)

    root = logging.getLogger()
    root.setLevel(settings.log_level)
    if not root.handlers:
        root.addHandler(file_handler)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
