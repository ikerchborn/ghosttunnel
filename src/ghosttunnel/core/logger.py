"""
GhostTunnel Logger Setup
===========================
Fixes applied:
  MED-04 — Log format secured; structured output for journal integration
"""
import logging
import sys


def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        # Professional log format: [INFO], [WARN], [CRITICAL]
        # Using %s-style format only — no user-controlled data in format string (MED-04)
        formatter = logging.Formatter(
            fmt="[%(levelname)s] %(asctime)s - %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        # Standardize level names
        logging.addLevelName(logging.WARNING, "WARN")
        logging.addLevelName(logging.CRITICAL, "CRITICAL")
        logging.addLevelName(logging.INFO, "INFO")
        logging.addLevelName(logging.ERROR, "ERROR")

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
