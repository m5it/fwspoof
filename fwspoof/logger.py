"""Logging utilities for FWSpoof."""

import sys
import logging
from datetime import datetime
from typing import Optional, Any
from functools import lru_cache

from .config import get_config, Config


# Custom log levels
VERBOSE = 15  # Between DEBUG (10) and INFO (20)


class ColoredFormatter(logging.Formatter):
    """Formatter with optional color support."""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'VERBOSE': '\033[35m',    # Magenta
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',       # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }
    
    def __init__(self, use_colors: bool = True, fmt: Optional[str] = None):
        super().__init__(fmt or '%(message)s')
        self.use_colors = use_colors and sys.stderr.isatty()
    
    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            reset = self.COLORS['RESET']
            record.levelname = f"{color}{record.levelname}{reset}"
        
        return super().format(record)


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """
    Setup logging configuration.
    
    Args:
        verbose: Enable verbose (DEBUG) output
        quiet: Suppress all output except errors
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('fwspoof')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    if not quiet:
        handler = logging.StreamHandler(sys.stderr)
        level = logging.DEBUG if verbose else logging.INFO
        handler.setLevel(level)
        
        # Format: TIMESTAMP [LEVEL] MESSAGE
        formatter = ColoredFormatter(
            use_colors=True,
            fmt='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


@lru_cache(maxsize=1)
def get_logger() -> logging.Logger:
    """Get or create the fwspoof logger."""
    return logging.getLogger('fwspoof')


def log(level: int, message: str, *args: Any, **kwargs: Any) -> None:
    """
    Log a message at the specified level.
    
    Args:
        level: Logging level (logging.DEBUG, logging.INFO, etc.)
        message: Message to log
        *args: Format arguments
        **kwargs: Additional logging kwargs
    """
    logger = get_logger()
    if logger.isEnabledFor(level):
        logger.log(level, message, *args, **kwargs)


def debug(message: str, *args: Any, **kwargs: Any) -> None:
    """Log a debug message."""
    log(logging.DEBUG, message, *args, **kwargs)


def verbose(message: str, *args: Any, **kwargs: Any) -> None:
    """Log a verbose message (between DEBUG and INFO)."""
    log(VERBOSE, message, *args, **kwargs)


def info(message: str, *args: Any, **kwargs: Any) -> None:
    """Log an info message."""
    log(logging.INFO, message, *args, **kwargs)


def warning(message: str, *args: Any, **kwargs: Any) -> None:
    """Log a warning message."""
    log(logging.WARNING, message, *args, **kwargs)


def error(message: str, *args: Any, **kwargs: Any) -> None:
    """Log an error message."""
    log(logging.ERROR, message, *args, **kwargs)


def critical(message: str, *args: Any, **kwargs: Any) -> None:
    """Log a critical message."""
    log(logging.CRITICAL, message, *args, **kwargs)


def log_packet(packet: Any, prefix: str = "Packet") -> None:
    """
    Log packet information in verbose mode.
    
    Args:
        packet: Packet object to log
        prefix: Prefix for the log message
    """
    logger = get_logger()
    if not logger.isEnabledFor(logging.DEBUG):
        return
    
    try:
        msg = f"{prefix}: {packet.sip}"
        if hasattr(packet, 'sport') and packet.sport:
            msg += f":{packet.sport}"
        msg += f" -> {packet.flags}"
        debug(msg)
    except AttributeError:
        debug(f"{prefix}: {packet}")


def log_attack(attack_info: dict, prefix: str = "Attack") -> None:
    """
    Log attack detection information.
    
    Args:
        attack_info: Attack information dictionary
        prefix: Prefix for the log message
    """
    logger = get_logger()
    if not logger.isEnabledFor(logging.INFO):
        return
    
    info(f"{prefix} detected from {attack_info.get('fto', 'unknown')}")
    
    if logger.isEnabledFor(logging.DEBUG):
        for key, value in attack_info.items():
            if key != 'subnets':
                debug(f"  {key}: {value}")
        
        subnets = attack_info.get('subnets', [])
        for subnet in subnets:
            debug(f"  Subnet: {subnet.get('cidr')} "
                  f"(SYN: {subnet.get('syn_count')}, "
                  f"SR: {subnet.get('sr_count')})")


def log_block(cidr: str, block_type: str = "range") -> None:
    """Log a block action."""
    info(f"Blocked {block_type}: {cidr}")


def log_unblock(cidr: str, block_type: str = "range") -> None:
    """Log an unblock action."""
    info(f"Unblocked {block_type}: {cidr}")


class LogContext:
    """Context manager for temporary logging changes."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.original_level: Optional[int] = None
    
    def __enter__(self) -> 'LogContext':
        logger = get_logger()
        self.original_level = logger.level
        if self.verbose:
            logger.setLevel(logging.DEBUG)
        return self
    
    def __exit__(self, *args: Any) -> None:
        if self.original_level is not None:
            get_logger().setLevel(self.original_level)


# Convenience function for conditional logging
def is_verbose() -> bool:
    """Check if verbose logging is enabled."""
    return get_logger().isEnabledFor(logging.DEBUG)
