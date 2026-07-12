"""
sentinel/logging_config.py
Configures structlog for the entire Sentinel application.
Call configure_logging() once at application startup (in main.py and run_real_data.py).
Emits:
  - Development: colored, human-readable output to stdout
  - Production (LOG_LEVEL=WARNING+): JSON to stdout, parseable by log aggregators
"""
import logging
import structlog
from sentinel.config.settings import settings

def configure_logging() -> None:
    """Configure structlog. Call once at process startup."""
    log_level = getattr(logging, settings.LOG_LEVEL, logging.INFO)
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]
    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer() if log_level <= logging.DEBUG
                  else structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level)

def get_logger(name: str):
    """Get a structlog logger bound to a component name."""
    return structlog.get_logger(name)
