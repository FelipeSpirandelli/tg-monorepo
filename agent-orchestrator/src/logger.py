import logging
import sys


# Configure the root logger
def setup_logger(
    name: str = "agent-orchestrator",
    level: int | str = logging.INFO,
    log_file: str | None = None,
) -> logging.Logger:
    """
    Set up a logger with configurable name, level, and optional file output

    Args:
        name: The name for the logger
        level: The logging level (default: from LOG_LEVEL env var or INFO)
        log_file: Optional path to a file where logs should be written

    Returns:
        The configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Create file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# Create default logger instance
logger = setup_logger()
