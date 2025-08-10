from src.logger import logger


def add(a: int, b: int) -> int:
    """Add two numbers"""
    logger.debug(f"Adding {a} and {b}")
    return a + b
