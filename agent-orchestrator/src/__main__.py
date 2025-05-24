import argparse
import logging
import os

from src.logger import setup_logger


def main():
    """
    Configure logging from the command line
    """
    parser = argparse.ArgumentParser(description="Configure agent-orchestrator logging")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=os.environ.get("LOG_LEVEL", "INFO").upper(),
        help="Set logging level (default: INFO or from LOG_LEVEL env var)",
    )
    parser.add_argument("--log-file", help="Path to log file (if not specified, logs to console only)")

    args = parser.parse_args()

    # Set up the logger with command line args
    logger = setup_logger(level=getattr(logging, args.log_level), log_file=args.log_file)
    logger.info(f"Logger initialized with level {args.log_level}")

    if args.log_file:
        logger.info(f"Logging to file: {args.log_file}")


if __name__ == "__main__":
    main()
