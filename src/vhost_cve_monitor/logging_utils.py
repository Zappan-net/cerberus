from __future__ import annotations

import logging
import sys
from typing import Dict, Optional


def configure_logging(config: Dict, override_level: Optional[str] = None) -> None:
    level_name = (override_level or config["logging"].get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    handlers = [logging.StreamHandler(sys.stdout)]
    log_file = config["logging"].get("file")
    if log_file:
        try:
            handlers.append(logging.FileHandler(log_file))
        except OSError:
            logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s", handlers=handlers)
            logging.getLogger(__name__).warning("Unable to open log file %s, falling back to stdout only", log_file)
            return
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
    )
