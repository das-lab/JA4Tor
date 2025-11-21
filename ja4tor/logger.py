import logging
import sys
from logging.handlers import RotatingFileHandler

def _configure_logger():
    logger_instance = logging.getLogger("FusionFlowExtractor")
    logger_instance.setLevel(logging.DEBUG)

    if logger_instance.hasHandlers():
        return logger_instance

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger_instance.addHandler(ch)

    # fh = RotatingFileHandler('app.log', maxBytes=1024*1024*5, backupCount=2)
    # fh.setLevel(logging.DEBUG)
    # fh.setFormatter(formatter)
    # logger_instance.addHandler(fh)

    return logger_instance

logger = _configure_logger()