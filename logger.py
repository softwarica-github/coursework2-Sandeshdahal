import logging
from logging.handlers import RotatingFileHandler
import os

class Logger:
    _instance = None  # Singleton instance

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance

    def __init__(self, log_file=None):
        if not hasattr(self, 'is_initialized'):
            self.logger = logging.getLogger("IDSLogger")
            self.logger.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            if log_file:
                log_directory = os.path.dirname(log_file)
                if log_directory and not os.path.exists(log_directory):
                    os.makedirs(log_directory)

                file_handler = RotatingFileHandler(log_file, maxBytes=1048576, backupCount=5)  # 1MB per file, max 5 files
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

            self.is_initialized = True  # Prevent re-initialization

    # ... rest of your class ...
s