import csv
from logger import logger

class CSVWriter:
    def __init__(self, filepath):
        try:
            self.file = open(filepath, 'w', newline='')
            self.writer = csv.writer(self.file)
            logger.info(f"CSV writer initialized for file: {filepath}")
        except IOError as e:
            logger.error(f"Failed to open file {filepath}: {e}")
            raise

    def write_row(self, row):
        try:
            self.writer.writerow(row)
        except Exception as e:
            logger.error(f"Failed to write row to CSV: {e}")

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()
            logger.info(f"CSV file closed: {self.file.name}")

    def __del__(self):
        self.close()