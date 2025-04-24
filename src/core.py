import logging
import os
import schedule
import time
import config
from Datalake2Anomali import Datalake2Anomali
from dotenv import load_dotenv

load_dotenv()

ANOMALI_URL = os.environ["ANOMALI_URL"]
ANOMALI_USER = os.environ["ANOMALI_USER"]
ANOMALI_API_KEY = os.environ["ANOMALI_API_KEY"]


def _build_logger():
    logger = logging.getLogger("datalake2anomali")
    logger.setLevel(logging.INFO)
    if config.verbose_log:
        logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(os.environ["LOG_FILE"], mode="a")
    handler.setLevel(logging.INFO)
    if config.verbose_log:
        handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

def upload_data():
    datalake2anomali = Datalake2Anomali(logger)
    datalake2anomali.uploadIndicatorsToAnomali()
    datalake2anomali.upload_bulletins()

def main():
    # create the connector

    if config.run_as_cron:
        upload_data()
        schedule.every(config.upload_frequency).hours.do(
            upload_data
        )
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        upload_data()


if __name__ == "__main__":
    logger = _build_logger()

    logger.info("Start Datalake2Anomali connector")
    main()
    logger.info("End Datalake2Anomali connector")
