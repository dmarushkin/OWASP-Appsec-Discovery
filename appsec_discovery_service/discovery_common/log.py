import logging

FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATEFMT = '%Y-%m-%d %H:%M:%S'


def get_logger(name=__name__):
    logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt=DATEFMT)
    return logging.getLogger(name)
