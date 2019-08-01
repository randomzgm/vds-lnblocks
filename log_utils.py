import logging
import os

# 获取当前目录的绝对路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) + '/logs'
if not os.path.exists(BASE_DIR):
    os.mkdir(BASE_DIR)
log_dir = BASE_DIR + '/record.log'


def get_logger(name):
    # 获得一个logger对象，默认是root
    logger = logging.getLogger(name)
    # 设置最低等级debug
    logger.setLevel(logging.DEBUG)
    # 设置日志格式
    fm = logging.Formatter('%(asctime)s %(name)s- %(levelname)s - %(message)s')

    # 日志输出到屏幕控制台
    ch = logging.StreamHandler()  # 日志输出到屏幕控制台
    ch.setLevel(logging.DEBUG)  # 设置日志等级
    ch.setFormatter(fm)

    # 创建一个文件流并设置编码utf8
    fh = logging.FileHandler(log_dir, encoding='utf-8')
    fh.setLevel(logging.INFO)
    fh.setFormatter(fm)

    # 把文件流添加进来，流向写入到文件
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger
