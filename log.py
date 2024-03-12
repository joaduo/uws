import gc
import time
import sys


MEM_FREE_THRESHOLD=20000
CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
IMPORTANT = 25
INFO = 20
DEBUG = 10
NOTSET = 0


INT_TO_LABEL = {
    CRITICAL:'CRITICAL',
    FATAL:'FATAL',
    ERROR:'ERROR',
    WARNING:'WARNING',
    IMPORTANT:'IMPORTANT',
    INFO:'INFO',
    DEBUG:'DEBUG',
}

LABEL_TO_INT = {v:k for k,v in INT_TO_LABEL.items()}

LOG_LEVEL = INFO


WEB_LOG_SIZE = 3
WEB_LOG_LEVEL = IMPORTANT


def debug(msg, *args, **kwargs):
    print_log(DEBUG, msg, *args, **kwargs)
def error(msg, *args, **kwargs):
    print_log(ERROR, msg, *args, **kwargs)
def warning(msg, *args, **kwargs):
    print_log(WARNING, msg, *args, **kwargs)
def important(msg, *args, **kwargs):
    print_log(IMPORTANT, msg, *args, **kwargs)
def info(msg, *args, **kwargs):
    print_log(INFO, msg, *args, **kwargs)
def exception(e, msg=''):
    print_log(ERROR, f'exc:{} {}', msg, e)
    sys.print_exception(e)

web_log_history = []
web_log_frequency = {}
def print_log(level, msg, *args, **kwargs):
    if LOG_LEVEL <= level:
        if args or kwargs:
            print(msg.format(*args, **kwargs))
        else:
            print(msg)
    if WEB_LOG_LEVEL <= level:
        t = time.time()
        web_log_history.append((t,level,msg,args,kwargs))
        if msg not in web_log_frequency:
            web_log_frequency[msg] = dict(count=0, level=level)
        web_log_frequency[msg]['count'] += 1
        web_log_frequency[msg]['last_seen'] = t
        purge_history()


def purge_history():
    # We allow a gap of 10
    if len(web_log_history) >= WEB_LOG_SIZE + 10:
        web_log_history[:10] = []


def garbage_collect(threshold=MEM_FREE_THRESHOLD, force=False):
    orig_free = gc.mem_free()
    if orig_free < threshold or force:
        gc.collect()
        now_free=gc.mem_free()
        debug('GC: was={orig_free}, now={now_free}',
              orig_free=orig_free, now_free=now_free)
        return now_free
    return orig_free


def stream_web_log():
    for l in reversed(web_log_history):
        msg = l[2].format(*l[3], **l[4])
        yield '{}:{}: {}\n'.format(l[0], INT_TO_LABEL[l[1]], msg)


def stream_web_log_frequency():
    for k in sorted(web_log_frequency):
        v = web_log_frequency[k]
        yield '{}:{}: {}: {}\n'.format(v['last_seen'], INT_TO_LABEL[v['level']], k, v['count'])

