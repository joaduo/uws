from uws import Plugin, POST, only_get
import log


log_plugin = Plugin()


@log_plugin.json()
async def token(method, new_token):
    if method == POST:
        log_plugin.auth_token = new_token
    return ''


@log_plugin.json()
async def log_level(method, level):
    if method == POST:
        log.LOG_LEVEL = log.LABEL_TO_INT.get(level, log.INFO)
    return log.INT_TO_LABEL.get(log.LOG_LEVEL, 'undefined for {}'.format(log.LOG_LEVEL))


@log_plugin.plain()
@only_get
async def logs():
    return log.stream_web_log()


@log_plugin.plain()
@only_get
async def log_freq():
    return log.stream_web_log_frequency()


@log_plugin.json()
async def logcfg(verb, cfg):
    if verb == POST:
        log.LOG_LEVEL = cfg.get('log_level', log.LOG_LEVEL)
        log.WEB_LOG_LEVEL = cfg.get('web_log_level', log.WEB_LOG_LEVEL)
        log.WEB_LOG_SIZE = cfg.get('web_log_size', log.WEB_LOG_SIZE)
    return dict(log_level=log.LOG_LEVEL,
                web_log_level=log.WEB_LOG_LEVEL,
                web_log_size=log.WEB_LOG_SIZE)
