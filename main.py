import log
import asyncio
from uws import Server, POST, serve_file


AUTH_TOKEN='MYTOKEN'

app = Server(static_path='/static/',
             auth_token=AUTH_TOKEN,
             port=8000,
             )


@app.json()
async def token(method, new_token):
    if method == POST:
        app.auth_token = new_token
    return ''


@app.json()
async def log_level(method, level):
    if method == POST:
        log.LOG_LEVEL = log.LABEL_TO_INT.get(level, log.INFO)
    return log.INT_TO_LABEL.get(log.LOG_LEVEL, 'undefined for {}'.format(log.LOG_LEVEL))


@app.plain()
async def logs(verb, _):
    return log.stream_web_log()


@app.plain()
async def log_freq(verb, _):
    return log.stream_web_log_frequency()


@app.json()
async def logcfg(verb, cfg):
    if verb == POST:
        log.LOG_LEVEL = cfg.get('log_level', log.LOG_LEVEL)
        log.WEB_LOG_LEVEL = cfg.get('web_log_level', log.WEB_LOG_LEVEL)
        log.WEB_LOG_SIZE = cfg.get('web_log_size', log.WEB_LOG_SIZE)
    return dict(log_level=log.LOG_LEVEL,
                web_log_level=log.WEB_LOG_LEVEL,
                web_log_size=log.WEB_LOG_SIZE)


@app.html('/')
async def index(method, _):
    return serve_file('client.html', {'@=AUTH_TOKEN=@':'MYTOKEN',
                                       '@=SERVER_ADDRESS=@':'',})


def main():
    log.LOG_LEVEL = log.INFO
    log.garbage_collect()
    try:
        asyncio.run(app.run())
        loop = asyncio.get_event_loop()
        loop.run_forever()
    except Exception as e:
        log.exception(e)
    finally:
        try:
            asyncio.run(app.close())
            _ = asyncio.new_event_loop()
        except Exception as e:
            print(e)


if __name__ == '__main__':
    main()
