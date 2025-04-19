import log
import asyncio
import machine
import time
from uws import Server, serve_file, only_get, POST
from plugins.log_plugin import log_plugin
from plugins.include_plugin import include_plugin
from plugins.mem_plugin import mem_plugin


app = Server(pages_path='pages/',
             auth_token='MYTOKEN',
             port=8000,
             )


@app.html('/')
@only_get
async def index():
    return serve_file('pages/client.html', {'@=AUTH_TOKEN=@':'MYTOKEN',
                                            '@=SERVER_ADDRESS=@':'',})


def set_rtc_datetime(t):
    # Inject `time.localtime()` format into
    # `machine.RTC.datetime()`
    t = (t[0], t[1], t[2], t[6], t[3], t[4], t[5], 0)
    return machine.RTC().datetime(t)


@app.json()
async def py_time(verb, t):
    if verb == POST:
        log.info('set time to {t}', t=t)
        # `time.localtime()` format
        set_rtc_datetime(t)
    return time.localtime()


@app.json()
async def js_time(verb, t):
    if verb == POST:
        log.info('set time to {t}', t=t)
        # https://stackoverflow.com/questions/10286224/javascript-timestamp-to-python-datetime-conversion
        # `var ts = new Date().getTime()` format 
        set_rtc_datetime(time.localtime(t/1000))
    return int(time.time() * 1000)


def main():
    log.LOG_LEVEL = log.INFO
    log.WEB_LOG_LEVEL = log.DEBUG
    log.garbage_collect()
    app.mount(log_plugin)
    app.mount(include_plugin)
    app.mount(mem_plugin)
    try:
        asyncio.run(app.run())
        asyncio.get_event_loop().run_forever()
    except Exception as e:
        log.exception(e)
    finally:
        try:
            asyncio.run(app.close())
            _ = asyncio.new_event_loop()
        except Exception:
            ...


if __name__ == '__main__':
    main()
