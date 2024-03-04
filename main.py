import machine
import utime
import log
import uasyncio
from uws import Server, POST, serve_file

LIGHT_PIN=2
light = machine.Pin(LIGHT_PIN, machine.Pin.OUT)
async def blink():
    light.off()
    await uasyncio.sleep(0.2)
    light.on()
    
AUTH_TOKEN='MYTOKEN'

app = Server(static_path='/static/',
                 auth_token=AUTH_TOKEN,
                 pre_request_hook=lambda: uasyncio.create_task(blink()))


@app.json()
async def log_level(method, level):
    if method == POST:
        log.LOG_LEVEL = log.LABEL_TO_INT.get(level, log.INFO)
    return log.INT_TO_LABEL.get(log.LOG_LEVEL, 'undefined for {}'.format(log.LOG_LEVEL))


_status = dict(name='hello')
@app.json()
async def status(method, payload):
    if method == POST:
        log.info(payload)
        _status.update(payload)
    return _status


@app.html('/')
def index(method, _):
    return serve_file('/client.html', {'@=AUTH_TOKEN=@':AUTH_TOKEN,
                                       '@=SERVER_ADDRESS=@':'',})


def main():
    gmt, localt = utime.gmtime(), utime.localtime()
    assert gmt == localt
    log.LOG_LEVEL = log.INFO
    log.garbage_collect()
    light.on()
    try:
        uasyncio.run(app.run())
        uasyncio.get_event_loop().run_forever()
    finally:
        uasyncio.run(app.close())
        _ = uasyncio.new_event_loop()


if __name__ == '__main__':
    main()

