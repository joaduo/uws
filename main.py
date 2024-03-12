import log
import asyncio
from uws import Server, serve_file, only_get
from plugins.log_plugin import log_plugin
from plugins.include_plugin import include_plugin
from plugins.mem_plugin import mem_plugin


AUTH_TOKEN='MYTOKEN'
app = Server(static_path='/static/',
             auth_token=AUTH_TOKEN,
             port=8000,
             )


@app.html('/')
@only_get
async def index():
    return serve_file('client.html', {'@=AUTH_TOKEN=@':'MYTOKEN',
                                       '@=SERVER_ADDRESS=@':'',})


def main():
    log.LOG_LEVEL = log.INFO
    log.garbage_collect()
    try:
        app.mount(log_plugin)
        app.mount(include_plugin)
        app.mount(mem_plugin)
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
