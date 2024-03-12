import log
import asyncio
from uws import Server, serve_file
from plugins.log_plugin import log_plugin


AUTH_TOKEN='MYTOKEN'
app = Server(static_path='/static/',
             auth_token=AUTH_TOKEN,
             port=8000,
             )


@app.html('/')
async def index(method, _):
    return serve_file('client.html', {'@=AUTH_TOKEN=@':'MYTOKEN',
                                       '@=SERVER_ADDRESS=@':'',})


def main():
    log.LOG_LEVEL = log.INFO
    log.garbage_collect()
    try:
        app.mount(log_plugin)
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
