from uws import Plugin, only_get
import gc


mem_plugin = Plugin()

@mem_plugin.json()
@only_get
async def mem():
    return gc.mem_free()
