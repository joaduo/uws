from uws import Plugin, POST
import config


config_plugin = Plugin()


@config_plugin.json()
async def cfg(method, payload):
    if method == POST:
        config.set_(**payload)
    return config._config_storage


@config_plugin.json()
async def cfg_dump(method, payload):
    if method == POST:
        config.dump()
    return config.DEFAULT_CONFIG_PATH


@config_plugin.json()
async def cfg_load(method, payload):
    if method == POST:
        config.load()
    return config.DEFAULT_CONFIG_PATH

