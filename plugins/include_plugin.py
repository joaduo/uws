from uws import Plugin, yield_chunks
from config import file_exists
import json


include_plugin = Plugin()


@include_plugin.javascript(is_async=False)
def include(m, pl, path):
    if file_exists(path):
        yield 'let content = '
        first = True
        for chunk in yield_chunks(path):
            if not first:
                yield '\n + '
            yield json.dumps(chunk)
            first = False
        yield ';\n'
        yield 'document.write(content);'
    yield ''
