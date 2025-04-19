from uws import Plugin, yield_chunks, serve_file
from config import file_exists
import json
import os

include_plugin = Plugin()


@include_plugin.javascript(is_async=False)
def include(m, pl, path):
    if file_exists(path):
        nspace = path.split(os.sep)[-1].split('.')[0]
        yield '(function () {\nlet content = '
        first = True
        for chunk in serve_file(path, {'@=NAMESPACE=@': nspace}):
            if not first:
                yield '\n + '
            yield json.dumps(chunk)
            first = False
        yield ';\n'
        yield 'document.write(content);\n})();'
    yield ''
