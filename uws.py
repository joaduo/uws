import uasyncio
import ujson
import utime
import sys
import log


CONN_TIMEOUT=10
STATUS_CODES = {
    200:'OK',
    302:'FOUND',
    404:'NOT FOUND',
    403:'FORBIDDEN',
    401:'UNAUTHORIZED',
    500:'SERVER ERROR'}
POST = 'POST'
GET = 'GET'
PUT = 'PUT'
PATCH = 'PATCH'
DELETE = 'DELETE'
EXTRA_HEADERS = {'Access-Control-Allow-Origin': '*'}
CHUNK_SIZE = 2048


async def _coroutine_func():
    pass
_coroutine_generator = type(_coroutine_func())
def iscoroutine_generator(m):
    return isinstance(m, _coroutine_generator)


def web_page(msg):
    yield '<html><body><p>'
    yield msg
    yield '</p></body></html>'


def response(status, content_type, payload, extra_headers=EXTRA_HEADERS):
    yield 'HTTP/1.1 {} {}\n'.format(status, STATUS_CODES[status])
    yield 'Content-Type: {}\n'.format(content_type)
    for k,v in extra_headers.items():
        yield k
        yield ': '
        yield v
        yield '\n'
    yield 'Connection: close\n\n'
    yield payload


def redirect(location, status=302):
    yield 'HTTP/1.1 {} {}\n'.format(status, STATUS_CODES[status])
    yield 'Location: {}\n'.format(location)


def extract_json(payload, auth_token):
    log.garbage_collect()
    log.debug('payload={payload}', payload=payload)
    msg = ujson.loads(payload)
    if msg.get('auth_token') != auth_token:
        raise UnauthorizedError('Unauthorized. Send {"auth_token":"<secret>", "payload": ...}')
    return msg['payload']


def jsondumps(o, depth=1):
    # Memory efficient Json String generator
    if depth and isinstance(o, dict):
        for s in _jsondumps_dict(o, depth):
            yield s
    elif depth and isinstance(o, (list, tuple, set)):
        for s in _jsondumps_iter(o, depth):
            yield s
    else:
        yield ujson.dumps(o)


def _jsondumps_iter(o, depth=1):
    depth -= 1
    yield '['
    count = 0
    lgth = len(o)
    for v in o:
        if depth:
            for s in jsondumps(v, depth):
                yield s
        else:
            yield ujson.dumps(v)
        count += 1
        if lgth != count:
            yield ' ,'
    yield ']'


def _jsondumps_dict(d, depth=1):
    depth -= 1
    yield '{'
    count = 0
    lgth = len(d)
    for k,v in d.items():
        yield ujson.dumps(k)
        yield ' : '
        if depth:
            for s in jsondumps(v, depth):
                yield s
        else:
            yield ujson.dumps(v)
        count += 1
        if lgth != count:
            yield ' ,'
    yield '}'


def serve_file(path, replacements=None):
    if replacements:
        return yield_lines(path, replacements)
    return yield_chunks(path)


def yield_chunks(path):
    with open(path) as fp:
        chunk = fp.read(CHUNK_SIZE)
        while chunk:
            yield chunk
            log.garbage_collect()
            chunk = fp.read(CHUNK_SIZE)


def yield_lines(path, replacements):
    with open(path) as fp:
        chunk = fp.readline()
        size = 0
        while chunk:
            for k,v in replacements.items():
                chunk = chunk.replace(k,v)
            yield chunk
            size += len(chunk)
            if size // CHUNK_SIZE:
                log.garbage_collect()
                size = 0
            chunk = fp.readline()


def urldecode_plus(s):
    s = s.replace('+', ' ')
    arr = s.split('%')
    res = arr[0]
    for it in arr[1:]:
        if len(it) >= 2:
            res += chr(int(it[:2], 16)) + it[2:]
        elif len(it) == 0:
            res += '%'
        else:
            res += it
    return res


def parse_query_string(s):
    s = s.strip()
    res = {}
    if not s:
        return res
    pairs = s.split('&')
    for p in pairs:
        vals = [urldecode_plus(x) for x in p.split('=', 1)]
        if len(vals) == 1:
            res[vals[0]] = ''
        else:
            res[vals[0]] = vals[1]
    return res


def file_exists(path):
    try:
        with open(path):
            pass
        return True
    except:
        return False


class UnauthorizedError(Exception):
    pass


class StopWebServer(Exception):
    pass


class HTTPException(Exception):
    def __init__(self, code=400):
        self.code = code


class Request:
    def __init__(self, _reader, timeout):
        self.reader = _reader
        self.timeout = timeout
        self.headers = {}
        self._headers_read = False
        self.method = ''
        self.path = ''
        self.query_string = ''
        self.max_body_size = CHUNK_SIZE

    async def read_request_line(self):
        while True:
            rl = await self.reader.readline()
            # skip empty lines
            if rl == b'\r\n' or rl == b'\n':
                continue
            break
        rl_frags = rl.decode('utf8').split()
        if len(rl_frags) != 3:
            raise HTTPException(400)
        self.method = rl_frags[0]
        url_frags = rl_frags[1].split('?', 1)
        self.path = url_frags[0]
        if len(url_frags) > 1:
            self.query_string = url_frags[1]
        return self.method, self.path, self.query_string

    def get_params(self):
        return parse_query_string(self.query_string)

    async def read_headers(self, exclude_headers=[]):
        if not self._headers_read:
            while True:
                line = await self.reader.readline()
                if line == b'\r\n':
                    break
                frags = line.split(b':', 1)
                if len(frags) != 2:
                    raise HTTPException(400)
                if frags[0] not in exclude_headers:
                    self.headers[frags[0]] = frags[1].strip()
            self._headers_read = True
        return self.headers

    payload = None
    async def read_payload(self):
        if self.payload is None:
            self.payload = await self._read_payload()
        return self.payload

    async def _read_payload(self):
        h = await self.read_headers()
        lch = {k.lower():v for k,v in h.items()}
        if b'content-length' not in lch:
            log.debug('No Content-Length header')
            return ''
        size = int(lch[b'content-length'])
        if size > self.max_body_size or size < 0:
            raise HTTPException(413)
        data = await self.reader.readexactly(size)
        if b'content-type' not in lch:
            log.warning('No Content-Type header')
            return data
        # application/x-www-form-urlencoded; charset=UTF-8
        ct = lch[b'content-type'].split(b';', 1)[0]
        try:
            if ct == b'application/json':
                return ujson.loads(data)
            elif ct == b'application/x-www-form-urlencoded':
                return parse_query_string(data.decode())
            else:
                return data
        except ValueError:
            raise HTTPException(400)


class Response:
    def __init__(self, swriter):
        self.writer = swriter
        # self.code = 200
        # self.version = '1.0'
        # self.headers = {}
        self.began = False

    async def send(self, resp_gen):
        self.began = True
        await self._send_response(resp_gen)

    async def _send_response(self, resp_gen):
        if isinstance(resp_gen, (str, bytes)):
            if resp_gen:
                self.writer.write(resp_gen)
                return len(resp_gen)
            return 0
        #elif iscoroutine_generator(resp_gen):
        #    return await self._send_response(await resp_gen)
        else:
            count = 0
            for l in resp_gen:
                count += await self._send_response(l)
                if count // CHUNK_SIZE:
                    await self.writer.drain()
                    count = 0
            return count

    async def send_error(self, code, content_type='text/plain', msg=''):
        if self.began:
            msg = 'ERROR: {} {} {}'.format(code, STATUS_CODES[code], msg)
            await self.send(msg)
        else:
            await self.send(response(code, content_type, msg))


DEFAULT_AUTHENTICATED_METHODS = (POST,)
class Server:
    class _decorator:
        # Base class to later do @app.json() or @app.html() decorations
        _endpoints = {}
        def __init__(self, path=None,
                           response_builder=None,
                           extra_headers=EXTRA_HEADERS,
                           authenticated_methods=DEFAULT_AUTHENTICATED_METHODS,
                           **kwargs):
            self.path = path
            self.kwargs = dict(
                    extra_headers=extra_headers,
                    response_builder=response_builder or response,
                    endpoint_type=self.__class__,
                    content_type=self.content_type,
                    authenticated_methods=authenticated_methods,
                    **kwargs
                    )
        def __call__(self, method):
            path = self.path or '/' + method.__name__
            self._endpoints[path] = dict(callback=method, kwargs=self.kwargs)
            return method

    class json(_decorator):
        content_type = 'application/json'
        def __init__(self, path=None,
                           response_builder=None,
                           extra_headers=EXTRA_HEADERS,
                           authenticated_methods=DEFAULT_AUTHENTICATED_METHODS,
                           json_resp=True,
                           json_depth=0,
                           **kwargs
                           ):
            super().__init__(path=path,
                             response_builder=response_builder,
                             extra_headers=extra_headers,
                             json_resp=json_resp,
                             json_depth=json_depth,
                             authenticated_methods=authenticated_methods,
                             **kwargs
                             )

    class html(_decorator):
        content_type = 'text/html'

    class plain(_decorator):
        content_type = 'text/plain'

    def _default_method(self, v,req,**params):
        return 'Not Found\n{}\n{}\n{}'.format(v, req, params)

    static_path = None
    static_files_replacements = {}

    def __init__(self,
                 host='0.0.0.0',
                 port=80,
                 backlog=5,
                 timeout=CONN_TIMEOUT,
                 auth_token='',
                 static_path=None,
                 static_files_replacements=None,
                 pre_request_hook=None
                 ):
        self.host = host
        self.port = port
        self.backlog = backlog
        self.timeout = timeout
        self.auth_token = auth_token
        self.static_path = static_path
        self.static_files_replacements = static_files_replacements
        self.pre_request_hook = pre_request_hook
        self.default_endpoint = dict(callback=self._default_method,
                                     kwargs=dict(
                                         endpoint_type='default',
                                         content_type='text/plain',
                                         extra_headers=EXTRA_HEADERS,
                                         response_builder=response,
                                         status=404,
                                     ))

    async def run(self):
        log.info('Opening address={host} port={port}.', host=self.host, port=self.port)
        self.conn_id = 0 #connections ids
        self.server = await uasyncio.start_server(self.accept_conn, self.host, self.port, self.backlog)

    async def accept_conn(self, sreader, swriter):
        self.conn_id += 1
        conn_id = self.conn_id
        log.info('Accepting conn_id={conn_id}', conn_id=conn_id)
        log.garbage_collect()
        try:
            req = Request(sreader, self.timeout)
            resp = Response(swriter)
            await req.read_request_line()
            log.debug('request={request!r}, conn_id={conn_id}', request=req.path, conn_id=conn_id)
            try:
                if self.static_path and req.path.startswith(self.static_path) and req.method == GET:
                    resp_gen = await self.serve_static(req)
                else:
                    resp_gen = await self.serve_request(req, resp)
                if resp_gen:
                    await resp.send(resp_gen)
            except UnauthorizedError as e:
                await resp.send_error(401, 'text/html', web_page('{} {!r}'.format(e,e)))
        except StopWebServer:
            raise
        except Exception as e:
            msg = 'Exception e={e} e={e!r} conn_id={conn_id}'.format(e=e, conn_id=conn_id)
            log.debug(msg)
            sys.print_exception(e)
            await resp.send_error(500, 'text/html', web_page(msg))
        finally:
            await swriter.drain()
            log.debug('Disconnect conn_id={conn_id}.', conn_id=conn_id)
            swriter.close()
            await swriter.wait_closed()
            log.debug('Socket closed conn_id={conn_id}.', conn_id=conn_id)
            log.garbage_collect()

    async def close(self):
        log.debug('Closing server.')
        self.server.close()
        await self.server.wait_closed()
        log.info('Server closed.')

    async def serve_static(self, req):
        await req.read_payload()
        if file_exists(req.path):
            content_type = 'text/html'
            if req.path.endswith('.js'):
                content_type = 'application/javascript'
            return response(200, content_type, serve_file(req.path, self.static_files_replacements))
        return response(404, 'text/html', web_page('404 Not Found'))

    async def serve_request(self, req:Request, resp:Response):
        if self.pre_request_hook:
            self.pre_request_hook()
        endpoint = self._decorator._endpoints.get(req.path, self.default_endpoint)
        kwargs = endpoint['kwargs']
        if kwargs.get('classic'):
            endpoint['callback'](req, resp)
        else:
            req_payload = await req.read_payload() 
            params = req.get_params()
            if req.method in kwargs.get('authenticated_methods', tuple()):
                if (req_payload or params).get('auth_token') != self.auth_token:
                    raise UnauthorizedError('Unauthorized. Send {"auth_token":"<secret>", "payload": ...}')
                req_payload = req_payload['payload']
            resp_payload = endpoint['callback'](req.method, req_payload, **params)
            if kwargs.get('json_resp'):
                resp_payload = await self.json_dump(resp_payload, kwargs.get('json_depth', 0))
            response_builder = kwargs['response_builder']
            return response_builder(kwargs.get('status', 200),
                                    kwargs['content_type'],
                                    resp_payload,
                                    extra_headers=kwargs['extra_headers'])

    async def json_dump(self, obj, depth=1):
        if iscoroutine_generator(obj):
            obj = await obj
        return jsondumps(obj, depth)


