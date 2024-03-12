import asyncio
import json
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
DEFAULT_HEADERS = {'Access-Control-Allow-Origin': '*'}
CHUNK_SIZE = 2048
DEFAULT_AUTHENTICATED_METHODS = (POST,)


def web_page(msg):
    yield '<html><body><p>'
    yield msg
    yield '</p></body></html>'


def response(status, content_type, payload, headers=DEFAULT_HEADERS):
    yield 'HTTP/1.1 {} {}\n'.format(status, STATUS_CODES[status])
    yield 'Content-Type: {}\n'.format(content_type)
    for k,v in headers.items():
        yield k
        yield ': '
        yield v
        yield '\n'
    yield 'Connection: close\n\n'
    yield payload


def redirect(location, status=302):
    yield 'HTTP/1.1 {} {}\n'.format(status, STATUS_CODES[status])
    yield 'Location: {}\n'.format(location)


def jsondumps(o, depth=1):
    # Memory efficient Json String generator
    if depth and isinstance(o, dict):
        for s in _jsondumps_dict(o, depth):
            yield s
    elif depth and isinstance(o, (list, tuple, set)):
        for s in _jsondumps_iter(o, depth):
            yield s
    else:
        yield json.dumps(o)


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
            yield json.dumps(v)
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
        yield json.dumps(k)
        yield ' : '
        if depth:
            for s in jsondumps(v, depth):
                yield s
        else:
            yield json.dumps(v)
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


class StopWebServer(Exception):
    pass


class HTTPException(Exception):
    def __init__(self, code=400):
        self.code = code


class UnauthorizedError(HTTPException):
    pass


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
        self.payload = None

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
                return json.loads(data)
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
        await self.writer.drain()

    async def _send_response(self, resp_gen):
        if isinstance(resp_gen, (str, bytes)):
            if resp_gen:
                self.writer.write(resp_gen)
                return len(resp_gen)
            return 0
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


class Endpoint:
    allowed = tuple(m.lower() for m in (GET, POST, PUT, PATCH, DELETE))
    def __init__(self, 
            endpoints,
            path=None,
            content_type='text/html',
            headers=DEFAULT_HEADERS,
            authenticated=DEFAULT_AUTHENTICATED_METHODS,
            **kwargs
            ):
        self.endpoints = endpoints
        self.path = path
        self.kwargs = dict(
                    headers=headers,
                    content_type=content_type,
                    authenticated=authenticated,
                    **kwargs
                    )
    def __call__(self, callback):
        path = self.path or '/' + callback.__name__
        if type(callback) == type(Endpoint):
            # this is a class with one method per HTTP verb
            callback = self.wrap_class(callback)
        self.endpoints[path] = dict(callback=callback, kwargs=self.kwargs)
        return callback

    def wrap_class(self, cls):
        instance = cls()
        def callback(method, payload, **params):
            method = method.decode('utf8').lower()
            if method not in self.allowed:
                raise ValueError(f'method={method} not allowed')
            attr = getattr(instance, method)
            if method == 'get':
                return attr(**params)
            return attr(payload, **params)
        return callback


class ServerBase:
    def __init__(self):
        self.endpoints = {}
    def decorate(self, content_type, path, kwargs):
        return Endpoint(self.endpoints, path,
                        content_type=content_type, 
                        **kwargs)
    def json(self, path=None, **kwargs):
        return self.decorate('application/json', path, kwargs)
    def html(self, path=None, **kwargs):
        return self.decorate('text/html', path, kwargs)
    def plain(self, path=None, **kwargs):
        return self.decorate('text/plain', path, kwargs)


class Plugin(ServerBase):
    ...

class Server(ServerBase):
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
        ServerBase.__init__(self)
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
                                         headers=DEFAULT_HEADERS,
                                         status=404,
                                     ))

    def mount(self, plugin:Plugin):
        for path, e in plugin.endpoints.items():
            if path in self.endpoints:
                raise ValueError(f'Endpoint with path={path} already exist')
            log.debug('mounting {} from plugin {}', path, plugin)
            self.endpoints[path] = e

    async def _default_method(self, v,req,**params):
        return 'Not Found\n{}\n{}\n{}'.format(v, req, params)

    async def run(self):
        log.info('Opening address={host} port={port}.', host=self.host, port=self.port)
        self.conn_id = 0 #connections ids
        self.server = await asyncio.start_server(self.accept_conn, self.host, self.port, self.backlog)

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
            except HTTPException as e:
                await resp.send_error(e.code, 'text/html', web_page('{} {!r}'.format(e,e)))
        except StopWebServer:
            raise
        except Exception as e:
            msg = 'Exception e={e} e={e!r} conn_id={conn_id}'.format(e=e, conn_id=conn_id)
            log.debug(msg)
            log.exception(e)
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
        path = req.path.lstrip('/')
        if file_exists(path):
            content_type = 'text/html'
            if path.endswith('.js'):
                content_type = 'application/javascript'
            return response(200, content_type, serve_file(path, self.static_files_replacements))
        return response(404, 'text/html', web_page('404 Not Found'))

    async def serve_request(self, req:Request, resp:Response):
        if self.pre_request_hook:
            self.pre_request_hook()
        endpoint = self.endpoints.get(req.path, self.default_endpoint)
        kwargs = endpoint['kwargs']
        if kwargs.get('classic'):
            endpoint['callback'](req, resp)
        else:
            req_payload = await req.read_payload() 
            params = req.get_params()
            if req.method in kwargs.get('authenticated', tuple()):
                if (req_payload or params).get('auth_token') != self.auth_token:
                    raise UnauthorizedError('Unauthorized. Send {"auth_token":"<secret>", "payload": ...}')
                req_payload = req_payload['payload']
            resp_payload = await endpoint['callback'](req.method, req_payload, **params)
            if kwargs['content_type'] ==  'application/json':
                resp_payload = jsondumps(resp_payload, kwargs.get('json_depth', 0))
            return response(kwargs.get('status', 200),
                            kwargs['content_type'],
                            resp_payload,
                            headers=kwargs['headers'])

