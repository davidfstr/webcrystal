import atexit
from cache import HttpResource, HttpResourceCache
from collections import namedtuple
import html
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
import re
import requests
import shutil
from socketserver import ThreadingMixIn
import sys


def main(options):
    is_quiet = False
    
    # Parse flags
    if len(options) >= 1 and options[0] in ['-q', '--quiet']:
        is_quiet = True
        options = options[1:]
    
    # Parse arguments
    if len(options) == 3:
        (port, cache_dirpath, default_origin_domain) = options
    else:
        (port, cache_dirpath,) = options
        default_origin_domain = None
    proxy_info = ProxyInfo(
        host='127.0.0.1',
        port=int(port),
    )
    
    # Open cache
    cache = HttpResourceCache(cache_dirpath)
    try:
        atexit.register(lambda: cache.close())  # last resort
        
        # ProxyState -- is mutable and threadsafe
        proxy_state = {
            'is_online': True
        }
        
        def create_request_handler(*args):
            return CachingHTTPRequestHandler(*args,
                cache=cache,
                proxy_info=proxy_info,
                default_origin_domain=default_origin_domain,
                is_quiet=is_quiet,
                proxy_state=proxy_state)
        
        if not is_quiet:
            print('Listening on %s:%s' % (proxy_info.host, proxy_info.port))
        httpd = ThreadedHttpServer(
            (proxy_info.host, proxy_info.port),
            create_request_handler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
    finally:
        cache.close()


ProxyInfo = namedtuple('ProxyInfo', ['host', 'port'])


class ThreadedHttpServer(ThreadingMixIn, HTTPServer):
    pass


class CachingHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that serves requests from an HttpResourceCache.
    When a resource is requested that isn't in the cache, it will be added
    to the cache automatically.
    """
    
    def __init__(self, *args, cache, proxy_info, default_origin_domain, is_quiet, proxy_state):
        self._cache = cache
        self._proxy_info = proxy_info
        self._default_origin_domain = default_origin_domain
        self._is_quiet = is_quiet
        self._proxy_state = proxy_state
        super().__init__(*args)
    
    def do_HEAD(self):
        f = self._send_head(method='HEAD')
        f.close()
    
    def do_GET(self):
        f = self._send_head(method='GET')
        try:
            shutil.copyfileobj(f, self.wfile)
        finally:
            f.close()
    
    def do_POST(self):
        f = self._send_head(method='POST')
        try:
            shutil.copyfileobj(f, self.wfile)
        finally:
            f.close()
    
    def _send_head(self, *, method):
        if self.path.startswith('/_') and not self.path.startswith('/_/'):
            return self._send_head_for_special_request(method=method)
        else:
            return self._send_head_for_regular_request(method=method)
    
    def _send_head_for_special_request(self, *, method):
        if self.path == '/_online':
            if method not in ['POST', 'GET']:
                self.send_response(405)  # Method Not Allowed
                self.end_headers()
                return BytesIO(b'')
            
            self._proxy_state['is_online'] = True
            
            self.send_response(200)  # OK
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            return BytesIO(b'OK')
        
        elif self.path == '/_offline':
            if method not in ['POST', 'GET']:
                self.send_response(405)  # Method Not Allowed
                self.end_headers()
                return BytesIO(b'')
            
            self._proxy_state['is_online'] = False
            
            self.send_response(200)  # OK
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            return BytesIO(b'OK')
        
        elif self.path.startswith('/_delete/'):
            if method not in ['POST', 'GET']:
                self.send_response(405)  # Method Not Allowed
                self.end_headers()
                return BytesIO(b'')
            
            parsed_request_url = _try_parse_client_request_path(self.path, self._default_origin_domain)
            assert parsed_request_url is not None
            request_url = '%s://%s%s' % (
                parsed_request_url.protocol,
                parsed_request_url.domain,
                parsed_request_url.path
            )
            
            did_exist = self._cache.delete(request_url)
            if did_exist:
                self.send_response(200)  # OK
                self.end_headers()
                return BytesIO(b'')
            else:
                self.send_response(404)  # Not Found
                self.end_headers()
                return BytesIO(b'')
        
        else:
            self.send_response(400)  # Bad Request
            self.end_headers()
            return BytesIO(b'')
    
    def _send_head_for_regular_request(self, *, method):
        if method not in ['GET', 'HEAD']:
            self.send_response(405)  # Method Not Allowed
            self.end_headers()
            return BytesIO(b'')
        
        canonical_request_headers = {k.lower(): v for (k, v) in self.headers.items()}  # cache
        
        parsed_request_url = _try_parse_client_request_path(self.path, self._default_origin_domain)
        if parsed_request_url is None:
            self.send_response(400)  # Bad Request
            self.end_headers()
            return BytesIO(b'')
        assert parsed_request_url.command == '_'
        
        request_referer = canonical_request_headers.get('referer')
        parsed_referer = \
            None if request_referer is None \
            else _try_parse_client_referer(request_referer, self._default_origin_domain)
        
        # Received a request at a site-relative path?
        # Redirect to a fully qualified proxy path at the appropriate domain.
        if not parsed_request_url.is_proxy:
            if parsed_referer is not None and parsed_referer.is_proxy:
                # Referer exists and is from the proxy?
                # Redirect to the referer domain.
                redirect_url = _format_proxy_url(
                    protocol=parsed_request_url.protocol,
                    domain=parsed_referer.domain,
                    path=parsed_request_url.path,
                    proxy_info=self._proxy_info
                )
                is_permanent = True
            else:
                if parsed_request_url.domain is None:
                    self.send_response(404)  # Not Found
                    self.end_headers()
                    
                    return BytesIO(b'')
                
                # No referer exists (or it's an unexpected external referer)?
                # Redirect to the default origin domain.
                redirect_url = _format_proxy_url(
                    protocol=parsed_request_url.protocol,
                    domain=parsed_request_url.domain,
                    path=parsed_request_url.path,
                    proxy_info=self._proxy_info
                )
                is_permanent = False  # temporary because the default origin domain can change
            
            self.send_response(308 if is_permanent else 307)  # Permanent Redirect, Temporary Redirect
            self.send_header('Location', redirect_url)
            self.send_header('Vary', 'Referer')
            self.end_headers()
            
            return BytesIO(b'')
        
        assert parsed_request_url.domain is not None
        request_url = '%s://%s%s' % (
            parsed_request_url.protocol,
            parsed_request_url.domain,
            parsed_request_url.path
        )
        
        # If client performs a hard refresh (Command-Shift-R in Chrome),
        # ignore any cached response and refetch a fresh resource from the origin server.
        request_cache_control = canonical_request_headers.get('cache-control')
        request_pragma = canonical_request_headers.get('pragma')
        should_disable_cache = (
            (request_cache_control is not None and 
                # HACK: fuzzy match
                'no-cache' in request_cache_control) or
            (request_pragma is not None and 
                # HACK: fuzzy match
                'no-cache' in request_pragma)
        )
        
        # Try fetch requested resource from cache.
        if should_disable_cache:
            resource = None
        else:
            resource = self._cache.get(request_url)
        
        # If missing fetch the resource from the origin and add it to the cache.
        if resource is None:
            # Fail if in offline mode
            if not self._proxy_state['is_online']:
                self.send_response(503)  # Service Unavailable
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                
                return BytesIO(
                    (('<html>Resource <a href="%s">%s</a> is not cached, ' +
                      'and this proxy is in offline mode. Go <a href="/_online">online</a>?</html>') %
                      (html.escape(request_url), html.escape(request_url))
                    ).encode('utf8')
                )
            
            request_headers = dict(self.headers)  # clone
            
            # Set Host request header appropriately
            _del_headers(request_headers, ['Host'])
            request_headers['Host'] = parsed_request_url.domain
            
            # Filter request headers before sending to origin server
            _filter_headers(request_headers, 'request header', is_quiet=self._is_quiet)
            _reformat_absolute_urls_in_headers(
                request_headers,
                proxy_info=self._proxy_info,
                default_origin_domain=self._default_origin_domain)
            
            response = requests.get(
                request_url,
                headers=request_headers,
                allow_redirects=False
            )
            
            # NOTE: Not streaming the response at the moment for simplicity.
            #       Probably want to use iter_content() later.
            response_content_bytes = response.content
            
            response_headers = dict(response.headers)
            _del_headers(response_headers, ['Content-Length', 'Content-Encoding'])
            response_headers['Content-Length'] = str(len(response_content_bytes))
            response_headers['X-Status-Code'] = str(response.status_code)
            
            response_content = BytesIO(response_content_bytes)
            try:
                self._cache.put(request_url, HttpResource(
                    headers=response_headers,
                    content=response_content
                ))
            finally:
                response_content.close()
            
            resource = self._cache.get(request_url)
            assert resource is not None
        
        status_code = int(resource.headers['X-Status-Code'])
        resource_headers = dict(resource.headers)
        resource_content = resource.content
        
        # Filter response headers before sending to client
        _filter_headers(resource_headers, 'response header', is_quiet=self._is_quiet)
        _reformat_absolute_urls_in_headers(
            resource_headers,
            proxy_info=self._proxy_info,
            default_origin_domain=self._default_origin_domain)
        
        # Filter response content before sending to client
        (resource_headers, resource_content) = _reformat_absolute_urls_in_content(
            resource_headers, resource_content,
            proxy_info=self._proxy_info)
        
        # Send headers
        self.send_response(status_code)
        for (key, value) in resource_headers.items():
            self.send_header(key, value)
        self.end_headers()
        
        return resource_content
    
    def log_message(self, *args):
        if self._is_quiet:
            pass  # operate silently
        else:
            super().log_message(*args)


def _del_headers(headers, header_names_to_delete):
    header_names_to_delete = [hn.lower() for hn in header_names_to_delete]
    for key in list(headers.keys()):
        if key.lower() in header_names_to_delete:
            del headers[key]


# ------------------------------------------------------------------------------
# Filter Headers

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Filter Header Keys

_HEADER_WHITELIST = [
    # Request
    'accept',
    'accept-encoding',
    'accept-language',
    'cookie',
    'host',
    'referer',
    'user-agent',

    # Response
    'access-control-allow-origin',
    'access-control-allow-credentials',
    'age',
    'content-length',
    'content-type',
    'date',
    'etag',
    'expires',
    'last-modified',
    'location',
    'retry-after',
    'server',
    'set-cookie',
    'via',
    'x-content-type-options',
    'x-frame-options',
    'x-runtime',
    'x-served-by',
    'x-xss-protection',
]
_HEADER_BLACKLIST = [
    # Request
    'cache-control',
    'connection',
    'if-modified-since',
    'if-none-match',
    'pragma',
    'upgrade-insecure-requests',
    'x-pragma',

    # Response
    'accept-ranges',
    'cache-control',
    'connection',
    'strict-transport-security',
    'transfer-encoding',
    'vary',
    'x-cache',
    'x-cache-hits',
    'x-request-id',
    'x-served-time',
    'x-timer',

    # Internal
    'x-status-code',
]

def _filter_headers(headers, header_type_title, *, is_quiet):
    for k in list(headers.keys()):
        k_lower = k.lower()
        if k_lower in _HEADER_WHITELIST:
            pass
        elif k_lower in _HEADER_BLACKLIST:
            del headers[k]
        else:  # graylist
            if not is_quiet:
                print('  - Removing unrecognized %s: %s' % (header_type_title, k))
            del headers[k]


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Filter Header URLs

def _reformat_absolute_urls_in_headers(headers, *, proxy_info, default_origin_domain):
    for k in list(headers.keys()):
        if k.lower() == 'location':
            parsed_url = _try_parse_absolute_url(headers[k])
            if parsed_url is not None:
                headers[k] = _format_proxy_url(
                    protocol=parsed_url.protocol,
                    domain=parsed_url.domain,
                    path=parsed_url.path,
                    proxy_info=proxy_info,
                )

        elif k.lower() == 'referer':
            referer = headers[k]

            parsed_referer = _try_parse_client_referer(referer, default_origin_domain)
            if parsed_referer is not None:
                headers[k] = '%s://%s%s' % (
                    parsed_referer.protocol,
                    parsed_referer.domain,
                    parsed_referer.path
                )


# ------------------------------------------------------------------------------
# Filter Content

_ABSOLUTE_URL_BYTES_IN_HTML_RE = re.compile(rb'([\'"])(https?://.*?)\1')
_PROTOCOL_RELATIVE_URL_BYTES_IN_HTML_RE = re.compile(rb'([\'"])(//.*?)\1')

def _reformat_absolute_urls_in_content(resource_headers, resource_content, *, proxy_info):
    """
    If specified resource is an HTML document, replaces any obvious absolute
    URL references with references of the format "/_/http/..." that will be
    interpreted by the caching proxy appropriately.

    Otherwise returns the original content unmodified.
    """
    is_html = False
    for (k, v) in resource_headers.items():
        if k.lower() == 'content-type':
            is_html = 'text/html' in v  # HACK: Loose test
            break

    if not is_html:
        return (resource_headers, resource_content)

    try:
        content_bytes = resource_content.read()
    finally:
        resource_content.close()

    def reformat_absolute_url_match(match_in_html):
        nonlocal proxy_info
        
        (quote, url) = match_in_html.groups()
        
        parsed_url = _try_parse_absolute_url_in_bytes(url)
        assert parsed_url is not None  # inner regex should be subset of outer

        return quote + _format_proxy_url_in_bytes(
            protocol=parsed_url.protocol,
            domain=parsed_url.domain,
            path=parsed_url.path,
            proxy_info=proxy_info
        ) + quote

    content_bytes = _ABSOLUTE_URL_BYTES_IN_HTML_RE.sub(reformat_absolute_url_match, content_bytes)
    
    def reformat_protocol_relative_url_match(match_in_html):
        nonlocal proxy_info
        
        (quote, url) = match_in_html.groups()
        
        parsed_url = _try_parse_protocol_relative_url_in_bytes(url, protocol=b'http')
        assert parsed_url is not None  # inner regex should be subset of outer

        return quote + _format_proxy_url_in_bytes(
            protocol=parsed_url.protocol,
            domain=parsed_url.domain,
            path=parsed_url.path,
            proxy_info=proxy_info
        ) + quote
    
    content_bytes = _PROTOCOL_RELATIVE_URL_BYTES_IN_HTML_RE.sub(reformat_protocol_relative_url_match, content_bytes)
    
    # Update Content-Length in the headers
    assert 'Content-Encoding' not in resource_headers
    _del_headers(resource_headers, ['Content-Length'])
    resource_headers['Content-Length'] = str(len(content_bytes))

    return (resource_headers, BytesIO(content_bytes))


# ------------------------------------------------------------------------------
# Parse URLs

_ABSOLUTE_REQUEST_URL_RE = re.compile(r'^/(_[^/]*)/(https?)/([^/]+)(/.*)$')

_ClientRequestUrl = namedtuple('_ClientRequestUrl',
    ['protocol', 'domain', 'path', 'is_proxy', 'command'])

def _try_parse_client_request_path(path, default_origin_domain):
    if path.startswith('/_'):
        m = _ABSOLUTE_REQUEST_URL_RE.match(path)
        if m is None:
            return None
        (command, protocol, domain, path) = m.groups()
        
        return _ClientRequestUrl(
            protocol=protocol,
            domain=domain,
            path=path,
            is_proxy=True,
            command=command
        )
    else:
        return _ClientRequestUrl(
            protocol='http',
            domain=default_origin_domain,
            path=path,
            is_proxy=False,
            command='_'
        )


_REFERER_LONG_RE = re.compile(r'^https?://[^/]*/_/(https?)/([^/]*)(/.*)?$')
_REFERER_SHORT_RE = re.compile(r'^(https?)://[^/]*(/.*)?$')

_ClientReferer = namedtuple('_ClientReferer',
    ['protocol', 'domain', 'path', 'is_proxy'])

def _try_parse_client_referer(referer, default_origin_domain):
    m = _REFERER_LONG_RE.match(referer)
    if m is not None:
        (protocol, domain, path) = m.groups()
        if path is None:
            path = ''

        return _ClientReferer(
            protocol=protocol,
            domain=domain,
            path=path,
            is_proxy=True
        )

    m = _REFERER_SHORT_RE.match(referer)
    if m is not None:
        (protocol, path) = m.groups()
        if path is None:
            path = ''

        return _ClientReferer(
            protocol=protocol,
            domain=default_origin_domain,
            path=path,
            is_proxy=False
        )

    return None  # failed to parse header


_Url = namedtuple('_Url', ['protocol', 'domain', 'path'])


_ABSOLUTE_URL_RE = re.compile(r'^(https?)://([^/]*)(/.*)?$')

def _try_parse_absolute_url(url):
    url_match = _ABSOLUTE_URL_RE.match(url)
    if url_match is None:
        return None
    
    (protocol, domain, path) = url_match.groups()
    if path is None:
        path = ''
    
    return _Url(
        protocol=protocol,
        domain=domain,
        path=path
    )


_ABSOLUTE_URL_BYTES_RE = re.compile(rb'^(https?)://([^/]*)(/.*)?$')

def _try_parse_absolute_url_in_bytes(url):
    url_match = _ABSOLUTE_URL_BYTES_RE.match(url)
    if url_match is None:
        return None
    
    (protocol, domain, path) = url_match.groups()
    if path is None:
        path = b''
    
    return _Url(
        protocol=protocol,
        domain=domain,
        path=path
    )


_PROTOCOL_RELATIVE_URL_BYTES_RE = re.compile(rb'^//([^/]*)(/.*)?$')

def _try_parse_protocol_relative_url_in_bytes(url, *, protocol):
    url_match = _PROTOCOL_RELATIVE_URL_BYTES_RE.match(url)
    if url_match is None:
        return None
    
    (domain, path) = url_match.groups()
    if path is None:
        path = b''
    
    return _Url(
        protocol=protocol,
        domain=domain,
        path=path
    )


def _format_proxy_path(protocol, domain, path, *, command='_'):
    return '/%s/%s/%s%s' % (
        command, protocol, domain, path)


def _format_proxy_url(protocol, domain, path, *, proxy_info):
    return 'http://%s:%s%s' % (
        proxy_info.host, proxy_info.port, _format_proxy_path(protocol, domain, path))


def _format_proxy_url_in_bytes(protocol, domain, path, *, proxy_info):
    (proxy_host, proxy_port) = (proxy_info.host.encode('utf8'), str(proxy_info.port).encode('utf8'))
    # TODO: After upgrading to Python 3.5+, replace the following code with:
    #       percent-substitution syntax like b'/_/%b/%b%b' % (protocol, domain, path
    return b'http://' + proxy_host + b':' + proxy_port + b'/_/' + protocol + b'/' + domain + path


# ------------------------------------------------------------------------------

if __name__ == '__main__':
    main(sys.argv[1:])
