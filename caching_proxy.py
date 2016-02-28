import atexit
from cache import HttpResource, HttpResourceCache
from collections import namedtuple
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
    (default_origin_domain, port, cache_dirpath,) = options
    proxy_info = ProxyInfo(
        host='127.0.0.1',
        port=int(port),
    )
    
    # Open cache
    cache = HttpResourceCache(cache_dirpath)
    atexit.register(lambda: cache.close())
    
    def create_request_handler(*args):
        return CachingHTTPRequestHandler(*args,
            cache=cache,
            proxy_info=proxy_info,
            default_origin_domain=default_origin_domain,
            is_quiet=is_quiet)
    
    if not is_quiet:
        print('Listening on %s:%s' % (proxy_info.host, proxy_info.port))
    httpd = ThreadedHttpServer(
        (proxy_info.host, proxy_info.port),
        create_request_handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


ProxyInfo = namedtuple('ProxyInfo', ['host', 'port'])


class ThreadedHttpServer(ThreadingMixIn, HTTPServer):
    pass


class CachingHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that serves requests from an HttpResourceCache.
    When a resource is requested that isn't in the cache, it will be added
    to the cache automatically.
    """
    
    def __init__(self, *args, cache, proxy_info, default_origin_domain, is_quiet):
        self._cache = cache
        self._proxy_info = proxy_info
        self._default_origin_domain = default_origin_domain
        self._is_quiet = is_quiet
        super().__init__(*args)
    
    def do_HEAD(self):
        f = self._send_head()
        f.close()
    
    def do_GET(self):
        f = self._send_head()
        try:
            shutil.copyfileobj(f, self.wfile)
        finally:
            f.close()
    
    def _send_head(self):
        canonical_request_headers = {k.lower(): v for (k, v) in self.headers.items()}  # cache
        
        # Recognize proxy-specific paths like "/_/http/xkcd.com/" and 
        # interpret them as absolute URLs like "http://xkcd.com/".
        parsed_request_url = _parse_client_request_path(self.path, self._default_origin_domain)
        request_url = '%s://%s%s' % (
            parsed_request_url.protocol,
            parsed_request_url.domain,
            parsed_request_url.path
        )
        
        request_referer = canonical_request_headers.get('referer')
        parsed_referer = \
            None if request_referer is None \
            else _try_parse_client_referer(request_referer, self._default_origin_domain)
        
        # If referrer is a proxy absolute URL but the request URL is a
        # regular absolute URL, redirect the request URL to also be a
        # proxy absolute URL at the referrer domain.
        if parsed_referer is not None and \
                parsed_referer.is_proxy and \
                not parsed_request_url.is_proxy:
            redirect_url = _format_proxy_url(
                protocol=parsed_request_url.protocol,
                domain=parsed_referer.domain,
                path=parsed_request_url.path,
                proxy_info=self._proxy_info
            )
            
            self.send_response(301)  # Moved Permanently
            self.send_header('Location', redirect_url)
            self.send_header('Vary', 'Referer')
            self.end_headers()
            
            return BytesIO(b'')
        
        # If client performs a hard refresh (Command-Shift-R in Chrome),
        # ignore any cached response and refetch a fresh resource from the origin server.
        request_cache_control = canonical_request_headers.get('cache-control')
        request_pragma = canonical_request_headers.get('pragma')
        should_disable_cache = (
            'no-cache' in request_cache_control or  # HACK: fuzzy match
            'no-cache' in request_pragma            # HACK: fuzzy match
        )
        
        # Try fetch requested resource from cache.
        # If missing fetch the resource from the origin and add it to the cache.
        resource = self._cache.get(request_url)
        if resource is None or should_disable_cache:
            if should_disable_cache and resource is not None:
                resource.content.close()  # dispose
            
            request_headers = dict(self.headers)  # clone
            
            # Set Host request header appropriately
            for key in list(request_headers.keys()):
                if key.lower() == 'host':
                    del request_headers[key]
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
            for key in list(response_headers.keys()):
                if key.lower() in ['content-encoding', 'content-length']:
                    del response_headers[key]
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
        response_headers = dict(resource.headers)
        resource_content = resource.content
        
        # Filter response headers before sending to client
        _filter_headers(response_headers, 'response header', is_quiet=self._is_quiet)
        _reformat_absolute_urls_in_headers(
            response_headers,
            proxy_info=self._proxy_info,
            default_origin_domain=self._default_origin_domain)
        
        # Filter response content before sending to client
        resource_content = _reformat_absolute_urls_in_content(
            resource_content,
            resource_headers=response_headers,
            proxy_info=self._proxy_info)
        
        # Send headers
        self.send_response(status_code)
        for (key, value) in response_headers.items():
            self.send_header(key, value)
        self.end_headers()
        
        return resource_content
    
    def log_message(self, *args):
        if self._is_quiet:
            pass  # operate silently
        else:
            super().log_message(*args)


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
                    protocol=parsed_url.parsed_url,
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

def _reformat_absolute_urls_in_content(resource_content, *, resource_headers, proxy_info):
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
        return resource_content

    try:
        content_bytes = resource_content.read()
    finally:
        resource_content.close()

    def urlrepl(match_in_html):
        nonlocal proxy_info
        
        (quote, url) = match_in_html.groups()
        
        parsed_url = _try_parse_absolute_url_in_bytes(url)
        # TODO: Handle this case
        if parsed_url is None:
            raise NotImplementedError()

        return quote + _format_proxy_url_in_bytes(
            protocol=parsed_url.protocol,
            domain=parsed_url.domain,
            path=parsed_url.path,
            proxy_info=proxy_info
        ) + quote

    content_bytes = _ABSOLUTE_URL_BYTES_IN_HTML_RE.sub(urlrepl, content_bytes)

    return BytesIO(content_bytes)


# ------------------------------------------------------------------------------
# Parse URLs

_ABSOLUTE_REQUEST_URL_RE = re.compile(r'^/_/(https?)/([^/]+)(/.*)$')

_ClientRequestUrl = namedtuple('_ClientRequestUrl',
    ['protocol', 'domain', 'path', 'is_proxy'])

def _parse_client_request_path(path, default_origin_domain):
    if path.startswith('/_/'):
        m = _ABSOLUTE_REQUEST_URL_RE.match(path)
        if m is None:
            self.send_response(400)  # Bad Request
            self.end_headers()
            return BytesIO(b'')
        (protocol, domain, path) = m.groups()
        
        return _ClientRequestUrl(
            protocol=protocol,
            domain=domain,
            path=path,
            is_proxy=True
        )
    else:
        return _ClientRequestUrl(
            protocol='http',
            domain=default_origin_domain,
            path=path,
            is_proxy=False
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
    url_match = _ABSOLUTE_URL_RE.match(headers[k])
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


def _format_proxy_path(protocol, domain, path):
    return '/_/%s/%s%s' % (
        protocol, domain, path)


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
