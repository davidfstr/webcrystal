#!/usr/bin/env python3
"""
webcrystal is:

1. An HTTP proxy and web service that saves every web page accessed through it to disk.
2. An on-disk archival format for storing websites.

webcrystal is intended as a tool for archiving websites.

See the README for more information.
"""

import argparse
import atexit
from collections import namedtuple, OrderedDict
import html
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
import json
import os.path
import re
import shutil
from socketserver import ThreadingMixIn
import sys
from threading import Lock

try:
    import urllib3
except ImportError:
    raise ImportError('webcrystal requires urllib3. Try: pip3 install urllib3')

if not (sys.version_info >= (3, 4)):
    raise ImportError('webcrystal requires Python 3.4 or later.')


# ==============================================================================
# Service


http = urllib3.PoolManager()


def main(raw_cli_args):
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='An archiving HTTP proxy and web service.',
        add_help=False)
    parser.add_argument('-h', '--help', action='help',
        help='Show this help message and exit.')
    parser.add_argument('-q', '--quiet', action='store_true', dest='is_quiet',
        help='Suppresses all output.')
    parser.add_argument('port', type=int,
        help='Port on which to run the HTTP proxy. Suggest 9227 (WBCR).')
    parser.add_argument('archive_dirpath',
        help='Path to the archive directory. Usually has .wbcr extension.')
    parser.add_argument('default_origin_domain', nargs='?', type=_domain,
        help='Default HTTP domain which the HTTP proxy will redirect to if no URL is specified.')
    cli_args = parser.parse_args(raw_cli_args)
    
    proxy_info = _ProxyInfo(host='127.0.0.1', port=cli_args.port)
    
    # Open archive
    archive = HttpResourceArchive(cli_args.archive_dirpath)
    try:
        atexit.register(lambda: archive.close())  # last resort
        
        # ProxyState -- is mutable and threadsafe
        proxy_state = {
            'is_online': True
        }
        
        def create_request_handler(*args):
            return _ArchivingHTTPRequestHandler(*args,
                archive=archive,
                proxy_info=proxy_info,
                default_origin_domain=cli_args.default_origin_domain,
                is_quiet=cli_args.is_quiet,
                proxy_state=proxy_state)
        
        # Run service until user presses ^C
        if not cli_args.is_quiet:
            print('Listening on %s:%s' % (proxy_info.host, proxy_info.port))
        httpd = _ThreadedHttpServer(
            (proxy_info.host, proxy_info.port),
            create_request_handler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
    finally:
        archive.close()


def _domain(domain_descriptor):
    m = re.search(r'^(?:(https?)://)?([^/]+)/?$', domain_descriptor)
    if m is None:
        raise argparse.ArgumentTypeError(
            '%r must look like %r or %r' %
            (domain_descriptor, 'xkcd.com', 'http://xkcd.com/'))
    (protocol, domain) = m.groups()
    if protocol == 'https':
        raise argparse.ArgumentTypeError(
            'The %r protocol is not supported for the default origin domain. Try %r instead.' %
            ('https', 'http'))
    return domain


_ProxyInfo = namedtuple('_ProxyInfo', ['host', 'port'])


class _ThreadedHttpServer(ThreadingMixIn, HTTPServer):
    pass


class _ArchivingHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that serves requests from an HttpResourceArchive.
    When a resource is requested that isn't in the archive, it will be added
    to the archive automatically.
    """
    
    def __init__(self, *args, archive, proxy_info, default_origin_domain, is_quiet, proxy_state):
        self._archive = archive
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
                return self._send_head_for_simple_response(405)  # Method Not Allowed
            
            self._proxy_state['is_online'] = True
            
            self.send_response(200)  # OK
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            return BytesIO(b'OK')
        
        elif self.path == '/_offline':
            if method not in ['POST', 'GET']:
                return self._send_head_for_simple_response(405)  # Method Not Allowed
            
            self._proxy_state['is_online'] = False
            
            self.send_response(200)  # OK
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            return BytesIO(b'OK')
        
        elif self.path.startswith('/_delete/'):
            if method not in ['POST', 'GET']:
                return self._send_head_for_simple_response(405)  # Method Not Allowed
            
            parsed_request_url = _try_parse_client_request_path(self.path, self._default_origin_domain)
            assert parsed_request_url is not None
            request_url = '%s://%s%s' % (
                parsed_request_url.protocol,
                parsed_request_url.domain,
                parsed_request_url.path
            )
            
            did_exist = self._archive.delete(request_url)
            if did_exist:
                return self._send_head_for_simple_response(200)  # OK
            else:
                return self._send_head_for_simple_response(404)  # Not Found
        
        elif self.path.startswith('/_refresh/'):
            if method not in ['POST', 'GET']:
                return self._send_head_for_simple_response(405)  # Method Not Allowed
            
            parsed_request_url = _try_parse_client_request_path(self.path, self._default_origin_domain)
            assert parsed_request_url is not None
            request_url = '%s://%s%s' % (
                parsed_request_url.protocol,
                parsed_request_url.domain,
                parsed_request_url.path
            )
            
            request_headers = self._archive.get_request_headers(request_url)
            if request_headers is None:
                return self._send_head_for_simple_response(404)  # Not Found
            
            resource = self._fetch_from_origin_and_store_in_archive(
                request_url, request_headers,
                parsed_request_url=parsed_request_url)
            resource.content.close()
            
            return self._send_head_for_simple_response(200)  # OK
            
        else:
            return self._send_head_for_simple_response(400)  # Bad Request
    
    def _send_head_for_regular_request(self, *, method):
        if method not in ['GET', 'HEAD']:
            return self._send_head_for_simple_response(405)  # Method Not Allowed
        
        canonical_request_headers = {k.lower(): v for (k, v) in self.headers.items()}  # cache
        
        parsed_request_url = _try_parse_client_request_path(self.path, self._default_origin_domain)
        if parsed_request_url is None:
            return self._send_head_for_simple_response(400)  # Bad Request
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
                    return self._send_head_for_simple_response(404)  # Not Found
                
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
        # ignore any archived response and refetch a fresh resource from the origin server.
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
        
        # Try fetch requested resource from archive.
        if should_disable_cache:
            resource = None
        else:
            resource = self._archive.get(request_url)
        
        # If missing fetch the resource from the origin and add it to the archive.
        if resource is None:
            # Fail if in offline mode
            if not self._proxy_state['is_online']:
                self.send_response(503)  # Service Unavailable
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                
                return BytesIO(
                    (('<html>Resource <a href="%s">%s</a> is not archived, ' +
                      'and this proxy is in offline mode. Go <a href="/_online">online</a>?</html>') %
                      (html.escape(request_url), html.escape(request_url))
                    ).encode('utf8')
                )
            
            resource = self._fetch_from_origin_and_store_in_archive(
                request_url,
                self.headers,
                parsed_request_url=parsed_request_url)
        
        return self._send_head_for_resource(resource)
    
    def _fetch_from_origin_and_store_in_archive(
            self, request_url, request_headers, *, parsed_request_url):
        request_headers = OrderedDict(request_headers)  # clone
        
        # Set Host request header appropriately
        _del_headers(request_headers, ['Host'])
        request_headers['Host'] = parsed_request_url.domain
        
        # Filter request headers before sending to origin server
        _filter_headers(request_headers, 'request header', is_quiet=self._is_quiet)
        _reformat_absolute_urls_in_headers(
            request_headers,
            proxy_info=self._proxy_info,
            default_origin_domain=self._default_origin_domain)
        
        response = http.request(
            method='GET',
            url=request_url,
            headers=request_headers,
            redirect=False
        )
        
        # NOTE: Not streaming the response at the moment for simplicity.
        #       Probably want to use iter_content() later.
        response_content_bytes = response.data
        
        response_headers = OrderedDict(response.headers)  # clone
        _del_headers(response_headers, ['Content-Length', 'Content-Encoding'])
        response_headers['Content-Length'] = str(len(response_content_bytes))
        response_headers['X-Status-Code'] = str(response.status)
        
        response_content = BytesIO(response_content_bytes)
        try:
            self._archive.put(request_url, request_headers, HttpResource(
                headers=response_headers,
                content=response_content
            ))
        finally:
            response_content.close()
        
        resource = self._archive.get(request_url)
        assert resource is not None
        
        return resource
    
    def _send_head_for_resource(self, resource):
        status_code = int(resource.headers['X-Status-Code'])
        resource_headers = OrderedDict(resource.headers)  # clone
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
    
    def _send_head_for_simple_response(self, status_code):
        self.send_response(status_code)
        self.end_headers()
        return BytesIO(b'')
    
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

_REQUEST_HEADER_WHITELIST = [
    # Request
    'accept',
    'accept-encoding',
    'accept-language',
    'cookie',
    'host',
    'referer',
    'user-agent',
]
_RESPONSE_HEADER_WHITELIST = [
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
_HEADER_WHITELIST = (
    _REQUEST_HEADER_WHITELIST + 
    _RESPONSE_HEADER_WHITELIST
)

_REQUEST_HEADER_BLACKLIST = [
    # Request
    'cache-control',
    'connection',
    'if-modified-since',
    'if-none-match',
    'pragma',
    'upgrade-insecure-requests',
    'x-pragma',
]
_RESPONSE_HEADER_BLACKLIST = [
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
]
_INTERNAL_RESPONSE_HEADERS = [
    # Internal
    'x-status-code',
]
_HEADER_BLACKLIST = (
    _REQUEST_HEADER_BLACKLIST + 
    _RESPONSE_HEADER_BLACKLIST + 
    _INTERNAL_RESPONSE_HEADERS
)

# TODO: Should differentiate between request & response headers.
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
    interpreted by the archiving proxy appropriately.

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


# ==============================================================================
# Archive


HttpResource = namedtuple('HttpResource', ['headers', 'content'])


class HttpResourceArchive:
    """
    Persistent archive of HTTP resources, include the full content and headers of
    each resource.

    This class is threadsafe.
    """

    def __init__(self, root_dirpath):
        """
        Opens the existing archive at the specified directory,
        or creates a new archive if there is no such directory.
        """
        self._closed = False
        self._lock = Lock()
        self._root_dirpath = root_dirpath

        # Create empty archive if archive does not already exist
        if not os.path.exists(root_dirpath):
            os.mkdir(root_dirpath)
            with self._open_index('w') as f:
                f.write('')

        # Load archive
        with self._open_index('r') as f:
            self._urls = f.read().split('\n')
            if self._urls == ['']:
                self._urls = []
        # NOTE: It is possible for the archive to contain multiple IDs for the
        #       same path under rare circumstances. In that case the last ID wins.
        self._resource_id_for_url = {url: i for (i, url) in enumerate(self._urls)}

    def get(self, url):
        """
        Gets the HttpResource at the specified url from this archive,
        or None if the specified resource is not in the archive.
        """
        with self._lock:
            resource_id = self._resource_id_for_url.get(url)
            if resource_id is None:
                return None

        with self._open_response_headers(resource_id, 'r') as f:
            headers = json.load(f, object_pairs_hook=OrderedDict)
        f = self._open_response_content(resource_id, 'rb')
        return HttpResource(
            headers=headers,
            content=f,
        )
    
    def get_request_headers(self, url):
        """
        Gets the request headers for the resource at the specified url from this archive,
        or None if the specified resource is not in the archive.
        """
        with self._lock:
            resource_id = self._resource_id_for_url.get(url)
            if resource_id is None:
                return None
        
        with self._open_request_headers(resource_id, 'r') as f:
            return json.load(f, object_pairs_hook=OrderedDict)

    def put(self, url, request_headers, resource):
        """
        Puts the specified HttpResource into this archive, replacing any previous
        resource with the same url.

        If two difference resources are put into this archive at the same url
        concurrently, the last one put into the archive will eventually win.
        """
        # Reserve resource ID (if new)
        with self._lock:
            resource_id = self._resource_id_for_url.get(url)
            if resource_id is None:
                resource_id = len(self._urls)
                self._urls.append('')  # reserve space
                resource_id_is_new = True
            else:
                resource_id_is_new = False

        # Write resource content
        with self._open_request_headers(resource_id, 'w') as f:
            json.dump(request_headers, f)
        with self._open_response_headers(resource_id, 'w') as f:
            json.dump(resource.headers, f)
        with self._open_response_content(resource_id, 'wb') as f:
            shutil.copyfileobj(resource.content, f)

        # Commit resource ID (if new)
        if resource_id_is_new:
            # NOTE: Only commit an entry to self._urls AFTER the resource
            #       content has been written to disk successfully.
            with self._lock:
                self._urls[resource_id] = url
                old_resource_id = self._resource_id_for_url.get(url)
                if old_resource_id is None or old_resource_id < resource_id:
                    self._resource_id_for_url[url] = resource_id
    
    def delete(self, url):
        """
        Deletes the specified resource from this archive if it exists.
        
        Returns whether the specified resource was found and deleted.
        """
        with self._lock:
            resource_id = self._resource_id_for_url.get(url)
            if resource_id is None:
                return False
            else:
                self._delete_resource(resource_id)
                
                self._urls[resource_id] = ''
                del self._resource_id_for_url[url]
                return True

    def flush(self):
        """
        Flushes all pending changes made to this archive to disk.
        """
        # TODO: Make this operation atomic, even if the write fails in the middle.
        with self._open_index('w') as f:
            f.write('\n'.join(self._urls))

    def close(self):
        """
        Closes this archive.
        """
        if self._closed:
            return
        self.flush()
        self._closed = True

    # === Filesystem I/O ===

    def _open_index(self, mode='r'):
        return open(os.path.join(self._root_dirpath, 'index.txt'), mode, encoding='utf8')
    
    def _open_request_headers(self, resource_id, mode='r'):
        resource_ordinal = resource_id + 1
        return open(os.path.join(self._root_dirpath, '%d.request_headers.json' % resource_ordinal), mode, encoding='utf8')
    
    def _open_response_headers(self, resource_id, mode='r'):
        resource_ordinal = resource_id + 1
        return open(os.path.join(self._root_dirpath, '%d.response_headers.json' % resource_ordinal), mode, encoding='utf8')

    def _open_response_content(self, resource_id, mode='rb'):
        resource_ordinal = resource_id + 1
        return open(os.path.join(self._root_dirpath, '%d.response_body.dat' % resource_ordinal), mode)
    
    def _delete_resource(self, resource_id):
        resource_ordinal = resource_id + 1
        os.remove(os.path.join(self._root_dirpath, '%d.request_headers.json' % resource_ordinal))
        os.remove(os.path.join(self._root_dirpath, '%d.response_headers.json' % resource_ordinal))
        os.remove(os.path.join(self._root_dirpath, '%d.response_body.dat' % resource_ordinal))


# ------------------------------------------------------------------------------

if __name__ == '__main__':
    main(sys.argv[1:])
