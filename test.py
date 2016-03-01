import caching_proxy
from caching_proxy import _format_proxy_path as format_proxy_path
from caching_proxy import _format_proxy_url as format_proxy_url
import gzip
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from multiprocessing import Process
import os
import os.path
import requests
import shutil
import signal
import tempfile
from threading import Thread
import unittest
from unittest import skip, TestCase


# ------------------------------------------------------------------------------
# Tests

_HOST = '127.0.0.1'
_PROXY_PORT = 9000
_DEFAULT_DOMAIN_PORT = 9001
_OTHER_DOMAIN_PORT = 9002

_PROXY_INFO = caching_proxy.ProxyInfo(host=_HOST, port=_PROXY_PORT)

_DEFAULT_DOMAIN = '%s:%s' % (_HOST, _DEFAULT_DOMAIN_PORT)
_OTHER_DOMAIN = '%s:%s' % (_HOST, _OTHER_DOMAIN_PORT)

_DEFAULT_DOMAIN_AS_IP = _DEFAULT_DOMAIN
_DEFAULT_DOMAIN_AS_DNS = 'localhost:%s' % _DEFAULT_DOMAIN_PORT

_PROXY_SERVER_URL = 'http://%s:%s' % (_HOST, _PROXY_PORT)
_DEFAULT_SERVER_URL = 'http://%s' % _DEFAULT_DOMAIN
_OTHER_SERVER_URL = 'http://%s' % _OTHER_DOMAIN


def forbid_unless_referer_starts_with(required_referer_prefix, ok_response):
    def generate_response(path, headers):
        referer = {k.lower(): v for (k, v) in headers.items()}.get('referer')
        if referer is None or not referer.startswith(required_referer_prefix):
            return dict(status_code=403)  # Forbidden
        else:
            return ok_response
    
    return generate_response

def modified_long_ago(ok_response):
    def generate_response(path, headers):
        if_modified_since = {k.lower(): v for (k, v) in headers.items()}.get('if-modified-since')
        if if_modified_since is not None:
            return dict(status_code=304)  # Not Modified
        else:
            return ok_response
    
    return generate_response

def no_weird_headers(ok_response):
    def generate_response(path, headers):
        has_weird_headers = 'X-Weird-Request-Header' in headers.keys()
        if has_weird_headers:
            return dict(status_code=400)  # Bad Request
        else:
            return ok_response
    
    return generate_response

def on_host(required_host, ok_response):
    def generate_response(path, headers):
        host = {k.lower(): v for (k, v) in headers.items()}.get('host')
        if host is None or host != required_host:
            return dict(status_code=404)  # Not Found
        else:
            return ok_response
    
    return generate_response

_DEFAULT_SERVER_RESPONSES = {  # like a blog
    '/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Default server</html>'
    ),
    '/posts/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Posts</html>'
    ),
    '/posts/image_no_hotlinking.png': forbid_unless_referer_starts_with(_DEFAULT_SERVER_URL, dict(
        headers=[('Content-Type', 'image/png')],
        body=b''
    )),
    '/posts/image_modified_long_ago.png': modified_long_ago(dict(
        headers=[('Content-Type', 'image/png')],
        body=b''
    )),
    '/api/no_weird_headers': no_weird_headers(dict(
        headers=[('Content-Type', 'application/json')],
        body='{}'
    )),
    '/posts/only_on_localhost.html': on_host(_DEFAULT_DOMAIN_AS_DNS, dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Most pages will not load if the Host header is wrong.</html>'
    )),
    '/posts/image_no_extension': dict(
        headers=[('Content-Type', 'image/png')],
        body=b''
    ),
    '/posts/super_secret.html': dict(
        headers=[
            ('Content-Type', 'text/html'),
            # NOTE: Normally this header would only be sent over an HTTPS connection.
            ('Strict-Transport-Security', 'max-age=31536000')
        ],
        body='<html>Secret!</html>'
    ),
    '/api/generate_weird_headers': dict(
        headers=[
            ('Content-Type', 'application/json'),
            ('X-Weird-Response-Header', 'boom')
        ],
        body='{}'
    ),
    '/posts/redirect_to_social_network.html': dict(
        status_code=302,  # Found
        headers=[('Location', _OTHER_SERVER_URL + '/feed/landing_page_from_blog.html')]
    ),
    '/posts/digits.txt': dict(
        headers=[
            ('Content-Type', 'text/plain'),
            ('Content-Encoding', 'gzip')
        ],
        body=gzip.compress(b'0123456789')
    ),
    '/posts/link_to_social_network.html': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html><a href="%s">Link</a></html>' % 
            (_OTHER_SERVER_URL + '/feed/landing_page_from_blog.html')
    ),
}

_OTHER_SERVER_RESPONSES = {  # like a social network
    '/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Other server</html>'
    ),
    '/feed/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Feed</html>'
    ),
    '/feed/landing_page_from_blog.html': forbid_unless_referer_starts_with(_DEFAULT_SERVER_URL, dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Thanks for visiting us from fooblog!</html>'
    )),
}

class CachingProxyTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls._proxy_server = start_proxy_server(_PROXY_PORT, _DEFAULT_DOMAIN)
        cls._default_server = start_origin_server(_DEFAULT_DOMAIN_PORT, _DEFAULT_SERVER_RESPONSES)
        cls._other_server = start_origin_server(_OTHER_DOMAIN_PORT, _OTHER_SERVER_RESPONSES)
    
    @classmethod
    def tearDownClass(cls):
        stop_proxy_server(cls._proxy_server)
        stop_origin_server(cls._default_server)
        stop_origin_server(cls._other_server)
    
    # === Request Formats ===
    
    # GET/HEAD of /__PATH__ when Referer is omitted
    #   -> http://__DEFAULT_DOMAIN__/__PATH__
    # TODO: Consider instead issuing an HTTP 3xx redirect to a qualified path.
    def test_request_of_unqualified_path_without_referer_reinterprets_with_default_domain(self):
        response = self._get('/posts/')
        self.assertEqual(200, response.status_code)
        self.assertEqual('<html>Posts</html>', response.text)
    
    # GET/HEAD of /__PATH__ when Referer is __OTHER_DOMAIN__
    #   -> http://__OTHER_DOMAIN__/__PATH__
    def test_request_of_unqualified_path_with_referer_uses_referer_domain(self):
        response = self._get('/', {
            'Referer': format_proxy_url('http', _OTHER_DOMAIN, '/feed/', proxy_info=_PROXY_INFO)
        }, allow_redirects=True)
        self.assertEqual(200, response.status_code)
        self.assertEqual('<html>Other server</html>', response.text)
    
    # GET/HEAD of /_/http/__OTHER_DOMAIN__/__PATH__
    #   -> http://__OTHER_DOMAIN__/__PATH__
    def test_request_of_qualified_http_path_works(self):
        response = self._get(format_proxy_path('http', _OTHER_DOMAIN, '/feed/'))
        self.assertEqual(200, response.status_code)
        self.assertEqual('<html>Feed</html>', response.text)
    
    # GET/HEAD of /_/https/__DOMAIN__/__PATH__
    #   -> https://__DOMAIN__/__PATH__
    @skip('not yet automated')
    def test_request_of_qualified_https_path_works(self):
        # TODO: Implement. It's a pain. Maybe the following will help:
        #       http://code.activestate.com/recipes/442473-simple-http-server-supporting-ssl-secure-communica/
        pass
    
    # === Request Header Processing: Client -> Proxy -> Server ===
    
    # Allows Request Header: User-Agent, Referer
    def test_allows_certain_headers_when_forwarding_request_to_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/image_no_hotlinking.png'),
            {'Referer': _DEFAULT_SERVER_URL + '/posts/'})
        self.assertEqual(200, response.status_code)
        
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/image_no_hotlinking.png'),
            {})
        self.assertEqual(403, response.status_code)
    
    # Blocks Request Header: If-Modified-Since
    def test_blocks_certain_headers_when_forwarding_request_to_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/image_modified_long_ago.png'),
            {})
        self.assertEqual(200, response.status_code)
        
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/image_modified_long_ago.png'),
            {'If-Modified-Since': 'Sat, 29 Oct 1994 19:43:31 GMT'})
        self.assertEqual(200, response.status_code)  # blocked, != 304
    
    # Blocks Request Header: X-Weird-Request-Header
    def test_blocks_unknown_headers_when_forwarding_request_to_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/api/no_weird_headers'),
            {})
        self.assertEqual(200, response.status_code)
        
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/api/no_weird_headers'),
            {'X-Weird-Request-Header': 'boom'})
        self.assertEqual(200, response.status_code)  # blocked, != 400
    
    # Rewrites Request Header: Host
    def test_rewrites_host_header_when_forwarding_request_to_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN_AS_DNS, '/posts/only_on_localhost.html'))
        self.assertEqual(200, response.status_code)
        
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN_AS_IP, '/posts/only_on_localhost.html'))
        self.assertEqual(404, response.status_code)
    
    # Rewrites Request Header: Referer
    def test_rewrites_referer_header_when_forwarding_request_to_server(self):
        # ...when coming from http://__PROXY_DOMAIN__/__PATH__
        response = self._get(
            format_proxy_path('http', _OTHER_DOMAIN, '/feed/landing_page_from_blog.html'),
            {'Referer': _PROXY_SERVER_URL + '/posts/redirect_to_social_network.html'})
        self.assertEqual(200, response.status_code)
        
        # ...when coming from http://__PROXY_DOMAIN__/_/http/__DEFAULT_DOMAIN__/__PATH__
        response = self._get(
            format_proxy_path('http', _OTHER_DOMAIN, '/feed/landing_page_from_blog.html'),
            {'Referer': format_proxy_url('http', _DEFAULT_DOMAIN, '/posts/redirect_to_social_network.html', proxy_info=_PROXY_INFO)})
        self.assertEqual(200, response.status_code)
    
    # === Response Header Processing: Client <- Proxy <- Server ===
    
    # Allows Response Header: Content-Type
    def test_allows_certain_headers_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/image_no_extension'))
        self.assertEqual(200, response.status_code)
        self.assertEqual('image/png', response.headers['Content-Type'])
    
    # Blocks Response Header: Strict-Transport-Security
    def test_blocks_certain_headers_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/super_secret.html'))
        self.assertEqual(200, response.status_code)
        self.assertNotIn('Strict-Transport-Security', response.headers)
    
    # Blocks Response Header: X-Weird-Response-Header
    def test_blocks_unknown_headers_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/api/generate_weird_headers'))
        self.assertEqual(200, response.status_code)
        self.assertNotIn('X-Weird-Response-Header', response.headers)
    
    # Blocks Response Header: X-Status-Code
    def test_blocks_internal_headers_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/'))
        self.assertEqual(200, response.status_code)
        self.assertNotIn('X-Status-Code', response.headers)
    
    # Rewrites Response Header: Location
    def test_rewrites_location_header_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/redirect_to_social_network.html'))
        self.assertEqual(302, response.status_code)  # Found
        self.assertEqual(
            format_proxy_url('http', _OTHER_DOMAIN, '/feed/landing_page_from_blog.html', proxy_info=_PROXY_INFO),
            response.headers['Location'])
    
    # Rewrites Response Header: Content-Length (if Content-Encoding is gzip or similar)
    def test_rewrites_content_length_header_when_returning_compressed_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/digits.txt'))
        self.assertEqual(200, response.status_code)
        self.assertEqual(b'0123456789', response.content)
        
        # NOTE: Presently the proxy never serves compressed responses to the client.
        #       This may change in the future.
        self.assertNotIn('Content-Encoding', response.headers)
        self.assertEqual('10', response.headers['Content-Length'])
    
    # === Response Content Processing: Client <- Proxy <- Server ===
    
    # Rewrites Response Content: absolute URLs
    def test_rewrites_absolute_urls_in_content_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/link_to_social_network.html'))
        self.assertEqual(200, response.status_code)
        self.assertIn(
            format_proxy_url('http', _OTHER_DOMAIN, '/feed/landing_page_from_blog.html', proxy_info=_PROXY_INFO),
            response.text)
    
    # Rewrites Response Content: protocol-relative URLs
    @skip('not yet automated')
    def test_rewrites_protocol_relative_urls_in_content_when_returning_response_from_server(self):
        pass
    
    # Retains Response Content: site-relative URLs
    @skip('not yet automated')
    def test_retains_site_relative_urls_in_content_when_returning_response_from_server(self):
        pass
    
    # Retains Response Content: relative URLs
    @skip('not yet automated')
    def test_retains_relative_urls_in_content_when_returning_response_from_server(self):
        pass
    
    # === Cache Behavior ===
    
    @skip('not yet automated')
    def test_returns_cached_response_by_default_if_available(self):
        pass
    
    # [Cache-Control: no-cache] should disable cache on a per-request basis
    @skip('not yet automated')
    def test_always_returns_fresh_response_if_cache_disabled(self):
        pass
    
    # === Utility ===
    
    def _get(self, path, headers={}, *, allow_redirects=False, cache=False):
        final_headers = dict(headers)  # clone
        if not cache:
            final_headers['Cache-Control'] = 'no-cache'
            final_headers['X-Pragma'] = 'no-cache'
        
        response = requests.get(
            _PROXY_SERVER_URL + path,
            headers=final_headers,
            allow_redirects=allow_redirects
        )
        return response


# ------------------------------------------------------------------------------
# Real Proxy Server

def start_proxy_server(port, default_origin_domain):
    cache_dirpath = os.path.join(
        tempfile.mkdtemp(prefix='caching_proxy_test_cache'),
        'default_origin.cache')
    
    process = Process(
        target=caching_proxy.main,
        args=(['--quiet', default_origin_domain, str(port), cache_dirpath],))
    process.start()
    
    return process


def stop_proxy_server(proxy_server):
    process = proxy_server
    
    # Send Control-C to the process to bring it down gracefully
    # NOTE: Graceful shutdown is required in order to collect
    #       code coverage metrics properly.
    os.kill(process.pid, signal.SIGINT)


# ------------------------------------------------------------------------------
# Mock Origin Server


def start_origin_server(port, responses):
    def create_request_handler(*args):
        nonlocal responses
        return TestServerHttpRequestHandler(*args, responses=responses)
    
    httpd = HTTPServer(('', port), create_request_handler)
    
    thread = Thread(target=httpd.serve_forever)
    thread.start()
    
    return httpd


def stop_origin_server(origin_server):
    httpd = origin_server
    
    httpd.shutdown()


class TestServerHttpRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, responses):
        self._responses = responses
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
        response = self._responses.get(self.path)
        if response is None:
            self.send_response(404)  # Not Found
            self.end_headers()
            return BytesIO(b'')
        
        # Compute response if it is dynamic
        if callable(response):
            response = response(self.path, self.headers)
        
        # Send header
        self.send_response(response.get('status_code', 200))
        for (k, v) in response.get('headers', {}):
            self.send_header(k, v)
        self.end_headers()
        
        # Prepare to send body
        response_body = response.get('body', b'')
        if isinstance(response_body, str):
            response_body = response_body.encode('utf8')
        return BytesIO(response_body)
    
    def log_message(self, *args):
        pass  # operate silently


# ------------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
