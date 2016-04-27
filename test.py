import webcrystal
from webcrystal import _format_proxy_path as format_proxy_path
from webcrystal import _format_proxy_url as format_proxy_url
from collections import OrderedDict
import gzip
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from multiprocessing import Process
import os
import os.path
import random
import shutil
import signal
import socket
import sys
import tempfile
from threading import Thread
import time
import unittest
from unittest import mock, skip, TestCase
import urllib3


# ------------------------------------------------------------------------------
# Tests

http = urllib3.PoolManager(retries=0)


_HOST = '127.0.0.1'
_PROXY_PORT = 9000
_DEFAULT_DOMAIN_PORT = 9001
_OTHER_DOMAIN_PORT = 9002

_PROXY_INFO = webcrystal._ProxyInfo(host=_HOST, port=_PROXY_PORT)

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

def forbid_unless_user_agent_is(required_user_agent, ok_response_func):
    def generate_response(path, headers):
        user_agent = {k.lower(): v for (k, v) in headers.items()}.get('user-agent')
        if user_agent != required_user_agent:
            return dict(status_code=403)  # Forbidden
        else:
            return ok_response_func(path, headers)
    
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

_default_server_counter = -1

def get_counter():
    def generate_response(path, headers):
        global _default_server_counter
        return dict(
            body=str(_default_server_counter)
        )
    
    return generate_response

_expected_request_headers = None

def expects_certain_request_headers():
    def generate_response(path, headers):
        global _expected_request_headers
        
        matching_request_headers = [k for k in headers.keys() if k in _expected_request_headers]
        if matching_request_headers != _expected_request_headers:
            return dict(
                status_code=400,  # Bad Request
                body='Expected headers %s but got %s.' % (
                    _expected_request_headers,
                    matching_request_headers
                )
            )
        else:
            return dict(status_code=200)  # OK
    
    return generate_response

_response_headers_to_send = None

def send_certain_response_headers():
    def generate_response(path, headers):
        global _response_headers_to_send
        
        return dict(status_code=200, headers=list(_response_headers_to_send.items()))
    
    return generate_response

def sometimes_disconnects():
    def generate_response(path, headers):
        global _should_disconnect
        
        if _should_disconnect:
            return '__disconnect__'
        else:
            return dict(status_code=200)
    
    return generate_response

def nice_404_page():
    def generate_response(path, headers):
        return dict(
            status_code=404,
            headers=[('Content-Type', 'text/plain')],
            body='No such page was found!'
        )
    
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
    '/posts/link_to_social_network_with_same_protocol.html': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html><a href="%s">Link</a></html>' % 
            ('//' + _OTHER_DOMAIN + '/feed/landing_page_from_blog.html')
    ),
    '/posts/link_to_homepage_with_site_relative_url.html': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html><a href="%s">Link</a></html>' % 
            ('/')
    ),
    '/posts/link_to_neighboring_post_with_relative_url.html': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html><a href="%s">Link</a></html>' % 
            ('neighboring_post.html')
    ),
    '/api/get_counter': get_counter(),
    '/api/get_counter_only_chrome': forbid_unless_user_agent_is('Chrome', get_counter()),
    '/api/expects_certain_request_headers': expects_certain_request_headers(),
    '/api/send_certain_response_headers': send_certain_response_headers(),
    '/sometimes_disconnects': sometimes_disconnects(),
    '/404.html': nice_404_page(),
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


class _AbstractEndpointTests(TestCase):
    has_default_domain = True
    
    @classmethod
    def setUpClass(cls):
        cls._proxy_server = _RealProxyServer(_PROXY_PORT, _DEFAULT_DOMAIN if cls.has_default_domain else None)
        cls._default_server = _MockOriginServer(_DEFAULT_DOMAIN_PORT, _DEFAULT_SERVER_RESPONSES)
        cls._other_server = _MockOriginServer(_OTHER_DOMAIN_PORT, _OTHER_SERVER_RESPONSES)
    
    @classmethod
    def tearDownClass(cls):
        cls._proxy_server.close()
        cls._default_server.close()
        cls._other_server.close()
    
    # === Utility: HTTP ===
    
    def _get(self, *args, **kwargs):
        return self._request('GET', *args, **kwargs)
    
    def _head(self, *args, **kwargs):
        return self._request('HEAD', *args, **kwargs)
    
    def _post(self, *args, **kwargs):
        return self._request('POST', *args, **kwargs)
    
    def _request(self, method, path, headers={}, *, allow_redirects=False, cache=False):
        final_headers = OrderedDict(headers)  # clone
        if not cache:
            final_headers['Cache-Control'] = 'no-cache'
            final_headers['X-Pragma'] = 'no-cache'
        
        urllib3_response = http.request(
            method=method,
            url=_PROXY_SERVER_URL + path,
            headers=final_headers,
            redirect=allow_redirects
        )
        return _HttpResponse(urllib3_response)


class _HttpResponse:
    """
    An HTTP response.
    
    Simulates the API of the "requests" library, since that's the library that
    the test suite was originally written with.
    """
    def __init__(self, urllib3_response):
        self._urllib3_response = urllib3_response
    
    @property
    def status_code(self):
        return self._urllib3_response.status
    
    @property
    def headers(self):
        return self._urllib3_response.headers
    
    @property
    def text(self):
        return self._urllib3_response.data.decode('utf8')
    
    @property
    def content(self):
        return self._urllib3_response.data


class CoreEndpointTests(_AbstractEndpointTests):
    """
    Acceptance tests for the behavior of the core endpoints:
        * GET,HEAD /
        * GET,HEAD /_/http[s]/__PATH__
    
    And supporting endpoints:
        * POST,GET /_online
        * POST,GET /_offline
    """
    
    # === Request Formats ===
    
    # GET/HEAD of /__PATH__ when Referer is omitted
    #   -> http://__DEFAULT_DOMAIN__/__PATH__
    def test_request_of_unqualified_path_without_referer_reinterprets_with_default_domain(self):
        for method in ['GET', 'HEAD', 'POST']:
            response = self._request(method, '/posts/', allow_redirects=True)
            if method == 'POST':
                self.assertEqual(405, response.status_code)
            else:
                self.assertEqual(200, response.status_code)
                self.assertEqual('<html>Posts</html>' if method == 'GET' else '', response.text)
    
    # GET/HEAD of /__PATH__ when Referer is __OTHER_DOMAIN__
    #   -> http://__OTHER_DOMAIN__/__PATH__
    def test_request_of_unqualified_path_with_referer_uses_referer_domain(self):
        for method in ['GET', 'HEAD', 'POST']:
            response = self._request(method, '/', {
                'Referer': format_proxy_url('http', _OTHER_DOMAIN, '/feed/', proxy_info=_PROXY_INFO)
            }, allow_redirects=True)
            if method == 'POST':
                self.assertEqual(405, response.status_code)
            else:
                self.assertEqual(200, response.status_code)
                self.assertEqual('<html>Other server</html>' if method == 'GET' else '', response.text)
    
    # GET/HEAD of /_/http/__OTHER_DOMAIN__/__PATH__
    #   -> http://__OTHER_DOMAIN__/__PATH__
    def test_request_of_qualified_http_path_works(self):
        for method in ['GET', 'HEAD', 'POST']:
            response = self._request(method, format_proxy_path('http', _OTHER_DOMAIN, '/feed/'))
            if method == 'POST':
                self.assertEqual(405, response.status_code)
            else:
                self.assertEqual(200, response.status_code)
                self.assertEqual('<html>Feed</html>' if method == 'GET' else '', response.text)
    
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
    def test_rewrites_protocol_relative_urls_in_content_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/link_to_social_network_with_same_protocol.html'))
        self.assertEqual(200, response.status_code)
        self.assertIn(
            format_proxy_url('http', _OTHER_DOMAIN, '/feed/landing_page_from_blog.html', proxy_info=_PROXY_INFO),
            response.text)
    
    # Retains Response Content: site-relative URLs
    # NOTE: Might rewrite these URLs in the future.
    def test_retains_site_relative_urls_in_content_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/link_to_homepage_with_site_relative_url.html'))
        self.assertEqual(200, response.status_code)
        self.assertIn('"/"', response.text)
    
    # Retains Response Content: relative URLs
    # NOTE: Might rewrite these URLs in the future.
    def test_retains_relative_urls_in_content_when_returning_response_from_server(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/link_to_neighboring_post_with_relative_url.html'))
        self.assertEqual(200, response.status_code)
        self.assertIn('"neighboring_post.html"', response.text)
    
    # === Header Order Preservation ===
    
    def test_sends_request_headers_in_same_order_as_client(self):
        global _expected_request_headers
        
        SAFE_REQUEST_HEADERS = [
            h for h in webcrystal._REQUEST_HEADER_WHITELIST
            if h not in ['host', 'referer']
        ]
        
        for i in range(5):
            headers = list(SAFE_REQUEST_HEADERS)  # clone
            if i != 0:
                random.shuffle(headers)
            
            _expected_request_headers = headers  # export
            
            response = self._get(
                format_proxy_path('http', _DEFAULT_DOMAIN, '/api/expects_certain_request_headers'),
                OrderedDict([(k, 'ignoreme') for k in headers]))
            self.assertEqual(200, response.status_code, response.text)
    
    def test_sends_response_headers_in_same_order_as_origin_server(self):
        global _response_headers_to_send
        
        SAFE_RESPONSE_HEADERS = [
            h for h in webcrystal._RESPONSE_HEADER_WHITELIST
            if h.startswith('x-')
        ]
        
        for i in range(5):
            headers = list(SAFE_RESPONSE_HEADERS)  # clone
            if i != 0:
                random.shuffle(headers)
            
            _response_headers_to_send = \
                OrderedDict([(k, 'ignoreme') for k in headers])  # export
            
            response = self._get(
                format_proxy_path('http', _DEFAULT_DOMAIN, '/api/send_certain_response_headers'))
            self.assertEqual(200, response.status_code)
            
            matching_response_headers = \
                [k for k in response.headers.keys() if k in _response_headers_to_send]
            self.assertEqual(headers, matching_response_headers)
    
    # === Online vs. Offline ===
    
    def test_returns_archived_response_by_default_if_available(self):
        global _default_server_counter
        
        _default_server_counter = 1
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/api/get_counter'),
            cache=False)
        self.assertEqual(200, response.status_code)
        self.assertEqual('1', response.text)
        
        _default_server_counter = 2
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/api/get_counter'),
            cache=True)
        self.assertEqual(200, response.status_code)
        self.assertEqual('1', response.text)  # should be stale
    
    # [Cache-Control: no-cache] should disable cache on a per-request basis
    def test_always_returns_fresh_response_if_cache_disabled(self):
        global _default_server_counter
        
        self.test_returns_archived_response_by_default_if_available()
        
        _default_server_counter = 3
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/api/get_counter'),
            cache=False)
        self.assertEqual(200, response.status_code)
        self.assertEqual('3', response.text)  # should be fresh
    
    def test_fetch_of_archived_resource_in_offline_mode_returns_the_resource(self):
        for starline_method in ['POST', 'GET']:
            response = self._get(
                format_proxy_path('http', _DEFAULT_DOMAIN, '/'),
                cache=False)
            self.assertEqual(200, response.status_code)
            self.assertIn('Default server', response.text)
            
            self._go_offline(method=starline_method)
            try:
                response = self._get(
                    format_proxy_path('http', _DEFAULT_DOMAIN, '/'),
                    cache=True)
                self.assertEqual(200, response.status_code)
                self.assertIn('Default server', response.text)
            finally:
                self._go_online(method=starline_method)
    
    def test_fetch_of_unarchived_resource_in_offline_mode_returns_http_503_with_link(self):
        for starline_method in ['POST', 'GET']:
            response = self._get(
                format_proxy_path('http', _DEFAULT_DOMAIN, '/',
                    command='_delete'),
                cache=False)
            self.assertIn(response.status_code, [200, 404])
            
            self._go_offline(method=starline_method)
            try:
                response = self._get(
                    format_proxy_path('http', _DEFAULT_DOMAIN, '/'),
                    cache=True)
                self.assertEqual(503, response.status_code)
                self.assertIn('"http://%s/"' % _DEFAULT_DOMAIN, response.text)
            finally:
                self._go_online(method=starline_method)
    
    def test_cannot_go_online_with_invalid_method(self):
        self._go_online(method='HEAD')
    
    def test_cannot_go_offline_with_invalid_method(self):
        try:
            self._go_offline(method='HEAD')
        finally:
            self._go_online()
    
    # === Misc ===
    
    def test_invalid_command_is_rejected(self):
        response = self._get('/_bogus/')
        self.assertEqual(400, response.status_code)  # Bad Request
    
    def test_fetch_of_invalid_proxy_url_returns_bad_request(self):
        response = self._get('/_/bogus_url')
        self.assertEqual(400, response.status_code)  # Bad Request
    
    def test_fetch_of_unreachable_origin_server_returns_http_502(self):
        response = self._get('/_/http/nosuchsite-really.com/')
        self.assertEqual(502, response.status_code)  # Bad Gateway
        self.assertIn('"http://nosuchsite-really.com/"', response.text)
    
    def test_head_works(self):
        response = self._head(format_proxy_path('http', _DEFAULT_DOMAIN, '/'))
        self.assertEqual('text/html', response.headers['Content-Type'])
    
    # === Utility: Commands ===
    
    def _go_online(self, *, method='POST'):
        response = self._request(method, '/_online')
        self.assertEqual(200 if method in ['POST', 'GET'] else 405, response.status_code)
    
    def _go_offline(self, *, method='POST'):
        response = self._request(method, '/_offline')
        self.assertEqual(200 if method in ['POST', 'GET'] else 405, response.status_code)


class CoreEndpointTests2(_AbstractEndpointTests):
    """
    Subset of the core endpoint tests that check behavior when there is no
    default origin domain.
    """
    
    has_default_domain = False
    
    # === Request Formats ===
    
    # GET/HEAD of /__PATH__ when Referer is omitted
    #   -> HTTP 404
    def test_request_of_unqualified_path_without_referer_returns_404_if_no_default_domain(self):
        for method in ['GET', 'HEAD', 'POST']:
            response = self._request(method, '/posts/', allow_redirects=True)
            if method == 'POST':
                self.assertEqual(405, response.status_code)
            else:
                self.assertEqual(404, response.status_code)


class RawEndpointTests(_AbstractEndpointTests):
    """
    Acceptance tests for the raw endpoint:
        * GET,HEAD /_raw/http[s]/__PATH__
    
    This endpoint exists primarily so that scrapers built on top of webcrystal
    can access the raw content of an archive without causing an implicit fetch
    of missing content, as would be the case with the core /_/ endpoint.
    """
    
    def test_request_of_resource_in_archive_returns_original_resource_verbatim(self):
        ORIGINAL_RESOURCE = _DEFAULT_SERVER_RESPONSES['/posts/link_to_social_network.html']
        
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/link_to_social_network.html'))
        self.assertEqual(200, response.status_code)
        
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/posts/link_to_social_network.html',
                command='_raw'))
        self.assertEqual(200, response.status_code)
        self.assertEqual(ORIGINAL_RESOURCE['body'], response.text)
        self.assertEqual(
            OrderedDict(ORIGINAL_RESOURCE['headers']),
            self._remove_automatically_added_headers(
                OrderedDict(response.headers)))
    
    def test_request_of_resource_not_in_archive_returns_http_503_with_link(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/not_in_archive',
                command='_raw'))
        self.assertEqual(503, response.status_code)
        self.assertIn('"http://%s/not_in_archive"' % _DEFAULT_DOMAIN, response.text)
    
    def test_request_of_404_in_archive_returns_404(self):
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/404.html'))
        self.assertEqual(404, response.status_code)
        self.assertEqual('No such page was found!', response.text)
        
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/404.html',
                command='_raw'))
        self.assertEqual(404, response.status_code)
        self.assertEqual('No such page was found!', response.text)
    
    @skip('not yet automated')
    def test_should_not_passthrough_connection_specific_headers(self):
        # In particualr the 'Content-Encoding' header, if it was received
        # from the origin server, should not be returned from the _raw endpoint.
        pass
    
    def test_cannot_use_invalid_method(self):
        response = self._request('POST',
            format_proxy_path('http', _DEFAULT_DOMAIN, '/',
                command='_raw'))
        self.assertEqual(405, response.status_code)
    
    # Removes headers added automatically by http.server (the underlying
    # server used by the MockOriginServer). They are hard to remove without
    # monkeypatching. So just ignore them.
    def _remove_automatically_added_headers(self, headers):
        headers = headers.copy()
        for hn in ['Server', 'Date', 'Content-Length']:
            if hn in headers:
                del headers[hn]
        return headers


class RefreshEndpointTests(_AbstractEndpointTests):
    """
    Acceptance tests for the refresh endpoint:
        * POST,GET /_refresh/http[s]/__PATH__
    
    This endpoint mainly exists to prove that webcrystal persists the original
    request headers for a previously fetched URL.
    """
    
    # === Refresh ===
    
    def test_can_refresh_resource_without_resending_request_headers(self):
        for method in ['POST', 'GET']:
            global _default_server_counter
            
            _default_server_counter = 1
            response = self._get(
                format_proxy_path('http', _DEFAULT_DOMAIN, '/api/get_counter_only_chrome'),
                {'User-Agent': 'Chrome'})
            self.assertEqual(200, response.status_code)
            self.assertEqual('1', response.text)
            
            _default_server_counter = 2
            response = self._request(method,
                format_proxy_path('http', _DEFAULT_DOMAIN, '/api/get_counter_only_chrome',
                    command='_refresh'))
            self.assertEqual(200, response.status_code)
            self.assertEqual('', response.text)
            
            response = self._get(
                format_proxy_path('http', _DEFAULT_DOMAIN, '/api/get_counter_only_chrome'),
                cache=True)
            self.assertEqual(200, response.status_code)
            self.assertEqual('2', response.text)
    
    def test_cannot_refresh_unarchived_resource(self):
        response = self._post(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/never_archived',
                command='_refresh'))
        self.assertEqual(404, response.status_code)
    
    def test_cannot_refresh_resource_with_invalid_method(self):
        response = self._request('HEAD',
            format_proxy_path('http', _DEFAULT_DOMAIN, '/',
                command='_refresh'))
        self.assertEqual(405, response.status_code)
    
    def test_refresh_of_unreachable_origin_server_returns_http_502(self):
        global _should_disconnect
        
        _should_disconnect = False
        response = self._get(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/sometimes_disconnects'))
        self.assertEqual(200, response.status_code)
        
        _should_disconnect = True
        response = self._post(
            format_proxy_path('http', _DEFAULT_DOMAIN, '/sometimes_disconnects',
                command='_refresh'))
        self.assertEqual(502, response.status_code)  # Bad Gateway


class ModuleImportTests(TestCase):
    """
    Acceptance tests related to the behavior of importing "webcrystal",
    particularly as related to dependencies available in the environment.
    """
    
    def test_missing_urllib3_gives_nice_error_message(self):
        with mock.patch.dict('sys.modules', {'urllib3': None}):
            del sys.modules['webcrystal']  # unimport
            try:
                import webcrystal
            except ImportError as e:
                self.assertIn('webcrystal requires urllib3. Try: pip3 install urllib3', str(e))
            else:
                self.fail()
    
    def test_unsupported_python_version_gives_nice_error_message(self):
        old_version_info = sys.version_info
        try:
            sys.version_info = (2, 7)
            
            del sys.modules['webcrystal']  # unimport
            try:
                import webcrystal
            except ImportError as e:
                self.assertIn('webcrystal requires Python 3.4 or later.', str(e))
            else:
                self.fail()
        finally:
            sys.version_info = old_version_info
    
    def test_imports_when_missing_pyopenssl(self):
        with mock.patch.dict('sys.modules', {'urllib3.contrib.pyopenssl': None}):
            del sys.modules['webcrystal']  # unimport
            import webcrystal
    
    def test_imports_when_missing_certifi(self):
        with mock.patch.dict('sys.modules', {'certifi': None}):
            del sys.modules['webcrystal']  # unimport
            import webcrystal


# ------------------------------------------------------------------------------
# Real Proxy Server

class _RealProxyServer:
    def __init__(self, port, default_origin_domain):
        self._port = port
        
        archive_dirpath = os.path.join(
            tempfile.mkdtemp(prefix='webcrystal_test_archive'),
            'default_origin.wbcr')
        
        args = ['--quiet', str(port), archive_dirpath,]
        if default_origin_domain is not None:
            args.append(default_origin_domain)
        
        self._process = Process(target=webcrystal.main, args=(args,))
        self._process.start()
        
        wait_until_port_not_open('127.0.0.1', port)
    
    def close(self):
        # Send Control-C to the process to bring it down gracefully
        # NOTE: Graceful shutdown is required in order to collect
        #       code coverage metrics properly.
        os.kill(self._process.pid, signal.SIGINT)
        
        wait_until_port_open('127.0.0.1', self._port)


# ------------------------------------------------------------------------------
# Mock Origin Server


class _MockOriginServer:
    def __init__(self, port, responses):
        self._port = port
        
        def create_request_handler(*args):
            nonlocal responses
            return _TestServerHttpRequestHandler(*args, responses=responses)
        
        self._httpd = HTTPServer(('', port), create_request_handler)
        
        # NOTE: Use a low poll interval so that shutdown() completes quickly
        thread = Thread(target=lambda: self._httpd.serve_forever(poll_interval=50/1000))
        thread.start()
        
        wait_until_port_not_open('127.0.0.1', port)
    
    def close(self):
        self._httpd.shutdown()
        self._httpd.socket.close()
        
        assert is_port_open('127.0.0.1', self._port)

class _TestServerHttpRequestHandler(BaseHTTPRequestHandler):
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
        
        # Disconnect abruptly if requested to
        if response == '__disconnect__':
            return BytesIO(b'')
        
        # Send header
        self.send_response(response.get('status_code', 200))
        for (k, v) in response.get('headers', []):
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
# Utility

def wait_until_port_not_open(hostname, port):
    while is_port_open(hostname, port):
        time.sleep(20/1000)


def wait_until_port_open(hostname, port):
    while not is_port_open(hostname, port):
        time.sleep(20/1000)


def is_port_open(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result = s.connect_ex((hostname, port))
        if result == 0:
            return False
        else:
            return True
    finally:
        s.close()


# ------------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
