import caching_proxy
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from multiprocessing import Process
import os.path
import requests
import shutil
import tempfile
from threading import Thread
import unittest
from unittest import skip, TestCase


# ------------------------------------------------------------------------------
# Tests

_DEFAULT_DOMAIN_RESPONSES = {  # like a blog
    '/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Default domain</html>'
    ),
    '/posts/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Posts</html>'
    )
}

_OTHER_DOMAIN_RESPONSES = {  # like a social network
    '/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Other domain</html>'
    ),
    '/feed/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Feed</html>'
    )
}

class CachingProxyTests(TestCase):
    @classmethod
    def setUpClass(cls):
        proxy_port = 9000
        default_domain_port = 9001
        other_domain_port = 9002
        
        default_domain = '127.0.0.1:%s' % default_domain_port
        
        cls._proxy_server_url = 'http://127.0.0.1:%s' % proxy_port
        cls._default_server_url = 'http://%s' % default_domain
        cls._other_server_url = 'http://127.0.0.1:%s' % other_domain_port
        
        cls._proxy_server = start_proxy_server(proxy_port, default_domain)
        cls._default_server = start_origin_server(default_domain_port, _DEFAULT_DOMAIN_RESPONSES)
        cls._other_server = start_origin_server(other_domain_port, _OTHER_DOMAIN_RESPONSES)
        
    
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
        response = self._get('/posts/', [])
        self.assertEqual(200, response.status_code)
        self.assertEqual('<html>Posts</html>', response.text)
    
    # GET/HEAD of /__PATH__ when Referer is __OTHER_DOMAIN__
    #   -> http://__OTHER_DOMAIN__/__PATH__
    @skip('not yet automated')
    def test_request_of_unqualified_path_with_referer_uses_referer_domain(self):
        # TODO: Extract test server logic to enable simulation of other domains.
        pass
    
    # GET/HEAD of /_/http/__DOMAIN__/__PATH__
    #   -> http://__DOMAIN__/__PATH__
    @skip('not yet automated')
    def test_request_of_qualified_http_path_works(self):
        # TODO: Extract test server logic to enable simulation of other domains.
        pass
    
    # GET/HEAD of /_/https/__DOMAIN__/__PATH__
    #   -> https://__DOMAIN__/__PATH__
    @skip('not yet automated')
    def test_request_of_qualified_https_path_works(self):
        # TODO: Extract test server logic to enable simulation of other domains.
        pass
    
    # === Utility ===
    
    def _get(self, path, headers):
        response = requests.get(
            self._proxy_server_url + path,
            headers=headers,
            allow_redirects=False
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
    
    # TODO: Better to send SIGINT (Control-C), but there is no easy API for this.
    process.terminate()


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
        for (k, v) in response['headers']:
            self.send_header(k, v)
        self.end_headers()
        
        # Prepare to send body
        response_body = response['body']
        if isinstance(response_body, str):
            response_body = response_body.encode('utf8')
        return BytesIO(response_body)
    
    def log_message(self, *args):
        pass  # operate silently


# ------------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
