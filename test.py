from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
import requests
import shutil
from threading import Thread
import unittest
from unittest import skip, TestCase


# ------------------------------------------------------------------------------
# Tests

class CachingProxyTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls._test_server = start_test_server(9000)
        cls._test_server_url = 'http://127.0.0.1:9000'
    
    @classmethod
    def tearDownClass(cls):
        stop_test_server(cls._test_server)
    
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
    def test_request_of_qualified_http_path_works(self):
        # TODO: Extract test server logic to enable simulation of other domains.
        pass
    
    # GET/HEAD of /_/https/__DOMAIN__/__PATH__
    #   -> https://__DOMAIN__/__PATH__
    def test_request_of_qualified_https_path_works(self):
        # TODO: Extract test server logic to enable simulation of other domains.
        pass
    
    # === Utility ===
    
    def _get(self, path, headers):
        response = requests.get(
            self._test_server_url + path,
            headers=headers,
            allow_redirects=False
        )
        return response


# ------------------------------------------------------------------------------
# Test Server


def start_test_server(port):
    httpd = HTTPServer(('', port), TestServerHttpRequestHandler)
    
    thread = Thread(target=httpd.serve_forever)
    thread.start()
    
    return httpd


def stop_test_server(test_server):
    httpd = test_server
    httpd.shutdown()


_RESPONSE_FOR_REQUEST = {
    '/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Home page</html>'
    ),
    '/posts/': dict(
        headers=[('Content-Type', 'text/html')],
        body='<html>Posts</html>'
    )
}

class TestServerHttpRequestHandler(BaseHTTPRequestHandler):
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
        response = _RESPONSE_FOR_REQUEST.get(self.path)
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
    
    def log_message(*args):
        pass  # operate silently


# ------------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
