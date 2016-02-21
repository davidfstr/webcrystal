from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
import requests
import shutil


ADDRESS = ''
PORT = 6969  # arbitrary
ORIGIN_HOST = 'xkcd.com'


def main():
    print('Listening on %s:%s' % (ADDRESS, PORT))
    httpd = HTTPServer((ADDRESS, PORT), CachingHTTPRequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


class CachingHTTPRequestHandler(BaseHTTPRequestHandler):
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
        request_headers = dict(self.headers)
        for key in list(request_headers.keys()):
            if key.lower() == 'host':
                del request_headers[key]
        request_headers['Host'] = ORIGIN_HOST
        
        response = requests.get(
            'http://%s%s' % (ORIGIN_HOST, self.path),
            headers=request_headers,
            allow_redirects=False
        )
        
        # NOTE: Not streaming the response at the moment for simplicity.
        #       Probably want to use iter_content() later.
        response_content = response.content
        
        response_headers = dict(response.headers)
        for key in list(response_headers.keys()):
            if key.lower() in ['content-encoding', 'content-length']:
                del response_headers[key]
        response_headers['Content-Length'] = str(len(response_content))
        
        self.send_response(response.status_code)
        for (key, value) in response_headers.items():
            self.send_header(key, value)
        self.end_headers()
        
        return BytesIO(response_content)


if __name__ == '__main__':
    main()
