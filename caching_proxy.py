import atexit
from collections import namedtuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
import json
import os.path
import re
import requests
import shutil
import sys
from threading import Lock


def main(args):
    # Parse arguments
    (origin_host, port, cache_dirpath,) = args
    address = ''
    port = int(port)
    
    # Open cache
    cache = HttpResourceCache(cache_dirpath)
    atexit.register(lambda: cache.close())
    
    def create_request_handler(*args):
        return CachingHTTPRequestHandler(*args, origin_host=origin_host, cache=cache)
    
    print('Listening on %s:%s' % (address, port))
    httpd = HTTPServer((address, port), create_request_handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


_ABSOLUTE_REQUEST_URL_RE = re.compile(r'^/_/(https?)/([^/]+)(/.*)$')

class CachingHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that serves requests from an HttpResourceCache.
    When a resource is requested that isn't in the cache, it will be added
    to the cache automatically.
    """
    
    def __init__(self, *args, origin_host, cache):
        self._origin_host = origin_host
        self._cache = cache
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
        # Recognize paths like "/_/http/xkcd.com/" and interpret them as
        # absolute URLs like "http://xkcd.com/".
        if self.path.startswith('/_/'):
            m = _ABSOLUTE_REQUEST_URL_RE.match(self.path)
            if m is None:
                self.send_response(400)  # Bad Request
                self.end_headers()
                return BytesIO(b'')
            
            request_url = '%s://%s%s' % m.groups()
        else:
            request_url = 'http://%s%s' % (self._origin_host, self.path)
        
        # Try fetch requested resource from cache.
        # If missing fetch the resource from the origin and add it to the cache.
        resource = self._cache.get(request_url)
        if resource is None:
            request_headers = dict(self.headers)
            for key in list(request_headers.keys()):
                if key.lower() == 'host':
                    del request_headers[key]
            request_headers['Host'] = self._origin_host
            
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
        
        self.send_response(int(resource.headers['X-Status-Code']))
        for (key, value) in resource.headers.items():
            if key == 'X-Status-Code':
                continue
            self.send_header(key, value)
        self.end_headers()
        
        return resource.content


class HttpResourceCache:
    """
    Persistent cache of HTTP resources, include the full content and headers of
    each resource.
    
    This class is threadsafe.
    """
    
    def __init__(self, root_dirpath):
        """
        Opens the existing cache at the specified directory,
        or creates a new cache if there is no such directory.
        """
        self._lock = Lock()
        self._root_dirpath = root_dirpath
        
        # Create empty cache if cache does not already exist
        if not os.path.exists(root_dirpath):
            os.mkdir(root_dirpath)
            with self._open_index('w') as f:
                f.write('')
        
        # Load cache
        with self._open_index('r') as f:
            self._urls = f.read().split('\n')
            if self._urls == ['']:
                self._urls = []
        # NOTE: It is possible for the cache to contain multiple IDs for the
        #       same path under rare circumstances. In that case the last ID wins.
        self._resource_id_for_url = {url: i for (i, url) in enumerate(self._urls)}
    
    def get(self, url):
        """
        Gets the HttpResource at the specified url from this cache,
        or None if the specified resource is not in the cache.
        """
        with self._lock:
            resource_id = self._resource_id_for_url.get(url)
            if resource_id is None:
                return None
        
        with self._open_header(resource_id, 'r') as f:
            headers = json.load(f)
        f = self._open_content(resource_id, 'rb')
        return HttpResource(
            headers=headers,
            content=f,
        )
    
    def put(self, url, resource):
        """
        Puts the specified HttpResource into this cache, replacing any previous
        resource with the same url.
        
        If two difference resources are put into this cache at the same url
        concurrently, the last one put into the cache will eventually win.
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
        with self._open_header(resource_id, 'w') as f:
            json.dump(resource.headers, f)
        with self._open_content(resource_id, 'wb') as f:
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
    
    def flush(self):
        """
        Flushes all pending changes made to this cache to disk.
        """
        # TODO: Make this operation atomic, even if the write fails in the middle.
        with self._open_index('w') as f:
            f.write('\n'.join(self._urls))
    
    def close(self):
        """
        Closes this cache.
        """
        self.flush()
    
    # === Utility ===
    
    def _open_index(self, mode='r'):
        return open(os.path.join(self._root_dirpath, '_index'), mode, encoding='utf8')
    
    def _open_header(self, resource_id, mode='r'):
        return open(os.path.join(self._root_dirpath, '%d.headers' % resource_id), mode, encoding='utf8')
    
    def _open_content(self, resource_id, mode='rb'):
        return open(os.path.join(self._root_dirpath, '%d.content' % resource_id), mode)


HttpResource = namedtuple('HttpResource', ['headers', 'content'])


if __name__ == '__main__':
    main(sys.argv[1:])
