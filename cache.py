from collections import namedtuple, OrderedDict
import json
import os.path
import shutil
from threading import Lock


HttpResource = namedtuple('HttpResource', ['headers', 'content'])


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
        self._closed = False
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

        with self._open_response_headers(resource_id, 'r') as f:
            headers = json.load(f, object_pairs_hook=OrderedDict)
        f = self._open_response_content(resource_id, 'rb')
        return HttpResource(
            headers=headers,
            content=f,
        )
    
    def get_request_headers(self, url):
        """
        Gets the request headers for the resource at the specified url from this cache,
        or None if the specified resource is not in the cache.
        """
        with self._lock:
            resource_id = self._resource_id_for_url.get(url)
            if resource_id is None:
                return None
        
        with self._open_request_headers(resource_id, 'r') as f:
            return json.load(f, object_pairs_hook=OrderedDict)

    def put(self, url, request_headers, resource):
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
        Deletes the specified resource from this cache if it exists.
        
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
        Flushes all pending changes made to this cache to disk.
        """
        # TODO: Make this operation atomic, even if the write fails in the middle.
        with self._open_index('w') as f:
            f.write('\n'.join(self._urls))

    def close(self):
        """
        Closes this cache.
        """
        if self._closed:
            return
        self.flush()
        self._closed = True

    # === Utility ===

    def _open_index(self, mode='r'):
        return open(os.path.join(self._root_dirpath, '_index'), mode, encoding='utf8')
    
    def _open_request_headers(self, resource_id, mode='r'):
        return open(os.path.join(self._root_dirpath, '%d.request' % resource_id), mode, encoding='utf8')
    
    def _open_response_headers(self, resource_id, mode='r'):
        return open(os.path.join(self._root_dirpath, '%d.headers' % resource_id), mode, encoding='utf8')

    def _open_response_content(self, resource_id, mode='rb'):
        return open(os.path.join(self._root_dirpath, '%d.content' % resource_id), mode)
    
    def _delete_resource(self, resource_id):
        os.remove(os.path.join(self._root_dirpath, '%d.headers' % resource_id))
        os.remove(os.path.join(self._root_dirpath, '%d.content' % resource_id))
