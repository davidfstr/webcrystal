# caching_proxy.py

A standalone caching HTTP proxy that caches all requests to a particular domain.

When a HTTP resource is requested for the first time it will be fetched from the origin HTTP server and cached locally. All subsequent requests for the same resource will be returned from the cache.

For example, to cache all requests from <http://xkcd.com>, you'd start the caching proxy with the command:

```
python3 caching_proxy.py xkcd.com 6969 xkcd.cache
```

Then you could visit <http://localhost:6969/> to have the same effect as visiting <http://xkcd.com/> directly, except that repeated requests will be cached.

### Known Limitations

* Only requests from the origin domain will be cached. No other domains will be cached.
* Absolute URLs to the origin domain will not be cached. Only resource-relative and site-relative URLs will be cached appropriately.
