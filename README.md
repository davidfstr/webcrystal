# caching_proxy.py

An HTTP proxy that caches and persists all web pages accessed through it.

When a HTTP resource is requested for the first time it will be fetched from the origin HTTP server and cached locally. All subsequent requests for the same resource will be returned from the cache.

To start the proxy run a command like:

```
python3 caching_proxy.py 6969 xkcd.cache
```

Then you could visit <http://localhost:6969/_/http/xkcd.com/> to have the same effect as visiting <http://xkcd.com/> directly, except that all requests are cached and persisted in `xkcd.cache/`.


## Features

* Cached resources are persisted in a simple on-disk format, suitable for archival.
    * Indeed the original purpose of writing this proxy was as a first step
      for implementing a website archiver tool.


## Known Limitations

* This tool needs a catchy name.
* Sites that vary the content served at a particular URL depending on whether you are logged in or not can only have one version of the URL cached.


## Requirements

* Python 3.4+
* Make
* `pip3 install -r requirements.txt`


## Running the Tests

```
make test
```


## Gathering Code Coverage Metrics

```
make coverage
open htmlcov/index.html
```


## CLI

### Starting the Proxy

```
python3 caching_proxy.py <port> <cache_dirpath> [<default_origin_domain>]
```


## API

While the proxy is running, it responds to the following API endpoints.

Notice that GET is an accepted HTTP method for all endpoints, so that they can be requested using a regular web browser easily.

### `GET,HEAD /`

Redirects to the home page of the default origin domain if it is known. Returns:

* HTTP 404 (Not Found) if no default origin domain is specified (the default) or
* HTTP 307 (Temporary Redirect) to the default origin domain if it is specified.

### `GET,HEAD /_/http[s]/__PATH__`

If in online mode (the default):

* The requested resource will be fetched from the origin server and added to the cache if:
    * (1) it is not already cached,
    * (2) a `Cache-Control=no-cache` header is specified, or
    * (3) a `Pragma=no-cache` header is specified.
* The newly cached resource will be returned to the client, with all URLs in HTTP headers and content rewritten to point to the proxy.

If in offline mode:

* If the resource is in the cache, it will be returned to the client, with all URLs in HTTP headers and content rewritten to point to the proxy.
* If the resource is not in the cache, an HTTP 503 (Service Unavailable) response will be returned, with an HTML page that provides a link to the online version of the content.

### `POST,GET /_online`

Switches the proxy to online mode.

### `POST,GET /_offline`

Switches the proxy to offline mode.

### `POST,GET /_refresh/http[s]/__PATH__`

Refetches the specified URL from the origin server using the same request headers as the last time it was fetched. Returns:

* HTTP 200 (OK) if successful or
* HTTP 404 (Not Found) if the specified URL was not in the cache.

### `POST,GET /_delete/http[s]/__PATH__`

Deletes the specified URL in the cache. Returns:

* HTTP 200 (OK) if successful or
* HTTP 404 (Not Found) if the specified URL was not in the cache.


## License

Copyright (c) 2016 by David Foster

You must ask me for permission before incorporating this software into your own software projects.