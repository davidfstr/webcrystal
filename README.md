# caching_proxy.py

An HTTP proxy that saves every web page accessed through it.
This is useful for automatically archiving websites.

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


## Archival Format

When this proxy is started with a command like:

```
python3 caching_proxy.py 6969 xkcd.cache
```

It creates a Project in the directory `xkcd.cache` in the following format:


### `xkcd.cache/index.txt`

* Text file listing the URL of each archived HTTP Resource, one per line.
* UTF-8 encoded.
* Unix line endings.

Example:

```
http://xkcd.com/
http://xkcd.com/s/b0dcca.css
http://xkcd.com/1645/
```

The preceding example project contains 3 HTTP Resources, numbered #0, #1, and #2.


### `xkcd.cache/0.request_headers.json`

* JSON file listing the HTTP request headers sent to the origin HTTP server to obtain the HTTP resource.
* UTF-8 encoded.

Example:

```
{"Accept-Language": "en-us", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Host": "xkcd.com", "Accept-Encoding": "gzip, deflate", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/601.4.4 (KHTML, like Gecko) Version/9.0.3 Safari/601.4.4"}
```


### `xkcd.cache/0.response_headers.json`

* JSON file listing the HTTP response headers received from the origin HTTP server when obtaining the HTTP resource.
* UTF-8 encoded.
* Contains an internal "X-Status-Code" header that indicates the HTTP response code received from the origin HTTP server.

Example:

```
{"Cache-Control": "public", "Connection": "keep-alive", "Accept-Ranges": "bytes", "X-Cache-Hits": "0", "Date": "Tue, 15 Mar 2016 04:37:05 GMT", "Age": "0", "X-Served-By": "cache-sjc3628-SJC", "Content-Type": "text/html", "Server": "lighttpd/1.4.28", "X-Status-Code": "404", "X-Cache": "MISS", "Content-Length": "345", "X-Timer": "S1458016625.375814,VS0,VE148", "Via": "1.1 varnish"}
```

### `xkcd.cache/0.response_body.dat`

* Binary file containing the contents of the HTTP response body received from the origin HTTP server when obtaining the HTTP resource.


## License

Copyright (c) 2016 by David Foster

You must ask me for permission before incorporating this software into your own software projects.