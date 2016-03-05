# caching_proxy.py

A standalone caching HTTP proxy that caches all requests to a particular domain.

When a HTTP resource is requested for the first time it will be fetched from the origin HTTP server and cached locally. All subsequent requests for the same resource will be returned from the cache.

For example, to cache all requests from <http://xkcd.com>, you'd start the caching proxy with the command:

```
python3 caching_proxy.py xkcd.com 6969 xkcd.cache
```

Then you could visit <http://localhost:6969/> to have the same effect as visiting <http://xkcd.com/> directly, except that repeated requests will be cached.

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

## API

While the proxy is running, it responds to the following API endpoints:

### `GET,HEAD /`

Undefined behavior.

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


## License

Copyright (c) 2016 by David Foster

You must ask me for permission before incorporating this software into your own software projects.