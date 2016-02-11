# pandaweb

Simple Go HTTPS webserver that supports reloading TLS certificates:

- Serves static content from a webroot directory
- Reloads TLS certificates on SIGHUP

## TODO

- Switch from flags to a config file
- Add some response headers (e.g. HSTS)
- Support FileServer config via config file, mostly so I can have Let's Encrypt do its webroot auth in a different directory
- Support response compression
