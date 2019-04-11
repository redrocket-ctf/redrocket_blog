---
layout: post
title: MidnightsunCTF Quals 2019 - bigspin
category: Web
tags: 
    - lukas2511
---

bigspin was a challenge for the MidnightsunCTF Quals 2019

On visiting the linked website you get a message, asking if you are a `user`,
`admin` or `uberadmin`, or just a usual `pleb` (all links to identically named
subdirectories).

# We are all usual plebs

Visiting anything but `pleb` fails. Visting `pleb` results in the content of
example.com showing on your screen.

With a bit of trial and error it becomes obvious that it's a reverse proxy
for example.com with a missing `/` after the domain name, making it possible
to visit something like `/pleb.localhost.localdomain/user`.

# nginx.cönf

Accessing the directory gives us a directory listing with a single file called
`nginx.cönf ` (including a space at the end of the filename).

Just clicking on the file results in a 404, we have to double encode the
filename because nginx decodes it first before it's used in the reverse
proxy url.
Something like `/pleb.localhost.localdomain/user/nginx.c%25C3%25B6nf%2520`
works and gives us a copy of the used nginx config:

```
worker_processes 1;
user nobody nobody;
error_log /dev/stdout;
pid /tmp/nginx.pid;
events {
  worker_connections 1024;
}

http {

    # Set an array of temp and cache files options that otherwise defaults to
    # restricted locations accessible only to root.

    client_body_temp_path /tmp/client_body;
    fastcgi_temp_path /tmp/fastcgi_temp;
    proxy_temp_path /tmp/proxy_temp;
    scgi_temp_path /tmp/scgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    resolver 8.8.8.8 ipv6=off;

    server {
        listen 80;

        location / {
            root /var/www/html/public;
            try_files $uri $uri/index.html $uri/ =404;
        }

        location /user {
            allow 127.0.0.1;
            deny all;
            autoindex on;
            root /var/www/html/;
        }

        location /admin {
            internal;
            autoindex on;
            alias /var/www/html/admin/;
        }

        location /uberadmin {
            allow 0.13.3.7;
            deny all;
            autoindex on;
            alias /var/www/html/uberadmin/;
        }

        location ~ /pleb([/a-zA-Z0-9.:%]+) {
            proxy_pass   http://example.com$1;
        }

        access_log /dev/stdout;
        error_log /dev/stdout;
    }

}
```

# I'm an admin!

We can see that `/admin` is an `internal` block, which can't be accessed directly
but since we have control over the reverse proxy URL we can use it to point to a
server of our control and add a header like `X-Accel-Redirect: /admin/`, which
instructs nginx to do an internal redirect and delivers us the content as if we'd
have been able to access `/admin/` directly.

In the admin directory is a `flag.txt`, but it only tells us that the flag is only
for `uberadmins`.

# I lied, I'm really an uberadmin.

Since the location blocks are not terminated with a slash but the alias in the `/admin`
block is terminated we can inject dots to access a higher directory.

Setting the header on our server to `X-Accel-Redirect: /admin../uberadmin/flag.txt`
results in the flag.

Lesson learned: Terminate all paths and URLs with slashes.
