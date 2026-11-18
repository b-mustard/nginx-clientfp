# Echo example: see the fingerprints your application receives

`echo_server.py` is a small HTTP server. It answers every request with the request headers it received, as JSON.
Put it behind nginx-clientfp, and you see the fingerprint headers (JA4, TLSFP, HTTP/2) that nginx adds for an
application.

```
client --TLS, HTTP/2 or HTTP/3--> nginx-clientfp :8443 --HTTP/1.1 + X-Client-* headers--> echo_server.py :8081
```

These steps build the package on the test machine and install it there. This is a native build: it uses the
compiler and the libraries of the test machine, and it does not need Docker.

The test machine must have:

- Ubuntu 24.04, Ubuntu 26.04, Debian 12 or Debian 13.
- Access to the internet. The build downloads the nginx source from GitHub.
- Approximately 800 MB of free disk space.
- A user account that can use `sudo`.

The package replaces the `nginx` package of the distribution. Do not use a machine where nginx serves real sites.

If you already have the `.deb` file for the test machine, go to step 4.

## 1. Install the prerequisites

1. Update the package lists:

   ```sh
   sudo apt update
   ```

2. Install the build tools and the libraries:

   ```sh
   sudo apt install git python3-venv build-essential debhelper dpkg-dev fakeroot lintian \
       libpcre2-dev libssl-dev zlib1g-dev
   ```

   `git` gets the source. `python3-venv` lets `build.sh` make its Python environment. `build-essential`,
   `debhelper`, `dpkg-dev`, `fakeroot` and `lintian` compile nginx, make the `.deb` file and check it.
   `libpcre2-dev`, `libssl-dev` and `zlib1g-dev` are the libraries that nginx uses.

   On a minimal system, apt installs approximately 340 packages, which use approximately 540 MB.

If a build package is missing, step 3 stops and shows the command that installs it.

## 2. Get the source

Do this step and step 3 as your normal user. Do not use `sudo`.

The public address of the repository is not published yet. Use the address that you received.

```sh
git clone <repository-url> nginx-clientfp
cd nginx-clientfp
git checkout main          # or the branch or tag that you want to build
```

## 3. Build the package

Select the nginx line: `1.31` or `1.30`. In the `nginx-clientfp` directory, build the package:

```sh
./build.sh build --flavor 1.31
```

The build does these steps:

1. It makes a Python environment in `.venv` (only the first time).
2. It downloads the source of the newest nginx release of the line into `extern_src/`.
3. It applies the patches, compiles nginx with the module and makes the `.deb` file.
4. It checks the package.

On a machine with 2 CPUs, the build takes approximately 2 minutes. The last line of the output is the path of the
package, for example:

```
dist/ubuntu-24.04/nginx-clientfp_1.31.8-1_amd64.deb
```

The directory name is the distribution of the machine, for example `dist/debian-13/` on Debian 13. The version in
the file name is the newest nginx release of the line.

To build a package for a different distribution, use a Docker build. See [Build](../README.md#build) in README.md.

## 4. Install the package

Install the package from step 3, and Python 3 and curl for steps 6 and 7:

```sh
sudo apt install ./dist/*/nginx-clientfp_1.31.*.deb python3 curl
```

For a `1.30` build, write `1.30` in the pattern. The pattern must find exactly one file:
`ls dist/*/nginx-clientfp_1.31.*.deb` shows the files that it finds. If you got the `.deb` file from a different
place, write its path instead.

apt also installs `ssl-cert`, which makes the self-signed certificate that the example site uses.

## 5. Enable the example site

The site listens on port 8443 for TLS (HTTP/1.1 and HTTP/2) and for QUIC (HTTP/3). It sends each request to
`127.0.0.1:8081` with all the fingerprint headers.

```sh
sudo cp examples/nginx-echo.conf /etc/nginx/sites-enabled/clientfp-echo.conf
sudo nginx -t
sudo systemctl reload nginx
```

`nginx -t` must show `syntax is ok` and `test is successful`.

The installed package has a copy of both example files in `/usr/share/doc/nginx-clientfp/examples/`.

## 6. Start the echo server

```sh
python3 examples/echo_server.py
```

The server has no options. It listens on `127.0.0.1:8081`, the address that the example site sends requests to, so
other machines cannot connect to it. Clients send their requests to nginx.

The server writes the address of nginx:

```
echo server ready. Send requests to nginx: https://localhost:8443/ (other machines: https://<this machine>:8443/)
```

Then it writes one line for each request, with the JA4 that it received. Keep this terminal open, and use a second
terminal for step 7. Press Ctrl-C to stop the server.

## 7. Send a request

From the test machine:

```sh
curl -k https://localhost:8443/
```

`-k` is necessary because the certificate is self-signed. The reply is JSON. `fingerprints` contains the headers that
nginx added, and `headers` contains all the request headers that the echo server received. This is the reply to
curl 8.5.0 on Ubuntu 24.04, with the long `X-Client-JA4-R` and `X-Client-JA4-RO` values removed:

```json
{
  "fingerprints": {
    "X-Client-JA4": "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6",
    "X-Client-JA4-O": "t13d3112h2_d7c3e2abb617_cad92ccb4254",
    "X-Client-TLSFP": "t13d3110h2_e8f1e7e78f70_75e657529f98_8180606ab83d",
    "X-Client-TLSFP-Registry": "1",
    "X-Client-HTTP2-FP": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
    "X-Client-HTTP2-FP-Hash": "64a832f547be33249bf4d33e8a46c5dc",
    "X-Client-HTTP2-FP-Overflow": "0"
  },
  "method": "GET",
  "path": "/",
  "headers": [
    ["Host", "localhost"],
    ["user-agent", "curl/8.5.0"],
    ...
  ]
}
```

The values depend on the client. Try other clients:

```sh
curl -k --http1.1 https://localhost:8443/   # HTTP/1.1: JA4 and TLSFP, but no HTTP/2 fingerprint
curl -k --http3 https://localhost:8443/     # HTTP/3: the JA4 starts with "q"
curl -k https://localhost:8443/fp           # the same values from nginx itself, without the echo server
```

`--http3` works only with a curl that has HTTP/3 support. The curl of Ubuntu 24.04 does not have it.

To use a browser, open `https://<test machine>:8443/` and accept the certificate warning. After the first reply,
the browser can change to HTTP/3 (the site sends an `Alt-Svc` header). To connect from another machine, open TCP
port 8443 and UDP port 8443 in the firewall.

## If it does not work

- **`502 Bad Gateway`**: the echo server does not run. Do step 6.
- **The echo server stops with `cannot listen on 127.0.0.1:8081: Address already in use`**: a different program
  uses port 8081, for example an echo server that still runs. Stop that program.
- **`nginx -t` shows `unknown directive "clientfp_request_header"`**: the nginx on the machine is not
  nginx-clientfp. Do step 4.
- **`nginx -t` shows `cannot load certificate "/etc/ssl/certs/ssl-cert-snakeoil.pem"`**: the certificate is
  missing. Run `sudo apt install ssl-cert`.
- **No reply on port 8443, and `/var/log/nginx/error.log` shows `bind() to 0.0.0.0:8443 failed (98: Address
  already in use)`**: a different program uses port 8443. Stop it, or change the port in the site file.
  `nginx -t` does not find this problem.
- **The JSON reply arrives, but `fingerprints` is empty**: the request went directly to port 8081. Send it to
  port 8443.

## Remove the example

```sh
sudo rm /etc/nginx/sites-enabled/clientfp-echo.conf
sudo systemctl reload nginx
```

Stop the echo server with Ctrl-C.
