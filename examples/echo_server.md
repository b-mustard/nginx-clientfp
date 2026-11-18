# Echo example: see the fingerprints your application receives

`echo_server.py` is a small HTTP server. It answers every request with the request headers it received, as JSON.
Put it behind nginx-clientfp, and you see the fingerprint headers (JA4, TLSFP, HTTP/2) that nginx adds for an
application.

```
client --TLS, HTTP/2 or HTTP/3--> nginx-clientfp :8443 --HTTP/1.1 + X-Client-* headers--> echo_server.py :8081
```

Use a test machine. The package replaces the distribution's `nginx`.

## 1. Get the source

The public address of the repository is not published yet. Use the address that you received.

```sh
git clone <repository-url> nginx-clientfp
cd nginx-clientfp
git checkout main          # or the branch or tag that you want to build
```

## 2. Build the package

You need Linux with `git`, Python 3 with the `venv` module (`python3-venv` on Debian and Ubuntu), and Docker
(rootless Docker is sufficient). The build downloads the nginx source.

Select the target that agrees with the machine where you will install the package: `ubuntu-24.04`, `ubuntu-26.04`,
`debian-12` or `debian-13`. Select the nginx line: `1.31` or `1.30`.

```sh
./build.sh build --target ubuntu-24.04 --flavor 1.31
```

The first build also makes the Docker build image, which takes some minutes. The result is a file in
`dist/<target>/`, for example `dist/ubuntu-24.04/nginx-clientfp_1.31.8-1_amd64.deb`.

If you already have the `.deb` file, go to step 3.

## 3. Install the package

Copy the `.deb` file to the test machine if necessary. Then install it. Use the name of the file from step 2:

```sh
sudo apt install ./dist/ubuntu-24.04/nginx-clientfp_1.31.8-1_amd64.deb
```

apt also installs `ssl-cert`, which makes the self-signed certificate that the example site uses.

## 4. Enable the example site

The site listens on port 8443 for TLS (HTTP/1.1 and HTTP/2) and for QUIC (HTTP/3). It sends each request to
`127.0.0.1:8081` with all the fingerprint headers.

```sh
sudo cp examples/nginx-echo.conf /etc/nginx/sites-enabled/clientfp-echo.conf
sudo nginx -t
sudo systemctl reload nginx
```

`nginx -t` must show `syntax is ok` and `test is successful`.

The installed package has a copy of both example files in `/usr/share/doc/nginx-clientfp/examples/`.

## 5. Start the echo server

The server needs only Python 3. It listens on `127.0.0.1:8081`.

```sh
python3 examples/echo_server.py --port 8081
```

The server writes `echo server on http://127.0.0.1:8081/`, then one line for each request, with the JA4 that it
received. Keep this terminal open, and use a second terminal for step 6. Press Ctrl-C to stop the server.

## 6. Send a request

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

- **`502 Bad Gateway`**: the echo server does not run. Do step 5.
- **`nginx -t` shows `unknown directive "clientfp_request_header"`**: the nginx on the machine is not
  nginx-clientfp. Do step 3.
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
