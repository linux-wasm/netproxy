# linux-wasm netproxy

A WebSocket to TCP/UDP proxy: the way out to the network for
[Linux on WebAssembly](https://github.com/linux-wasm/distro).

A browser page cannot open sockets. The kernel in the page has its own
TCP/IP stack and a network card; the page's host code (`usernet.js` in
the [kernel tree](https://github.com/linux-wasm/linux), `tools/wasm/host/`)
is the other end of every connection the kernel starts and passes the
payload on to a proxy, which opens the real socket:

```
program -> kernel TCP/IP -> virtio network card -> usernet.js -> WebSocket -> netproxy -> TCP or UDP
```

The protocol is [Wisp](https://github.com/MercuryWorkshop/wisp-protocol)
version 1: many TCP and UDP streams over one WebSocket. This server and
the kernel's client were also tested against the reference implementation
(wisp-js 0.5.3 as the server: HTTP over TCP and a DNS lookup over UDP),
so either end can be exchanged for another Wisp implementation.

## Usage

Requirements: node >= 20.

```sh
npm ci
node server.mjs                 # ws://127.0.0.1:8765/
npm test                        # against local echo servers
```

Then, on the page's boot menu, tick "Network card" and enter the proxy's
URL. (Under node: `node-run.mjs --net ws://127.0.0.1:8765/`.)

| Option | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Address to listen on |
| `--port` | `8765` | Port to listen on |
| `--token SECRET` | none | Only accept WebSockets opened at the path `/SECRET` |
| `--allow-origin ORIGIN` | any | Only accept pages from this origin (repeatable), e.g. `https://linux-wasm.github.io` |
| `--allow-private` | off | Also connect to loopback, private and link-local addresses |
| `--verbose` | off | Log every stream |

## What running it means

Whoever can reach the proxy can make connections from the machine it
runs on. Hence the defaults:

- It listens on `127.0.0.1`: only programs on the same computer, such as
  your browser, can use it.
- It refuses destinations that are not public addresses (loopback,
  RFC 1918, link-local, CGNAT, multicast, and their IPv6 counterparts),
  so that a page cannot use it to reach your router or services on your
  machine. Names are resolved first and the connection goes to the
  address that was checked. `--allow-private` lifts this; with it, the
  system reaches the proxy's machine at 10.0.2.2.

A browser lets any web page you visit open a WebSocket to `127.0.0.1`.
With the defaults such a page could use the proxy to connect to public
addresses from your computer. `--allow-origin` (browsers send the page's
origin and a page cannot forge it) or `--token` close that.

To offer it to others, put it behind a TLS-terminating reverse proxy
(pages served over https can only open `wss://`), set `--token` or
`--allow-origin`, and keep in mind that you are then an open relay for
whoever has the token.

Limits: 256 streams per client, no limit on clients or bandwidth, no
authentication beyond the token. UDP streams end after two minutes
without traffic. There is no way to accept connections from outside.

## License

MIT, see [LICENSE](LICENSE). Depends on [ws](https://github.com/websockets/ws) (MIT).
