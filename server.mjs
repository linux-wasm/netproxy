#!/usr/bin/env node
// WebSocket to TCP/UDP proxy for Linux on WebAssembly.
//
// A browser page cannot open sockets. The kernel in the page has a real
// TCP/IP stack, and the page's host code (usernet.js in the kernel tree)
// ends every connection the kernel starts and passes the payload to a
// server like this one, which opens the real socket. The protocol is Wisp
// version 1 (https://github.com/MercuryWorkshop/wisp-protocol): many TCP
// and UDP streams over one WebSocket.
//
//   node server.mjs [--host 127.0.0.1] [--port 8765] [--token SECRET]
//                   [--allow-private] [--allow-origin ORIGIN]... [--verbose]
//
// See README.md for what the options mean and what running this exposes.
import dgram from "node:dgram";
import dns from "node:dns/promises";
import { createServer } from "node:http";
import net from "node:net";
import { parseArgs } from "node:util";
import { WebSocketServer } from "ws";

const CONNECT = 1;
const DATA = 2;
const CONTINUE = 3;
const CLOSE = 4;
const TCP = 1;
const UDP = 2;

const REASON_VOLUNTARY = 0x02;
const REASON_NETWORK = 0x03;
const REASON_INVALID = 0x41;
const REASON_UNREACHABLE = 0x42;
const REASON_TIMEOUT = 0x43;
const REASON_REFUSED = 0x44;
const REASON_BLOCKED = 0x48;

// DATA packets a client may send on a TCP stream before it has to wait
// for a CONTINUE.
const ALLOWANCE = 128;
// Stop reading from a remote while this much is waiting to go to the client.
const HIGH_WATER = 1 << 20;
const CONNECT_TIMEOUT_MS = 15000;
const UDP_IDLE_MS = 120000;
const MAX_STREAMS = 256;

// Addresses that are not "the internet": this machine and the networks
// it may be attached to. Refused unless --allow-private.
const privateAddresses = new net.BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 3],
])
  privateAddresses.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [
  ["::", 127], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
])
  privateAddresses.addSubnet(address, prefix, "ipv6");

function isPrivate(address, family) {
  // ::ffff:a.b.c.d is a.b.c.d.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return privateAddresses.check(mapped[1], "ipv4");
  return privateAddresses.check(address, family === 6 ? "ipv6" : "ipv4");
}

function packet(type, id, payload = new Uint8Array(0)) {
  const out = Buffer.alloc(5 + payload.length);
  out[0] = type;
  out.writeUInt32LE(id, 1);
  out.set(payload, 5);
  return out;
}

const u32 = (value) => {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
};

// Start a proxy. Returns the http.Server (listening).
export function startProxy(options = {}) {
  const {
    host = "127.0.0.1", port = 8765, token, allowPrivate = false,
    allowOrigin = [], verbose = false,
  } = options;
  const log = verbose ? (...args) => console.log(new Date().toISOString(), ...args) : () => {};

  // Resolve first and connect to the address that was checked, so that a
  // name cannot point somewhere else between the check and the connect.
  async function resolve(hostname) {
    const addresses = net.isIP(hostname)
      ? [{ address: hostname, family: net.isIP(hostname) }]
      : await dns.lookup(hostname, { all: true });
    const allowed = addresses.find((a) => allowPrivate || !isPrivate(a.address, a.family));
    if (!allowed) throw Object.assign(new Error("blocked"), { reason: REASON_BLOCKED });
    return allowed;
  }

  const server = createServer((request, response) => {
    response.writeHead(200, { "Content-Type": "text/plain" });
    response.end("linux-wasm netproxy: connect with a WebSocket (Wisp v1)\n");
  });

  const wss = new WebSocketServer({
    server,
    perMessageDeflate: false,
    verifyClient({ req, origin }) {
      if (token && new URL(req.url, "http://x").pathname !== `/${token}`) return false;
      return !allowOrigin.length || allowOrigin.includes(origin);
    },
  });

  wss.on("connection", (ws, request) => {
    const peer = request.socket.remoteAddress;
    const streams = new Map();
    log(`client ${peer} connected`);

    const send = (type, id, payload) => {
      if (ws.readyState === ws.OPEN) ws.send(packet(type, id, payload));
    };
    const close = (id, reason) => {
      const stream = streams.get(id);
      if (!stream) return;
      streams.delete(id);
      stream.destroy();
      send(CLOSE, id, Uint8Array.of(reason));
      log(`stream ${id} closed, reason 0x${reason.toString(16)}`);
    };

    async function connect(id, type, port, hostname) {
      // Until the socket exists, the stream collects what the client
      // already sends.
      const pending = [];
      const stream = { write: (data) => pending.push(data), destroy() {} };
      streams.set(id, stream);
      let target;
      try {
        target = await resolve(hostname);
      } catch (e) {
        return close(id, e.reason ?? REASON_UNREACHABLE);
      }
      if (streams.get(id) !== stream) return; // closed meanwhile
      log(`stream ${id}: ${type === TCP ? "tcp" : "udp"} ${hostname} (${target.address}) port ${port}`);

      if (type === TCP) {
        const socket = net.connect({ host: target.address, port, timeout: CONNECT_TIMEOUT_MS });
        let unacknowledged = 0;
        stream.destroy = () => socket.destroy();
        stream.write = (data) =>
          socket.write(data, () => {
            // Written: the client may send that many more.
            if (++unacknowledged >= ALLOWANCE / 2) {
              unacknowledged = 0;
              send(CONTINUE, id, u32(ALLOWANCE));
            }
          });
        socket.on("connect", () => {
          socket.setTimeout(0);
          socket.setNoDelay(true);
        });
        socket.on("timeout", () => close(id, REASON_TIMEOUT));
        socket.on("data", (data) => {
          if (ws.readyState !== ws.OPEN) return;
          ws.send(packet(DATA, id, data), () => {
            if (ws.bufferedAmount < HIGH_WATER) socket.resume();
          });
          if (ws.bufferedAmount >= HIGH_WATER) socket.pause();
        });
        socket.on("end", () => close(id, REASON_VOLUNTARY));
        socket.on("error", (e) =>
          close(id, e.code === "ECONNREFUSED" ? REASON_REFUSED
            : e.code === "ETIMEDOUT" ? REASON_TIMEOUT
            : e.code === "EHOSTUNREACH" || e.code === "ENETUNREACH" ? REASON_UNREACHABLE
            : REASON_NETWORK));
      } else {
        const socket = dgram.createSocket(target.family === 6 ? "udp6" : "udp4");
        let idle;
        const touch = () => {
          clearTimeout(idle);
          idle = setTimeout(() => close(id, REASON_VOLUNTARY), UDP_IDLE_MS);
        };
        stream.destroy = () => {
          clearTimeout(idle);
          socket.close();
        };
        stream.write = (data) => {
          touch();
          socket.send(data, port, target.address);
        };
        socket.on("message", (data, from) => {
          // Only answers from where the datagrams went.
          if (from.address !== target.address || from.port !== port) return;
          touch();
          send(DATA, id, data);
        });
        socket.on("error", () => close(id, REASON_NETWORK));
        touch();
      }
      for (const data of pending) stream.write(data);
    }

    ws.on("message", (message, isBinary) => {
      if (!isBinary || message.length < 5) return;
      const type = message[0];
      const id = message.readUInt32LE(1);
      const payload = message.subarray(5);
      switch (type) {
        case CONNECT: {
          if (payload.length < 4 || streams.has(id) || id === 0) return close(id, REASON_INVALID);
          const streamType = payload[0];
          if (streamType !== TCP && streamType !== UDP) {
            send(CLOSE, id, Uint8Array.of(REASON_INVALID));
            return;
          }
          if (streams.size >= MAX_STREAMS) {
            send(CLOSE, id, Uint8Array.of(REASON_BLOCKED));
            return;
          }
          connect(id, streamType, payload.readUInt16LE(1), payload.subarray(3).toString("utf8"));
          break;
        }
        case DATA:
          streams.get(id)?.write(Buffer.from(payload));
          break;
        case CLOSE:
          if (streams.has(id)) {
            streams.get(id).destroy();
            streams.delete(id);
            log(`stream ${id} closed by the client`);
          }
          break;
      }
    });

    ws.on("close", () => {
      for (const stream of streams.values()) stream.destroy();
      streams.clear();
      log(`client ${peer} disconnected`);
    });
    ws.on("error", () => ws.close());

    // The allowance of every new stream.
    send(CONTINUE, 0, u32(ALLOWANCE));
  });

  server.listen(port, host);
  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { values: args } = parseArgs({
    options: {
      host: { type: "string", default: "127.0.0.1" },
      port: { type: "string", default: "8765" },
      token: { type: "string" },
      "allow-private": { type: "boolean", default: false },
      "allow-origin": { type: "string", multiple: true, default: [] },
      verbose: { type: "boolean", default: false },
    },
  });
  const server = startProxy({
    host: args.host,
    port: Number(args.port),
    token: args.token,
    allowPrivate: args["allow-private"],
    allowOrigin: args["allow-origin"],
    verbose: args.verbose,
  });
  server.on("listening", () => {
    const { address, port } = server.address();
    console.log(`ws://${address}:${port}/${args.token ?? ""}` +
      (args["allow-private"] ? " (private addresses allowed)" : ""));
  });
}
