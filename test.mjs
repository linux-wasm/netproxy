// Tests the proxy against local TCP and UDP echo servers, speaking Wisp
// from a client written here.
//   node test.mjs
import assert from "node:assert/strict";
import dgram from "node:dgram";
import net from "node:net";
import WebSocket from "ws";
import { startProxy } from "./server.mjs";

const listening = (server) => new Promise((r) => server.once("listening", r));

const tcpEcho = net.createServer((socket) => socket.pipe(socket)).listen(0, "127.0.0.1");
const udpEcho = dgram.createSocket("udp4");
udpEcho.on("message", (data, from) => udpEcho.send(data, from.port, from.address));
udpEcho.bind(0, "127.0.0.1");
await Promise.all([listening(tcpEcho), listening(udpEcho)]);

function packet(type, id, payload) {
  const out = Buffer.alloc(5 + payload.length);
  out[0] = type;
  out.writeUInt32LE(id, 1);
  Buffer.from(payload).copy(out, 5);
  return out;
}
const connectPayload = (type, port, host) => {
  const out = Buffer.alloc(3 + host.length);
  out[0] = type;
  out.writeUInt16LE(port, 1);
  out.write(host, 3);
  return out;
};

// A client: resolves once the initial CONTINUE is in; collects packets.
async function client(url) {
  const ws = new WebSocket(url);
  const packets = [];
  let wake = () => {};
  ws.on("message", (m) => {
    packets.push({ type: m[0], id: m.readUInt32LE(1), payload: m.subarray(5) });
    wake();
  });
  const next = async (match) => {
    for (;;) {
      const i = packets.findIndex(match);
      if (i >= 0) return packets.splice(i, 1)[0];
      await new Promise((r) => (wake = r));
    }
  };
  await new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
  const first = await next((p) => p.type === 3 && p.id === 0);
  assert.ok(first.payload.readUInt32LE(0) > 0, "initial allowance");
  return { ws, next };
}

async function run(name, options, body) {
  const proxy = startProxy({ port: 0, ...options });
  await listening(proxy);
  const url = `ws://127.0.0.1:${proxy.address().port}/`;
  try {
    await body(url);
    console.log(`ok ${name}`);
  } finally {
    proxy.closeAllConnections?.();
    proxy.close();
  }
}

await run("tcp: data both ways, flow control, close", { allowPrivate: true }, async (url) => {
  const { ws, next } = await client(url);
  ws.send(packet(1, 1, connectPayload(1, tcpEcho.address().port, "127.0.0.1")));
  // More packets than one allowance, so a CONTINUE has to come.
  let sent = 0;
  for (let i = 0; i < 200; i++) {
    ws.send(packet(2, 1, Buffer.alloc(1000, i)));
    sent += 1000;
  }
  let received = 0;
  while (received < sent)
    received += (await next((p) => p.type === 2 && p.id === 1)).payload.length;
  assert.equal(received, sent);
  const more = await next((p) => p.type === 3 && p.id === 1);
  assert.ok(more.payload.readUInt32LE(0) > 0);
  ws.send(packet(4, 1, [2]));
  ws.close();
});

await run("tcp: refused", { allowPrivate: true }, async (url) => {
  const { ws, next } = await client(url);
  const unused = net.createServer().listen(0, "127.0.0.1");
  await listening(unused);
  const port = unused.address().port;
  await new Promise((r) => unused.close(r));
  ws.send(packet(1, 7, connectPayload(1, port, "127.0.0.1")));
  const closed = await next((p) => p.type === 4 && p.id === 7);
  assert.equal(closed.payload[0], 0x44);
  ws.close();
});

await run("udp: datagrams keep their boundaries", { allowPrivate: true }, async (url) => {
  const { ws, next } = await client(url);
  ws.send(packet(1, 2, connectPayload(2, udpEcho.address().port, "127.0.0.1")));
  ws.send(packet(2, 2, "one"));
  ws.send(packet(2, 2, "three"));
  assert.equal((await next((p) => p.type === 2)).payload.toString(), "one");
  assert.equal((await next((p) => p.type === 2)).payload.toString(), "three");
  ws.close();
});

await run("private addresses are blocked by default", {}, async (url) => {
  const { ws, next } = await client(url);
  ws.send(packet(1, 3, connectPayload(1, tcpEcho.address().port, "127.0.0.1")));
  assert.equal((await next((p) => p.type === 4 && p.id === 3)).payload[0], 0x48);
  ws.send(packet(1, 4, connectPayload(1, tcpEcho.address().port, "localhost")));
  assert.equal((await next((p) => p.type === 4 && p.id === 4)).payload[0], 0x48);
  ws.send(packet(1, 5, connectPayload(2, 53, "::ffff:192.168.1.1")));
  assert.equal((await next((p) => p.type === 4 && p.id === 5)).payload[0], 0x48);
  ws.close();
});

await run("a token is required when set", { token: "secret" }, async (url) => {
  await assert.rejects(client(url));
  const { ws } = await client(`${url}secret`);
  ws.close();
});

tcpEcho.close();
udpEcho.close();
