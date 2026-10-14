// Tiny reverse proxy for the demo console behind a forwarding proxy that rewrites Host (GitHub
// Codespaces forwards https://<codespace>-3000.app.github.dev to localhost:3000 with Host and
// X-Forwarded-Host set to localhost:3000). The console's CSRF check compares the browser's Origin
// with X-Forwarded-Proto/-Host, so this sets both to the public origin and streams everything
// else through unchanged (SSE included). Started by ops/demo/console.sh; no dependencies.
//
//   SIBYL_PUBLIC_ORIGIN=https://x-3000.app.github.dev PROXY_PORT=3000 TARGET_PORT=3001 \
//     node ops/demo/origin-proxy.mjs
import http from "node:http";

const origin = new URL(process.env.SIBYL_PUBLIC_ORIGIN ?? "");
const listenPort = Number(process.env.PROXY_PORT ?? 3000);
const targetPort = Number(process.env.TARGET_PORT ?? 3001);
const proto = origin.protocol.replace(":", "");

const server = http.createServer((req, res) => {
  const headers = { ...req.headers, "x-forwarded-host": origin.host, "x-forwarded-proto": proto };
  const upstream = http.request(
    { host: "127.0.0.1", port: targetPort, method: req.method, path: req.url, headers },
    (reply) => {
      res.writeHead(reply.statusCode ?? 502, reply.headers);
      reply.pipe(res);
    },
  );
  upstream.on("error", () => {
    if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
    res.end("console is starting; reload in a few seconds\n");
  });
  req.pipe(upstream);
});

server.listen(listenPort, "0.0.0.0", () => {
  process.stdout.write(`origin-proxy: :${listenPort} -> :${targetPort} as ${origin.origin}\n`);
});
