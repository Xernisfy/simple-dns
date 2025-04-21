import { Buffer } from "node:buffer";
// @ts-types="npm:@types/dns-packet"
import { decode, encode, type Packet } from "npm:dns-packet";

const conn = Deno.listenDatagram({ transport: "udp", port: 53 });
console.log("DNS listening on udp/53");

async function fallback(msg: Uint8Array) {
  console.warn("[WARN] resolved by public DNS");
  const upstream = Deno.listenDatagram({
    transport: "udp",
    hostname: "0.0.0.0",
    port: 0,
  });
  await upstream.send(msg, {
    transport: "udp",
    hostname: "8.8.8.8",
    port: 53,
  });
  const [p] = await upstream.receive();
  upstream.close();
  return p;
}

for await (const [msg, addr] of conn) {
  if (addr.transport !== "udp") continue;
  let query: Packet;
  try {
    query = decode(Buffer.from(msg));
  } catch (error) {
    console.error("[ERR ] malformed packet:", error);
    continue;
  }
  if (!query.questions || !query.questions.length) {
    console.error("[ERR ] no question in packet");
    continue;
  }
  if (query.questions.length > 1) {
    await conn.send(await fallback(msg), addr);
    continue;
  }
  const question = query.questions[0];
  const localRecords: Record<string, string> = Object.fromEntries(
    Deno.readTextFileSync("records.txt").split("\n").map((line) =>
      line.split(/\s+/)
    ),
  );
  if (question.type !== "A" || !(question.name in localRecords)) {
    await conn.send(await fallback(msg), addr);
    continue;
  }
  console.log(`[INFO] resolved "${question.name}" -> ${localRecords[question.name]}`);
  await conn.send(
    encode({
      id: query.id,
      type: "response",
      flags: 0x8000,
      questions: query.questions,
      answers: [{
        name: question.name,
        type: "A",
        class: "IN",
        ttl: 300,
        data: localRecords[question.name],
      }],
    }),
    addr,
  );
}
