import { randomBytes } from "crypto";
import { EventEmitter } from "events";
import LRU from "lru-cache";
import ipInt from "ip-to-int";
import * as pcap from "pcap";
import IPv4 from "pcap/decode/ipv4";
import NullPacket from "pcap/decode/null_packet";

export type PubSubClient = {
    publish(topic: string, payload: Buffer): Promise<void>;
    subscribe(topic: string, handler: (payload: Buffer) => Promise<void>): Promise<void>;
};

function encodeBase64URL(data: Buffer): string {
    return Buffer.from(data).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function nat(packet: Buffer, src: number, dst: number) {
    packet.writeUInt16BE(0, 10); // clear checksum
    packet.writeUInt32BE(src, 12);
    packet.writeUInt32BE(dst, 16);
}

const loopbackIp = ipInt("127.0.0.1").toInt();

export function server(
    pubsub: PubSubClient,
    opts: {
        tunnelTopic: string;
        addressStart: string;
        addressRange: number;
        sessionIdleTimeout?: number;
    }
) {
    const idCache: { [id: string]: number } = {};
    const ipCache = new LRU<number, string>({
        max: opts.addressRange - 1,
        maxAge: opts.sessionIdleTimeout || 2 * 60 * 60 * 1000,
        updateAgeOnGet: true,
        dispose(key, val) {
            delete idCache[val];
        },
    });
    let allocNumber = 0;
    function allocIp(idStr: string): number {
        const startIp = ipInt(opts.addressStart).toInt();
        while (ipCache.has(startIp + allocNumber)) {
            allocNumber += 1;
            allocNumber %= opts.addressRange;
        }
        const newIp = startIp + allocNumber;
        ipCache.set(newIp, idStr);
        idCache[idStr] = newIp;
        return newIp;
    }
    const session = pcap.createSession("lo0", { filter: `not dst host 127.0.0.1` });
    pubSub.subscribe(opts.tunnelTopic, async (payload) => {
        const id = payload.slice(0, 16);
        const packet = payload.slice(16);
        const idStr = encodeBase64URL(id);
        const ip = idCache[idStr] || allocIp(idStr);
        ipCache.get(ip); // renew age
        nat(packet.slice(4), ip, loopbackIp);
        session.inject(packet);
    });
    session.on("packet", ({ header, buf }: { header: Buffer; buf: Buffer }) => {
        const len = header.readUInt32LE(8);
        const packet = buf.slice(0, len);
        const ip = packet.readUInt32BE(4 + 16);
        const idStr = ipCache.get(ip);
        if (idStr) pubSub.publish(`${opts.tunnelTopic}/${idStr}`, buf);
    });
    return session;
}

export function client(pubsub: PubSubClient, opts: { tunnelTopic: string; bindAddress: string }) {
    const id = randomBytes(16);
    const idStr = encodeBase64URL(id);
    const bindIp = ipInt(opts.bindAddress).toInt();
    const session = pcap.createSession("lo0", { filter: `dst host ${opts.bindAddress}` });
    pubSub.subscribe(`${opts.tunnelTopic}/${idStr}`, async (packet) => {
        nat(packet.slice(4), bindIp, loopbackIp);
        console.log(new IPv4().decode(packet, 4));
        session.inject(packet);
    });
    session.on("packet", ({ header, buf }: { header: Buffer; buf: Buffer }) => {
        const len = header.readUInt32LE(8);
        const packet = buf.slice(0, len);
        pubSub.publish(opts.tunnelTopic, Buffer.concat([id, packet]));
    });
    return session;
}

const ee = new EventEmitter();
const pubSub: PubSubClient = {
    async publish(topic, payload) {
        await new Promise((r) => {
            setImmediate(() => (ee.emit(topic, payload), r()));
        });
    },
    async subscribe(topic, handler) {
        ee.on(topic, handler);
    },
};
