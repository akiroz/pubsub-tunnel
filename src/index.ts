import os from "os";
import { randomBytes } from "crypto";
import LRU from "lru-cache";
import ipInt from "ip-to-int";
import * as pcap from "pcap";

export type PubSubClient = {
    publish(topic: string, payload: Buffer): Promise<void>;
    subscribe(topic: string, handler: (payload: Buffer) => Promise<void>): Promise<void>;
};

const loopbackIp = ipInt("127.0.0.1").toInt();
const linkOffset = os.platform() === "darwin" ? 4 : 14;
const linkHeader = (() => {
    const buf = Buffer.alloc(linkOffset);
    if (os.platform() === "darwin") buf.writeUInt32LE(2);
    else buf.writeUInt16BE(0x800, 12);
    return buf;
})();

function encodeBase64URL(data: Buffer): string {
    return Buffer.from(data).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function nat(packet: Buffer, src: number, dst: number) {
    packet.writeUInt16BE(0, 10); // clear checksum
    packet.writeUInt32BE(src, 12);
    packet.writeUInt32BE(dst, 16);
}

export function server(
    pubsub: PubSubClient,
    opts: {
        topic: string;
        addressStart: string;
        addressRange: number;
        sessionIdleTimeout?: number;
    }
) {
    const ifce = os.platform() === "darwin" ? "lo0" : "lo";
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

    const session = pcap.createSession(ifce, { filter: `ip and not dst host 127.0.0.1` });
    pubsub.subscribe(opts.topic, async (payload) => {
        const id = payload.slice(0, 16);
        const packet = payload.slice(16);
        const idStr = encodeBase64URL(id);
        const ip = idCache[idStr] || allocIp(idStr);
        ipCache.get(ip); // renew age
        nat(packet, ip, loopbackIp);
        session.inject(Buffer.concat([linkHeader, packet]));
    });

    session.on("packet", ({ header, buf }: pcap.PacketWithHeader) => {
        const len = header.readUInt32LE(8);
        const packet = buf.slice(linkOffset, len);
        const idStr = ipCache.get(packet.readUInt32BE(16));
        if (idStr) pubsub.publish(`${opts.topic}/${idStr}`, packet);
    });

    return session;
}

export function client(
    pubsub: PubSubClient,
    opts: {
        topic: string;
        bindAddress: string;
    }
) {
    const ifce = os.platform() === "darwin" ? "lo0" : "lo";
    const id = randomBytes(16);
    const idStr = encodeBase64URL(id);
    const bindIp = ipInt(opts.bindAddress).toInt();

    const session = pcap.createSession(ifce, { filter: `dst host ${opts.bindAddress}` });
    pubsub.subscribe(`${opts.topic}/${idStr}`, async (packet) => {
        nat(packet, bindIp, loopbackIp);
        session.inject(Buffer.concat([linkHeader, packet]));
    });

    session.on("packet", ({ header, buf }: pcap.PacketWithHeader) => {
        const len = header.readUInt32LE(8);
        const packet = buf.slice(linkOffset, len);
        pubsub.publish(opts.topic, Buffer.concat([id, packet]));
    });

    return session;
}
