import os from "os";
import { randomBytes } from "crypto";
import LRU from "lru-cache";
import ipInt from "ip-to-int";
import * as pcap from "pcap";

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

function coercePacket(packet: Buffer, link_type: pcap.LinkType): Buffer | null {
    switch (link_type) {
        case "LINKTYPE_ETHERNET": {
            const etherType = packet.readUInt16BE(12);
            if (etherType !== 0x800) {
                console.log(
                    `[pubsub-tunnel] Unsupported EthernetPacket (not IPv4) etherType=${etherType.toString(16)}`
                );
                return null;
            }
            return packet.slice(14);
        }
        case "LINKTYPE_LINUX_SLL": {
            const etherType = packet.readUInt16BE(14);
            if (etherType !== 0x800) {
                console.log(`[pubsub-tunnel] Unsupported SLLPacket (not IPv4) etherType=${etherType.toString(16)}`);
                return null;
            }
            return packet.slice(16);
        }
        case "LINKTYPE_NULL": {
            const pfType = packet[0] === 0 && packet[1] === 0 ? packet[3] : packet[0];
            if (pfType !== 2) {
                console.log(`[pubsub-tunnel] Unsupported NullPacket (not IPv4) pfType=${pfType}`);
                return null;
            }
            return packet.slice(4);
        }
        case "LINKTYPE_RAW": {
            if (packet[0] >> 4 != 4) {
                console.log(`[pubsub-tunnel] Unsupported RawPacket (not IPv4)`);
                return null;
            }
            return packet;
        }
        default: {
            console.log(`[pubsub-tunnel] Unsupported link_type ${link_type}`);
            return null;
        }
    }
}

const loopbackIp = ipInt("127.0.0.1").toInt();

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

    const session = pcap.createSession(ifce, { filter: `not dst host 127.0.0.1` });
    pubsub.subscribe(opts.topic, async (payload) => {
        const id = payload.slice(0, 16);
        const packet = payload.slice(16);
        const idStr = encodeBase64URL(id);
        const ip = idCache[idStr] || allocIp(idStr);
        ipCache.get(ip); // renew age
        nat(packet.slice(4), ip, loopbackIp);
        session.inject(packet);
    });

    session.on("packet", ({ header, buf, link_type }: pcap.PacketWithHeader) => {
        const len = header.readUInt32LE(8);
        const packet = buf.slice(0, len);
        const rawPacket = coercePacket(packet, link_type);
        if (!rawPacket) return;
        const ip = rawPacket.readUInt32BE(16);
        const idStr = ipCache.get(ip);
        if (idStr) pubsub.publish(`${opts.topic}/${idStr}`, rawPacket);
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
        nat(packet.slice(4), bindIp, loopbackIp);
        session.inject(packet);
    });

    session.on("packet", ({ header, buf, link_type }: pcap.PacketWithHeader) => {
        const len = header.readUInt32LE(8);
        const packet = buf.slice(0, len);
        const rawPacket = coercePacket(packet, link_type);
        if (!rawPacket) return;
        pubsub.publish(opts.topic, Buffer.concat([id, rawPacket]));
    });

    return session;
}
