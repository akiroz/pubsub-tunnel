import os from "os";
import { randomBytes } from "crypto";
import LRU from "lru-cache";
import ipInt from "ip-to-int";
import { PacketWithHeader, PcapSession } from "pcap";

export type PubSubClient = {
    publish(topic: string, payload: Buffer): Promise<void>;
    subscribe(topic: string, handler: (payload: Buffer) => Promise<void>): Promise<void>;
};

const localhost = ipInt("127.0.0.1").toInt();

class NetworkDriver {
    platform: NodeJS.Platform;
    closed = false;

    // TUN Driver

    // Pcap Driver
    pcapHeader = Buffer.alloc(4);
    pcapSession: PcapSession;

    static async createSession(): Promise<NetworkDriver> {
        const drv = new NetworkDriver();
        drv.platform = os.platform();
        if (drv.platform === "linux") {
        } else {
            const pcap = require("pcap");
            drv.pcapHeader.writeUInt32LE(2);
            drv.pcapSession = pcap.createSession("lo0", { filter: "ip and not dst host 127.0.0.1" });
        }
        return drv;
    }

    inject(packet: Buffer) {
        if (this.closed) return;
        if (this.platform === "linux") {
        } else {
            this.pcapSession.inject(Buffer.concat([this.pcapHeader, packet]));
        }
    }

    onPacket(handler: (packet: Buffer) => void) {
        if (this.platform === "linux") {
        } else {
            this.pcapSession.on("packet", ({ header, buf }: PacketWithHeader) => {
                const len = header.readUInt32LE(8);
                handler(Buffer.from(buf.slice(4, len)));
            });
        }
    }

    close() {
        this.closed = true;
        if (this.platform === "linux") {
        } else {
            this.pcapSession.close();
        }
    }
}

function encodeBase64URL(data: Buffer): string {
    return Buffer.from(data).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function nat(packet: Buffer, src: number, dst: number) {
    packet.writeUInt16LE(0, 10); // clear checksum
    packet.writeUInt32BE(src, 12);
    packet.writeUInt32BE(dst, 16);
    const len = packet[0] & 0x0F;
    let sum = 0;
    for(let i = 0; i < len*2; i++) sum += packet.readUInt16LE(i*2);
    while(sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    packet.writeUInt16LE(~sum & 0xFFFF, 10);
}

export async function server(
    pubsub: PubSubClient,
    opts: {
        topic: string;
        addressStart: string;
        addressRange: number;
        sessionIdleTimeout?: number;
    }
): Promise<NetworkDriver> {
    const net = await NetworkDriver.createSession();
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

    pubsub.subscribe(opts.topic, async (payload) => {
        const id = payload.slice(0, 16);
        const packet = payload.slice(16);
        const idStr = encodeBase64URL(id);
        const ip = idCache[idStr] || allocIp(idStr);
        ipCache.get(ip); // renew age
        nat(packet, ip, localhost);
        net.inject(packet);
    });

    net.onPacket((packet) => {
        const idStr = ipCache.get(packet.readUInt32BE(16));
        if (idStr) pubsub.publish(`${opts.topic}/${idStr}`, packet);
    });

    return net;
}

export async function client(
    pubsub: PubSubClient,
    opts: {
        topic: string;
        bindAddress: string;
    }
): Promise<NetworkDriver> {
    const net = await NetworkDriver.createSession();
    const id = randomBytes(16);
    const idStr = encodeBase64URL(id);
    const bindIp = ipInt(opts.bindAddress).toInt();

    pubsub.subscribe(`${opts.topic}/${idStr}`, async (packet) => {
        nat(packet, bindIp, localhost);
        net.inject(packet);
    });

    net.onPacket((packet) => {
        if (packet.readUInt32BE(16) === bindIp) {
            pubsub.publish(opts.topic, Buffer.concat([id, packet]));
        }
    });

    return net;
}
