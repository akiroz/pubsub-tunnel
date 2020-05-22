import os from "os";
import { promises as fs, ReadStream, WriteStream, createReadStream, createWriteStream } from "fs";
import { randomBytes } from "crypto";
import LRU from "lru-cache";
import { PacketWithHeader, PcapSession } from "pcap";
import { cidr as CIDR, ip as IP } from "node-cidr";

export type PubSubClient = {
    publish(topic: string, payload: Buffer): Promise<void>;
    subscribe(topic: string, handler: (payload: Buffer) => Promise<void>): Promise<void>;
};

class NetworkDriver {
    platform: NodeJS.Platform;
    closed = false;

    // TUN Driver
    tun = {
        AF_INET: 2,
        // flags
        IFF_TUN: 1,
        IFF_NO_PI: 0x1000,
        IFF_UP: 1,
        // calls
        TUNSETIFF: 0x400454ca,
        SIOCSIFADDR: 0x8916,
        SIOCSIFNETMASK: 0x891c,
        SIOCSIFMTU: 0x8922,
        SIOCSIFFLAGS: 0x8914,
    };
    tunName: string;
    tunFd: fs.FileHandle;
    tunReadStream: ReadStream;
    tunWriteStream: WriteStream;

    // Pcap Driver
    pcapHeader = Buffer.alloc(4);
    pcapSession: PcapSession;

    static async createSession(opts: { localAddress?: string; cidrBlock?: string }): Promise<NetworkDriver> {
        const drv = new NetworkDriver();
        drv.platform = os.platform();
        if (drv.platform === "linux") {
            const ioctl = require("ioctl-napi");
            drv.tunFd = await fs.open("/dev/net/tun", "r+");
            drv.tunReadStream = createReadStream(null, { fd: drv.tunFd.fd });
            drv.tunWriteStream = createWriteStream(null, { fd: drv.tunFd.fd });

            const ifr = Buffer.alloc(18);
            const { TUNSETIFF, IFF_TUN, IFF_NO_PI } = drv.tun;
            ifr.writeUInt16LE(IFF_TUN | IFF_NO_PI, 16);
            ioctl(drv.tunFd.fd, TUNSETIFF, ifr);
            const nameEnd = [...ifr].indexOf(0);
            drv.tunName = ifr.toString("ascii", 0, nameEnd);

            const sockaddr = Buffer.alloc(32);
            const { AF_INET, SIOCSIFADDR, SIOCSIFNETMASK } = drv.tun;
            sockaddr.write(drv.tunName);
            sockaddr.writeUInt16LE(AF_INET, 16);
            sockaddr.writeUInt32BE(IP.toInt(opts.localAddress), 18);
            ioctl(drv.tunFd.fd, SIOCSIFADDR, sockaddr);
            sockaddr.writeUInt32BE(IP.toInt(CIDR.netmask(opts.cidrBlock)), 2);
            //ioctl(drv.tunFd.fd, SIOCSIFNETMASK, Buffer.concat([drv.tunName, sockaddr]));

            const { SIOCSIFMTU } = drv.tun;
            const mtu = Buffer.alloc(4);
            mtu.writeUInt32LE(65535);
            //ioctl(drv.tunFd.fd, SIOCSIFMTU, Buffer.concat([drv.tunName, mtu]));

            const { SIOCSIFFLAGS, IFF_UP } = drv.tun;
            const flags = Buffer.alloc(2);
            mtu.writeUInt16LE(IFF_UP);
            //ioctl(drv.tunFd.fd, SIOCSIFFLAGS, Buffer.concat([drv.tunName, flags]));
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
            this.tunWriteStream.write(packet);
        } else {
            this.pcapSession.inject(Buffer.concat([this.pcapHeader, packet]));
        }
    }

    onPacket(handler: (packet: Buffer) => void) {
        if (this.platform === "linux") {
            this.tunReadStream.on("data", (packet: Buffer) => handler(packet));
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
            this.tunWriteStream.close();
            this.tunReadStream.close();
            this.tunFd.close();
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
    const len = packet[0] & 0x0f;
    let sum = 0;
    for (let i = 0; i < len * 2; i++) sum += packet.readUInt16LE(i * 2);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    packet.writeUInt16LE(~sum & 0xffff, 10);
}

export async function server(
    pubsub: PubSubClient,
    opts: {
        topic: string;
        cidrBlock: string;
        localAddress?: string;
        sessionIdleTimeout?: number;
    }
): Promise<NetworkDriver> {
    const localIp = IP.toInt(os.platform() === "darwin" ? "127.0.0.1" : opts.localAddress);
    const startIp = IP.toInt(CIDR.address(opts.cidrBlock));
    const numIps = IP.toInt(CIDR.max(opts.cidrBlock)) - startIp;
    const net = await NetworkDriver.createSession(opts);
    const idCache: { [id: string]: number } = {};
    const ipCache = new LRU<number, string>({
        max: numIps,
        maxAge: opts.sessionIdleTimeout || 2 * 60 * 60 * 1000,
        updateAgeOnGet: true,
        dispose(key, val) {
            delete idCache[val];
        },
    });

    let allocNumber = 0;
    function allocIp(idStr: string): number {
        while (ipCache.has(startIp + allocNumber)) {
            allocNumber += 1;
            allocNumber %= numIps;
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
        nat(packet, ip, localIp);
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
        localAddress?: string;
    }
): Promise<NetworkDriver> {
    const net = await NetworkDriver.createSession({
        localAddress: opts.bindAddress,
        cidrBlock: "0.0.0.0/32",
    });
    const id = randomBytes(16);
    const idStr = encodeBase64URL(id);
    const bindIp = IP.toInt(opts.bindAddress);
    const localIp = IP.toInt(os.platform() === "darwin" ? "127.0.0.1" : opts.localAddress);

    pubsub.subscribe(`${opts.topic}/${idStr}`, async (packet) => {
        nat(packet, bindIp, localIp);
        net.inject(packet);
    });

    net.onPacket((packet) => {
        if (packet.readUInt32BE(16) === bindIp) {
            pubsub.publish(opts.topic, Buffer.concat([id, packet]));
        }
    });

    return net;
}
