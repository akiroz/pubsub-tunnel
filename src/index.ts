import { promisify } from "util";
import { execFile } from "child_process";
import { platform } from "os";
import { promises as fs, ReadStream, WriteStream, createReadStream, createWriteStream } from "fs";
import { randomBytes } from "crypto";
import LRU from "lru-cache";
import { PacketWithHeader, PcapSession } from "pcap";
import { cidr as CIDR, ip as IP } from "node-cidr";

export type PubSubClient = {
    publish(topic: string, payload: Uint8Array | Buffer): Promise<void>;
    subscribe(topic: string, handler: (payload: Uint8Array | Buffer) => Promise<void>): Promise<void>;
};

class NetworkDriver {
    platform: NodeJS.Platform;
    closed = false;

    // TUN Driver
    tunName: string;
    tunFd: fs.FileHandle;
    tunReadStream: ReadStream;
    tunWriteStream: WriteStream;

    // Pcap Driver
    pcapHeader = Buffer.alloc(4);
    pcapSession: PcapSession;

    static async createSession(opts: {
        localAddress?: string;
        cidrBlock?: string;
        mtu?: number;
    }): Promise<NetworkDriver> {
        const drv = new NetworkDriver();
        drv.platform = platform();
        if (drv.platform === "linux") {
            const ioctl = require("ioctl-napi");
            drv.tunFd = await fs.open("/dev/net/tun", "r+");
            drv.tunReadStream = createReadStream(null, { fd: drv.tunFd.fd });
            drv.tunWriteStream = createWriteStream(null, { fd: drv.tunFd.fd });

            // Use ioctl system call to create TUN device
            const IFF_TUN = 0x1;
            const IFF_NO_PI = 0x1000;
            const TUNSETIFF = 0x400454ca;
            const ifr = Buffer.alloc(18);
            ifr.writeUInt16LE(IFF_TUN | IFF_NO_PI, 16);
            ioctl(drv.tunFd.fd, TUNSETIFF, ifr);

            const nameEnd = [...ifr].indexOf(0);
            drv.tunName = ifr.toString("ascii", 0, nameEnd);
            const prefix = CIDR.mask(opts.cidrBlock);
            await promisify(execFile)("ip", [
                "link",
                "set",
                drv.tunName,
                "up",
                "multicast",
                "off",
                "mtu",
                `${opts.mtu || 1500}`,
            ]);
            await promisify(execFile)("ip", ["addr", "add", `${opts.localAddress}/${prefix}`, "dev", drv.tunName]);
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
            this.tunReadStream.on("data", (packet: Buffer) => {
                if (packet[0] >> 4 === 4) {
                    handler(packet);
                }
            });
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

function checksum(buf: Buffer): number {
    if (buf.length % 2 !== 0) buf = Buffer.concat([buf, Buffer.alloc(1)]);
    let sum = 0;
    for (let i = 0; i < buf.length / 2; i++) {
        sum += buf.readUInt16BE(i * 2);
    }
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return sum ^ 0xffff;
}

function nat(packet: Buffer, src: number, dst: number) {
    packet.writeUInt16LE(0, 10); // Clear checksum
    packet.writeUInt32BE(src, 12);
    packet.writeUInt32BE(dst, 16);

    // Compute IP Checksum (Linux will verify)
    const ihl = packet[0] & 0x0f;
    const payloadOffset = ihl * 4;
    packet.writeUInt16BE(checksum(packet.slice(0, payloadOffset)), 10);

    function constructPseudoHeader() {
        const pseudoHeader = Buffer.alloc(12);
        pseudoHeader.writeUInt32BE(src, 0);
        pseudoHeader.writeUInt32BE(dst, 4);
        pseudoHeader.writeUInt8(packet[9], 9);
        pseudoHeader.writeUInt16BE(packet.length - payloadOffset, 10);
        return pseudoHeader;
    }

    // Protocol Handling
    switch (packet[9]) {
        case 6: // TCP
        case 17: // UDP
            const pseudoHeader = constructPseudoHeader();
            const cksumOffset = payloadOffset + (packet[9] === 6 ? 16 : 6);
            packet.writeUInt16BE(0, cksumOffset);
            const cksum = checksum(Buffer.concat([pseudoHeader, packet.slice(payloadOffset)]));
            packet.writeUInt16BE(cksum, cksumOffset);
            break;
        default:
        // No special handling
    }
}

export async function server(
    pubsub: PubSubClient,
    opts: {
        topic: string;
        cidrBlock: string;
        localAddress?: string;
        sessionIdleTimeout?: number;
        mtu?: number;
    }
): Promise<NetworkDriver> {
    const localIp = IP.toInt(platform() === "darwin" ? "127.0.0.1" : opts.localAddress);
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

    await pubsub.subscribe(opts.topic, async (payload) => {
        if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);
        const id = (payload as Buffer).slice(0, 16);
        const packet = (payload as Buffer).slice(16);
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
        mtu?: number;
    }
): Promise<NetworkDriver> {
    const net = await NetworkDriver.createSession({
        localAddress: opts.localAddress,
        cidrBlock: `${opts.bindAddress}/31`,
    });
    const id = randomBytes(16);
    const idStr = encodeBase64URL(id);
    const bindIp = IP.toInt(opts.bindAddress);
    const localIp = IP.toInt(platform() === "darwin" ? "127.0.0.1" : opts.localAddress);

    pubsub.subscribe(`${opts.topic}/${idStr}`, async (packet) => {
        if (!Buffer.isBuffer(packet)) packet = Buffer.from(packet);
        nat(packet as Buffer, bindIp, localIp);
        net.inject(packet as Buffer);
    });

    net.onPacket((packet) => {
        if (packet.readUInt32BE(16) === bindIp) {
            pubsub.publish(opts.topic, Buffer.concat([id, packet]));
        }
    });

    return net;
}
