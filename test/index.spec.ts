import { EventEmitter } from "events";
import { strict as assert } from "assert";
import { PubSubClient, server, client } from "../src/index";
import * as ping from "net-ping";
import http from "server";
import axios from "axios";
import { platform } from "os";

const ee = new EventEmitter();
const pubsub: PubSubClient = {
    async publish(topic, payload) {
        await new Promise((r) => setImmediate(() => (ee.emit(topic, payload), r())));
    },
    async subscribe(topic, handler) {
        ee.on(topic, handler);
    },
};

let baseIp: string;

if (platform() === "darwin") {
    baseIp = "127.0.0";
    server(pubsub, { topic: "tunnel", cidrBlock: "127.0.1.1/24" });
    client(pubsub, { topic: "tunnel", bindAddress: "127.0.0.2" });
    client(pubsub, { topic: "tunnel", bindAddress: "127.0.0.3" });
    client(pubsub, { topic: "tunnel", bindAddress: "127.0.0.4" });
} else {
    baseIp = "10.240.0";
    server(pubsub, { topic: "tunnel", cidrBlock: "10.240.1.2/24", localAddress: "10.240.1.1" });
    client(pubsub, { topic: "tunnel", bindAddress: "10.240.0.3", localAddress: "10.240.0.2" });
    client(pubsub, { topic: "tunnel", bindAddress: "10.240.0.5", localAddress: "10.240.0.4" });
    //client(pubsub, { topic: "tunnel", bindAddress: "10.240.0.7", localAddress: "10.240.0.6" });
}

describe("Tunnel", function () {
    it("wait for tunnel", async () => {
        await new Promise((r) => setTimeout(r, 2500));
    }).timeout(3000);

    it("ping", async () => {
        const session = ping.createSession();
        const target = await new Promise((rsov, rjct) => {
            session.pingHost(baseIp + ".3", (err, target) => {
                if (err) rjct(err);
                rsov(target);
            });
        });
        assert.equal(target, baseIp + ".3");
        session.close();
    });

    it("http get", async () => {
        const s = await http({ port: 3000, security: false }, [http.router.get("/test", () => "ok")]);
        const { data: getData } = await axios.get(`http://${baseIp}.5:3000/test`);
        assert.equal(getData, "ok");
    });

    it("http post", async () => {
        const s = await http({ port: 3001, security: false }, [http.router.post("/echo", (ctx) => ctx.data)]);
        const { data: postData } = await axios.post(`http://${baseIp}.7:3001/echo`, { foo: "foo" });
        assert.equal(postData.foo, "foo");
    });
});

after(() => {
    setTimeout(() => process.exit(0), 100);
});
