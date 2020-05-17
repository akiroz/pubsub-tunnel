import { EventEmitter } from "events";
import { strict as assert } from "assert";
import { PubSubClient, server, client } from "../src/index";
import * as ping from "net-ping";
import http from "server";
import axios from "axios";

const ee = new EventEmitter();
const pubsub: PubSubClient = {
    async publish(topic, payload) {
        await new Promise((r) => setImmediate(() => (ee.emit(topic, payload), r())));
    },
    async subscribe(topic, handler) {
        ee.on(topic, handler);
    },
};
server(pubsub, { topic: "tunnel", addressStart: "127.0.1.1", addressRange: 10, interface: "lo" });
client(pubsub, { topic: "tunnel", bindAddress: "127.0.0.2", interface: "lo" });
client(pubsub, { topic: "tunnel", bindAddress: "127.0.0.3", interface: "lo" });
client(pubsub, { topic: "tunnel", bindAddress: "127.0.0.4", interface: "lo" });

describe("Tunnel", function () {
    it("wait for tunnel", async () => {
        await new Promise((r) => setTimeout(r, 2000));
    }).timeout(3000);

    it("ping", async () => {
        const session = ping.createSession();
        const target = await new Promise((rsov, rjct) => {
            session.pingHost("127.0.0.2", (err, target) => {
                if (err) rjct(err);
                rsov(target);
            });
        });
        assert.equal(target, "127.0.0.2");
        session.close();
    });

    it("http get", async () => {
        const s = await http({ port: 3000, security: false }, [http.router.get("/test", () => "ok")]);
        const { data: getData } = await axios.get("http://127.0.0.3:3000/test");
        assert.equal(getData, "ok");
    });

    it("http post", async () => {
        const s = await http({ port: 3001, security: false }, [http.router.post("/echo", (ctx) => ctx.data)]);
        const { data: postData } = await axios.post("http://127.0.0.4:3001/echo", { foo: "foo" });
        assert.equal(postData.foo, "foo");
    });
});

after(() => {
    setTimeout(() => process.exit(0), 100);
});
