import { EventEmitter } from "events";
import { PubSubClient, server, client } from "../src/index";

const ee = new EventEmitter();
const pubsub: PubSubClient = {
    async publish(topic, payload) {
        await new Promise((r) => setImmediate(() => (ee.emit(topic, payload), r())));
    },
    async subscribe(topic, handler) {
        ee.on(topic, handler);
    },
};
server(pubsub, { topic: "tunnel", cidrBlock: "10.200.1.2/24", localAddress: "10.200.1.1" });
client(pubsub, { topic: "tunnel", bindAddress: "10.200.0.2", localAddress: "10.200.0.1" });
