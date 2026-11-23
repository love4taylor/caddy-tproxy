const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const page = fs.readFileSync(0, 'utf8');
const script = page.match(/<script nonce="[^"]+">([\s\S]+)<\/script>/)[1];
const mode = process.argv[2];
const delivery = process.argv[3];
const scenario = process.argv[4];
const context = vm.createContext({mode, delivery, scenario, assert, AbortController, URL, setTimeout, clearTimeout});
vm.runInContext(`
    const calls = [], messages = [], sockets = [];
    const listeners = new Map();
    let largestAllocation = 0, frameViews = 0, retryBuffer, interruptedSplit;
    let finishSessionHeaders, finishWelcome, welcomeRead, sessionAttempts = 0;
    const downCursors = [];
    globalThis.Uint8Array = class extends Uint8Array {
        constructor(value, ...rest) {
            super(value, ...rest);
            if (typeof value === 'number') largestAllocation = Math.max(largestAllocation, value);
            if (value instanceof ArrayBuffer && rest.length === 2) frameViews++;
        }
    };
    const compressedMedia = new Uint8Array(10 << 10).fill(66);
    const location = {hash: delivery === 'native' ? '#android=' + 'a'.repeat(43) : '', pathname: '/relay/'};
    const history = {replaceState(a, b, path) { assert.equal(path, '/relay/'); }};
    const addEventListener = (event, callback) => { listeners.set(event, callback); };
    const nativeBridge = {postMessage(value) { messages.push(value); }};
    if (delivery === 'native') globalThis.TelegramWebProxy = nativeBridge;
    const parent = {};
    const port = {
        start() { this.started = true; },
        close() { this.closed = true; },
        postMessage(value, transfer) {
            if (value instanceof ArrayBuffer) {
                assert.equal(transfer.length, 1);
                assert.equal(transfer[0], value);
            }
            messages.push(value);
        },
    };
    function frame(kind, id, payload = []) {
        const buffer = new ArrayBuffer(8 + payload.length);
        const view = new DataView(buffer);
        view.setUint32(0, (kind << 24) | id);
        view.setUint32(4, payload.length);
        new Uint8Array(buffer, 8).set(payload);
        return buffer;
    }
    function response(status, fields, body, chunks) {
        const headers = {get: key => fields[key] ?? null};
        if (status !== 200) return {status, headers};
        chunks ??= [new Uint8Array(body, 0, 3), new Uint8Array(body, 3)];
        const reader = {
            async read() {
                if (!chunks.length) return {done: true};
                const value = chunks.shift();
                if (value instanceof Error) throw value;
                return {value};
            },
            async cancel() { chunks.length = 0; },
            releaseLock() {}
        };
        return {status, headers, body: {getReader() { return reader; }}};
    }
    const fetch = (url, options) => {
        assert(url.startsWith('https://proxy.example.com/relay/api/v1/'));
        assert.equal(options.mode, 'same-origin');
        assert.equal(options.credentials, 'omit');
        assert.equal(options.redirect, 'error');
        assert.equal(options.cache, 'no-store');
        assert.equal(options.referrerPolicy, 'no-referrer');
        calls.push({url, options});
        if (options.method === 'DELETE') return Promise.resolve(response(204, {}, null));
        if (url.endsWith('/session')) {
            const fields = {'Content-Length': '8', 'X-Session-Token': 'testing', 'X-Carrier-Mode': mode};
            if (scenario === 'session-live-retry' && ++sessionAttempts === 1) {
                return Promise.resolve(response(200, fields, null, [new Error('WELCOME interrupted')]));
            }
            if (scenario?.startsWith('session-close-')) {
                let started = false;
                const held = {status: 200, headers: {get: key => fields[key] ?? null}, body: {getReader: () => ({
                    async read() {
                        if (started) return {done: true};
                        started = welcomeRead = true;
                        return new Promise((resolve, reject) => {
                            finishWelcome = () => resolve({value: new Uint8Array(frame(17, 0))});
                            options.signal.addEventListener('abort', () => reject(new Error('aborted WELCOME')), {once: true});
                        });
                    },
                    async cancel() {},
                    releaseLock() {}
                })}};
                if (scenario === 'session-close-before-headers') {
                    return new Promise(resolve => { finishSessionHeaders = () => resolve(held); });
                }
                return Promise.resolve(held);
            }
            return Promise.resolve(response(200, fields, frame(17, 0)));
        }
        if (url.endsWith('/up')) {
            assert.equal(options.headers['Content-Type'], 'application/octet-stream');
            if (scenario === 'split-data-minimum' && options.headers['X-Up-Seq'] === '2') {
                if (!interruptedSplit) {
                    interruptedSplit = options;
                    return Promise.reject(new Error('split upload interrupted'));
                }
                assert.equal(options.body, interruptedSplit.body);
            }
            return Promise.resolve(response(204, {'X-Up-Ack': options.headers['X-Up-Seq']}, null));
        }
        const lane = options.headers['X-Lane-ID'];
        const cursor = options.headers['X-Down-Cursor'];
        if (scenario?.startsWith('closed-lane')) {
            if (lane === '9') {
                if (scenario === 'closed-lane-after-frame' && cursor === '0') {
                    return Promise.resolve(response(200, {'X-Down-Cursor': '1'}, frame(3, 9)));
                }
                return Promise.resolve(response(204, {'X-Down-Cursor': cursor, 'X-Lane-Closed': '1'}, null));
            }
            if (lane === '10' && cursor === '0') {
                return Promise.resolve(response(200, {'X-Down-Cursor': '1'}, frame(2, 10, [41])));
            }
        }
        if (scenario === 'downlink-retry' && (lane === '9' || lane === undefined)) {
            downCursors.push(cursor);
            if (cursor === '0') {
                const first = downCursors.length === 1;
                const data = frame(2, 9, [first ? 99 : 101]);
                const chunks = [new Uint8Array(data)];
                if (first) chunks.push(new Error('body interrupted'));
                else retryBuffer = data;
                return Promise.resolve(response(200, {'Content-Length': '9', 'X-Down-Cursor': '1'}, null, chunks));
            }
            if (cursor === '1') {
                const storage = new Uint8Array(12).fill(255);
                storage.set(new Uint8Array(frame(2, 9, [102])), 1);
                return Promise.resolve(response(200, {'Content-Encoding': 'gzip', 'X-Down-Cursor': '2'}, null, [storage.subarray(1, 10)]));
            }
        } else if ((lane === '9' || lane === undefined) && cursor === '0') {
            return Promise.resolve(response(200, {'Content-Length': '6', 'Content-Encoding': 'gzip', 'X-Down-Cursor': '1'}, frame(2, 9, compressedMedia)));
        }
        return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')), {once: true}));
    };
    class WebSocket {
        static OPEN = 1;
        static CLOSING = 2;
        static CLOSED = 3;
        constructor(url, protocol) {
            assert.equal(url, 'wss://proxy.example.com/relay/api/v1/ws');
            this.protocol = protocol;
            this.readyState = 0;
            this.bufferedAmount = 0;
            this.sent = [];
            this.discardedSends = 0;
            sockets.push(this);
        }
        send(payload) {
            if (this.readyState !== WebSocket.OPEN) {
                this.discardedSends++;
                this.bufferedAmount += payload.byteLength;
                return;
            }
            if (this.rejectSend) throw new Error('socket send failed');
            this.sent.push(payload);
            if (this.holdSplit && payload.byteLength === 4096 * 12) {
                this.holdSplit = false;
                this.bufferedAmount = payload.byteLength;
            }
        }
        finishOpen() {
            this.readyState = WebSocket.OPEN;
            this.onopen?.();
        }
        close() {
            if (this.readyState >= WebSocket.CLOSING) return;
            this.readyState = WebSocket.CLOSING;
            if (this.deferClose) this.closing = true;
            else this.finishClose();
        }
        finishClose() {
            this.readyState = WebSocket.CLOSED;
            this.closed = true;
            this.onclose?.();
        }
    }
    function send(type, id, payload) {
        (delivery === 'native' ? nativeBridge : port).onmessage({data: frame(type, id, payload)});
    }
    function controlMessage(kind, state) {
        return messages.some(value => {
            if (typeof value === 'string') value = JSON.parse(value);
            return value?.t === kind && value.state === state;
        });
    }
    function gotData(kind, value) {
        return messages.some(message => message instanceof ArrayBuffer && new Uint8Array(message)[0] === kind &&
            (value === undefined || new Uint8Array(message)[8] === value));
    }
    async function until(predicate, attempts = 100) {
        for (let tries = 0; tries < attempts; tries++) {
            if (predicate()) return;
            await new Promise(resolve => setTimeout(resolve, 1));
        }
        assert(predicate(), 'timed out waiting for carrier');
    }
`, context);
vm.runInContext(script, context);
vm.runInContext(`
    (async () => {
        if (delivery === 'native') {
            assert(controlMessage('tproxy-android-init', undefined));
        } else {
            const init = listeners.get('message');
            const valid = {source: parent, origin: 'http://127.0.0.1:29431', data: {t: 'tproxy-init', v: 1}, ports: [port]};
            init({...valid, origin: 'https://proxy.example.com'});
            init({...valid, source: {}});
            assert.equal(!!port.started, false);
            init(valid);
            assert.equal(port.started, true);
            assert(controlMessage('status', 'connecting'));
        }
        send(16, 0, [1]);
        if (scenario?.startsWith('session-close-')) {
            const {options} = calls[0];
            const beforeHeaders = scenario === 'session-close-before-headers';
            try {
                if (!beforeHeaders) await until(() => welcomeRead);
                listeners.get('pagehide')();
                if (beforeHeaders) {
                    assert.equal(options.signal.aborted, false);
                    finishSessionHeaders();
                }
                await until(() => calls.some(call => call.options.method === 'DELETE'));
                assert.equal(options.signal.aborted, true);
                assert.equal(!!welcomeRead, !beforeHeaders);
                assert.equal(calls.length, 2);
                assert.equal(calls[1].options.headers.Authorization, 'Bearer testing');
                assert.equal(calls[1].options.keepalive, true);
                assert(!gotData(17));
                assert(!controlMessage('status', 'failed'));
            } finally {
                finishWelcome?.();
            }
            return;
        }
        await until(() => gotData(17));
        if (scenario === 'invalid-uplink-batch') {
            send(1, 9);
            const uploads = () => calls.filter(({url}) => url.endsWith('/up')).length;
            const socket = sockets[0];
            if (socket) socket.finishOpen();
            else await until(() => uploads() === 1);
            const first = frame(2, 9, [47]);
            const invalid = frame(4, 9, [0, 0, 0, 0]);
            const batch = new Uint8Array(first.byteLength + invalid.byteLength);
            batch.set(new Uint8Array(first));
            batch.set(new Uint8Array(invalid), first.byteLength);
            frameViews = 0;
            port.onmessage({data: batch.buffer});
            assert(controlMessage('status', 'failed'));
            assert.equal(frameViews, 0);
            assert.equal(socket ? socket.sent.length : uploads(), 1);
            assert.equal(calls.filter(call => call.options.method === 'DELETE').length, 1);
            return;
        }
        if (scenario === 'session-live-retry') {
            try {
                const attempts = calls.filter(({url}) => url.endsWith('/session'));
                assert.equal(attempts.length, 2);
                assert.equal(attempts[0].options.body, attempts[1].options.body);
                assert(attempts.every(({options}) => options.method === 'POST' && options.headers.Authorization === 'Bearer bootstrap'));
                assert(!controlMessage('status', 'failed'));
            } finally {
                listeners.get('pagehide')();
            }
            assert.equal(calls.filter(call => call.options.method === 'DELETE').length, 1);
            return;
        }
        if (scenario === 'socket-burst') {
            try {
                send(1, 9);
                for (let i = 1; i <= 7; i++) send(2, 9, new Uint8Array(144 << 10).fill(i));
                const socket = sockets[0];
                socket.finishOpen();
                assert.equal(socket.sent.length, 4, 'the first send pump should make bounded progress');
                await until(() => socket.sent.length === 7);
                for (let i = 0; i < socket.sent.length; i++) {
                    const body = new Uint8Array(socket.sent[i]);
                    const offset = i === 0 ? 8 : 0;
                    assert.equal(body.length, offset + 8 + (144 << 10));
                    assert.equal(new DataView(body.buffer).getUint32(offset), (2 << 24) | 9);
                    assert.deepEqual(body.subarray(offset + 8), new Uint8Array(144 << 10).fill(i + 1));
                }
                assert(!controlMessage('status', 'failed'));
            } finally {
                listeners.get('pagehide')();
            }
            return;
        }
        if (scenario === 'socket-closing') {
            try {
                send(1, 9);
                const socket = sockets[0];
                socket.finishOpen();
                socket.bufferedAmount = 2 << 20;
                send(2, 9, [47]);
                assert.equal(socket.sent.length, 1);
                const messageCount = messages.length;
                // The browser can enter CLOSING before it delivers the close event.
                socket.readyState = WebSocket.CLOSING;
                socket.bufferedAmount = 0;
                await new Promise(resolve => setTimeout(resolve, 30));
                assert.equal(socket.discardedSends, 0);
                assert.equal(messages.length, messageCount);
                if (mode.endsWith('-lanes')) {
                    const data = new Uint8Array(frame(2, 9, [55]));
                    const late = new Uint8Array(1025 * data.byteLength);
                    for (let offset = 0; offset < late.length; offset += data.byteLength) late.set(data, offset);
                    port.onmessage({data: late.buffer});
                    assert(!controlMessage('status', 'failed'));
                    send(1, 10);
                    sockets[1].finishOpen();
                    send(2, 10, [59]);
                    assert.equal(sockets[1].sent.length, 2);
                    socket.finishClose();
                    const closes = messages.filter(value => value instanceof ArrayBuffer &&
                        value.byteLength === 8 && new DataView(value).getUint32(0) === ((3 << 24) | 9));
                    assert.equal(closes.length, 1);
                    assert(!controlMessage('status', 'failed'));
                } else {
                    socket.finishClose();
                    assert(controlMessage('status', 'failed'));
                }
            } finally {
                listeners.get('pagehide')();
            }
            assert.equal(calls.filter(call => call.options.method === 'DELETE').length, 1);
            return;
        }
        if (scenario?.startsWith('split-data')) {
            const payload = Uint8Array.from({length: 600 << 10}, (_, i) => i % 251);
            const expected = [frame(1, 9), frame(2, 9, [123]), frame(2, 9, payload), frame(4, 9, [0, 0, 0, 1])];
            const webSocket = mode.startsWith('websocket');
            const limit = scenario === 'split-data-minimum' ? 4 : delivery === 'native' ? (256 << 10) - 8 : 32 << 10;
            const splitCount = Math.ceil(payload.length / limit);
            const wireSize = expected.reduce((size, data) => size + data.byteLength, 0) + (splitCount - 1) * 8;
            const batches = () => webSocket ? sockets[0]?.sent ?? [] :
                calls.filter(({url, options}) => url.endsWith('/up') && options !== interruptedSplit).map(({options}) => options.body);
            try {
                if (delivery === 'native') {
                    for (const data of expected) nativeBridge.onmessage({data});
                } else {
                    const input = new Uint8Array(expected.reduce((size, data) => size + data.byteLength, 0));
                    let at = 0;
                    for (const data of expected) {
                        input.set(new Uint8Array(data), at);
                        at += data.byteLength;
                    }
                    port.onmessage({data: input.buffer});
                }
                if (webSocket) {
                    const socket = sockets[0];
                    socket.holdSplit = scenario === 'split-data-minimum';
                    socket.finishOpen();
                    if (scenario === 'split-data-minimum') {
                        await until(() => socket.bufferedAmount === 4096 * 12);
                        const held = socket.sent.length;
                        await new Promise(resolve => setTimeout(resolve, 30));
                        assert.equal(socket.sent.length, held);
                        socket.bufferedAmount = 0;
                    }
                }
                await until(() => batches().reduce((size, batch) => size + batch.byteLength, 0) >= wireSize, 1000);
                const kinds = [], received = new Uint8Array(payload.length + 1);
                let written = 0;
                for (const batch of batches()) {
                    const bytes = new Uint8Array(batch);
                    assert(bytes.byteLength <= 256 << 10);
                    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
                    let count = 0;
                    for (let at = 0; at < bytes.length;) {
                        assert(++count <= 4096);
                        const word = view.getUint32(at);
                        const size = view.getUint32(at + 4);
                        const kind = word >>> 24;
                        assert.equal(word & 0xffffff, 9);
                        assert(at + 8 + size <= bytes.length);
                        kinds.push(kind);
                        if (kind === 2) {
                            assert(size > 0 && size <= limit);
                            received.set(bytes.subarray(at + 8, at + 8 + size), written);
                            written += size;
                        }
                        if (kind === 4) assert.equal(view.getUint32(at + 8), 1);
                        at += 8 + size;
                    }
                }
                assert.deepEqual(kinds, [1, 2, ...Array(splitCount).fill(2), 4]);
                assert.equal(written, received.length);
                assert.equal(received[0], 123);
                assert.deepEqual(received.subarray(1), payload);
                if (!webSocket && scenario === 'split-data-minimum') assert(interruptedSplit);
                assert(!controlMessage('status', 'failed'));
            } finally {
                listeners.get('pagehide')();
            }
            return;
        }
        if (scenario === 'downlink-retry') {
            send(1, 9);
            try {
                await until(() => downCursors.includes('2'), 1000);
                assert.deepEqual(downCursors, ['0', '0', '1', '2']);
                const data = messages.filter(value => value instanceof ArrayBuffer && new Uint8Array(value)[0] === 2);
                assert.equal(data.length, 2);
                assert.equal(data[0], retryBuffer);
                assert.deepEqual(data[1], frame(2, 9, [102]));
                assert(!controlMessage('status', 'failed'));
            } finally {
                listeners.get('pagehide')();
            }
            assert.equal(calls.filter(call => call.options.method === 'DELETE').length, 1);
            return;
        }
        if (scenario?.startsWith('closed-lane')) {
            try {
                send(1, 9);
                send(1, 10);
                await until(() => gotData(2, 41) && gotData(3));
                const closes = messages.filter(value => value instanceof ArrayBuffer && new DataView(value).getUint32(0) === ((3 << 24) | 9));
                assert.equal(closes.length, 1);
                assert(!controlMessage('status', 'failed'));
            } finally {
                listeners.get('pagehide')();
            }
            return;
        }
        if (scenario) {
            try {
                // Leave 256 bytes in the session-wide budget across 16 sockets.
                for (let id = 1; id <= 16; id++) {
                    send(1, id);
                    const socket = sockets.at(-1);
                    socket.finishOpen();
                    socket.bufferedAmount = (2 << 20) - 16;
                    send(2, id, [42]);
                }
                const first = sockets[0];
                if (scenario === 'drained') first.bufferedAmount = 0;
                else {
                    first.deferClose = true;
                    first.rejectSend = true;
                    send(2, 1, [21]);
                    assert(first.closing);
                    if (scenario === 'closed') first.finishClose();
                }
                assert(!controlMessage('status', 'failed'));
                const other = sockets[1];
                const payload = new Uint8Array(512);
                send(2, 2, payload);
                assert.equal(controlMessage('status', 'failed'), scenario === 'closing');
                if (scenario !== 'closing') assert.equal(other.sent.at(-1).byteLength, payload.byteLength + 8);
            } finally {
                listeners.get('pagehide')();
            }
            assert.equal(calls.filter(call => call.options.method === 'DELETE').length, 1);
            return;
        }
        send(1, 9);
        send(2, 9, [7]);
        if (mode.startsWith('websocket')) {
            assert.equal(sockets.length, 1);
            assert.equal(sockets[0].protocol, mode.endsWith('-lanes') ? 'tproxy-lane-v1.testing.9' : 'tproxy-v1.testing');
            sockets[0].finishOpen();
            assert.equal(sockets[0].sent.length, 1);
            assert.equal(new Uint8Array(sockets[0].sent[0])[0], 1);
            sockets[0].onmessage({data: frame(2, 9, [66])});
            const first = frame(2, 9, [71]);
            const second = frame(2, 9, [89, 90]);
            const batch = new Uint8Array(first.byteLength + second.byteLength);
            batch.set(new Uint8Array(first));
            batch.set(new Uint8Array(second), first.byteLength);
            frameViews = 0;
            const before = messages.length;
            sockets[0].onmessage({data: batch.buffer});
            assert.equal(frameViews, 0);
            const data = messages.slice(before).filter(value => value instanceof ArrayBuffer);
            if (delivery === 'native') {
                assert.deepEqual(data, [first, second]);
            } else {
                assert.equal(data.length, 1);
                assert.equal(data[0], batch.buffer);
            }
        } else {
            await until(() => calls.filter(({url}) => url.endsWith('/up')).length === 2);
            const uploads = calls.filter(({url}) => url.endsWith('/up')).map(call => call.options.headers);
            assert.deepEqual(uploads.map(headers => headers['X-Up-Seq']), ['1', '2']);
            assert.deepEqual(uploads.map(headers => headers['X-Lane-ID']), mode.endsWith('-lanes') ? ['9', '9'] : [undefined, undefined]);
        }
        await until(() => gotData(2, 66));
        if (!mode.startsWith('websocket')) {
            const received = messages.find(message => message instanceof ArrayBuffer && new Uint8Array(message)[0] === 2);
            assert.equal(received.byteLength, compressedMedia.length + 8);
            assert.equal(new Uint8Array(received).at(-1), 66);
            assert(largestAllocation <= 32 << 10, 'small compressed batch allocated a full carrier buffer');
        }
        if (delivery === 'loopback') {
            const payload = new Uint8Array(64 << 10);
            const frameSize = 8 + payload.length;
            const aggregate = new Uint8Array(8 * frameSize);
            for (let i = 0; i < 8; i++) {
                payload[0] = i;
                aggregate.set(new Uint8Array(frame(2, 9, payload)), i * frameSize);
            }
            frameViews = 0;
            port.onmessage({data: aggregate.buffer});
            assert.equal(frameViews, 1);
            if (mode.startsWith('websocket')) {
                assert.equal(sockets[0].sent.at(-1), aggregate.buffer);
            } else {
                await until(() => calls.some(({options}) => options.headers?.['X-Up-Seq'] === '3'));
                const {body} = calls.find(({options}) => options.headers?.['X-Up-Seq'] === '3').options;
                assert.equal(body.buffer, aggregate.buffer);
                assert.equal(body.byteLength, aggregate.byteLength);
            }
            if (mode.endsWith('-lanes')) {
                const first = [frame(2, 9, [1]), frame(2, 9, [2])];
                const second = [frame(1, 10), frame(2, 10, [3])];
                const spans = [...first, ...second];
                const mixed = new Uint8Array(spans.reduce((total, part) => total + part.byteLength, 0));
                let offset = 0;
                for (const part of spans) {
                    mixed.set(new Uint8Array(part), offset);
                    offset += part.byteLength;
                }
                frameViews = 0;
                port.onmessage({data: mixed.buffer});
                assert.equal(frameViews, 2);
                let firstBody, secondBody;
                if (mode.startsWith('websocket')) {
                    sockets[1].finishOpen();
                    firstBody = new Uint8Array(sockets[0].sent.at(-1));
                    secondBody = new Uint8Array(sockets[1].sent.at(-1));
                } else {
                    const mixedUpload = (id, sequence) => calls.find(({options}) =>
                        options.headers?.['X-Lane-ID'] === id && options.headers['X-Up-Seq'] === sequence);
                    await until(() => mixedUpload('9', '4') && mixedUpload('10', '1'));
                    firstBody = mixedUpload('9', '4').options.body;
                    secondBody = mixedUpload('10', '1').options.body;
                }
                assert.notEqual(firstBody.buffer, mixed.buffer);
                assert.notEqual(secondBody.buffer, mixed.buffer);
                const boundary = first[0].byteLength + first[1].byteLength;
                assert.deepEqual(firstBody, mixed.subarray(0, boundary));
                assert.deepEqual(secondBody, mixed.subarray(boundary));
            }
        }
        if (mode === 'websocket-lanes') {
            let tail;
            const chunk = new Uint8Array(12 << 10);
            for (let id = 100; id < 3600; id++) {
                send(1, id);
                send(2, id, chunk);
                tail = sockets.at(-1);
                send(3, id);
                assert(tail.closed);
                assert.equal(tail.sent.length, 0);
            }
            tail.onopen?.();
            assert.equal(tail.sent.length, 0);
            const total = sockets.length;
            send(2, 3599, [91]);
            assert.equal(sockets.length, total);
            send(1, 3600);
            sockets.at(-1).finishOpen();
            assert.equal(sockets.at(-1).sent.length, 1);
        }
        assert(!controlMessage('status', 'failed'));
        if (mode.startsWith('websocket')) {
            const byteLimit = delivery === 'native' && mode.endsWith('-lanes');
            const wrongShape = delivery === 'native' && !byteLimit;
            const count = byteLimit || wrongShape ? 2 : 4097;
            const size = byteLimit ? 1 << 20 : 1;
            const stride = 8 + size;
            const buffer = new ArrayBuffer(count * stride);
            const view = new DataView(buffer);
            for (let i = 0; i < count; i++) {
                view.setUint32(i * stride, (2 << 24) | 9);
                view.setUint32(i * stride + 4, size);
            }
            if (wrongShape) view.setUint32(stride, 2 << 24);
            frameViews = 0;
            const firstMessage = messages.length;
            sockets[0].onmessage({data: buffer});
            assert(controlMessage('status', 'failed'));
            assert(!messages.slice(firstMessage).some(value => value instanceof ArrayBuffer));
            assert.equal(frameViews, 0);
        }
        listeners.get('pagehide')();
        if (delivery === 'loopback') assert.equal(port.closed, true);
        assert.equal(calls.filter(call => call.options.method === 'DELETE').length, 1);
    })();
`, context).catch(error => { console.error(error); process.exitCode = 1; });
