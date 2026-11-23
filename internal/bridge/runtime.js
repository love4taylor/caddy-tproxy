(() => {
    const endpoint = relayBase + 'api/v1/';
    const sessionEndpoint = relayBase + 'api/v1/session';
    const native = globalThis.TelegramWebProxy;
    const fragment = /^#android=([\w-]{43})$/.exec(location.hash);
    history.replaceState(null, '', location.pathname);

    const frameLimit = 4096;
    const payloadLimit = 1 << 20;
    const queueLimit = 32 << 20;
    const itemLimit = 16384;
    const laneBytes = 8 << 20;
    const laneItems = 1024;
    const lanes = new Map();
    const tombstones = new Set();
    const creation = new AbortController();
    let main, boundary, token, starting, closed;
    let queuedBytes = 0, queuedItems = 0, bufferedBytes = 0;
    const pumping = new Set();
    const bufferedLanes = new Set();
    const websocket = carrierMode.startsWith('websocket');
    const individual = carrierMode.endsWith('-lanes');

    function frameView(buffer, maxBytes) {
        if (!(buffer instanceof ArrayBuffer) || buffer.byteLength < 8 || buffer.byteLength > maxBytes) {
            throw new Error('invalid WEB frame buffer');
        }
        return new DataView(buffer);
    }

    function frameEnd(view, offset) {
        if (view.byteLength - offset < 8) throw new Error('invalid WEB frame batch');
        const size = view.getUint32(offset + 4);
        const end = offset + 8 + size;
        if (size > payloadLimit || end > view.byteLength) throw new Error('invalid WEB frame size');
        return end;
    }

    function validateAppFrames(view) {
        let count = 0;
        for (let offset = 0; offset < view.byteLength; count++) {
            if (count === itemLimit) throw new Error('invalid WEB frame batch');
            const end = frameEnd(view, offset);
            const word = view.getUint32(offset);
            const kind = word >>> 24, id = word & 0xffffff;
            const length = end - offset - 8;
            const valid = id === 0 ? kind === 6 && length <= 64
                : ((kind === 1 || kind === 3) && length === 0) || (kind === 2 && length > 0) ||
                  (kind === 4 && length === 4 && view.getUint32(offset + 8) !== 0);
            if (!valid) throw new Error('invalid app frame');
            offset = end;
        }
        return count;
    }

    function deliver(buffer, lane) {
        const view = frameView(buffer, batchLimit);
        let remoteClose = false;
        for (let offset = 0, count = 0; offset < view.byteLength; count++) {
            if (count === frameLimit) throw new Error('invalid WEB frame batch');
            const end = frameEnd(view, offset);
            const word = view.getUint32(offset);
            const kind = word >>> 24, id = word & 0xffffff;
            if (individual && id !== lane.id) throw new Error('cross-lane downlink');
            const length = end - offset - 8;
            const valid = id === 0
                ? (kind === 5 || kind === 31) && length <= 64
                : (kind === 2 && length > 0) || (kind === 3 && length === 0) ||
                  (kind === 4 && length === 4 && view.getUint32(offset + 8) !== 0);
            if (!valid) throw new Error('invalid relay frame');
            if (individual && kind === 3) remoteClose = true;
            offset = end;
        }
        if (remoteClose) lane.remoteClose = true;
        message({t: 'traffic', up: 0, down: buffer.byteLength});
        sendFrames(buffer, view);
    }

    function message(value) {
        if (boundary) boundary.control(value);
    }

    function sendFrames(buffer, view) {
        if (!boundary) return;
        if (boundary.native) {
            const size = buffer.byteLength;
            if (!view || 8 + view.getUint32(4) === size) {
                native.postMessage(buffer);
                return;
            }
            for (let offset = 0; offset < size;) {
                const end = offset + 8 + view.getUint32(offset + 4);
                native.postMessage(buffer.slice(offset, end));
                offset = end;
            }
        } else {
            boundary.port.postMessage(buffer, [buffer]);
        }
    }

    function request(path, method, authorization, body, extra, signal, keepalive = false) {
        const headers = {Authorization: 'Bearer ' + authorization, ...extra};
        if (body !== undefined) headers['Content-Type'] = 'application/octet-stream';
        return fetch(path === 'session' ? sessionEndpoint : endpoint + path, {
            method, headers, body, signal, keepalive, mode: 'same-origin', credentials: 'omit',
            cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer'
        });
    }

    async function readBatch(response, limit) {
        const coding = response.headers.get('Content-Encoding');
        const declared = !coding || coding === 'identity' ? Number(response.headers.get('Content-Length')) : 0;
        const size = Number.isSafeInteger(declared) && declared > 0 ? declared : 0;
        if (size > limit) {
            if (response.body) response.body.cancel().catch(() => {});
            throw new Error('oversized carrier response');
        }
        if (!response.body) {
            const bytes = await response.arrayBuffer();
            if (bytes.byteLength > limit) throw new Error('oversized carrier response');
            if (size && bytes.byteLength !== size) throw new Error('truncated carrier response');
            return bytes;
        }
        const reader = response.body.getReader();
        let output = null;
        let length = 0;
        try {
            for (;;) {
                const {done, value} = await reader.read();
                if (done) break;
                if (value.byteLength > limit - length || (size && value.byteLength > size - length)) {
                    throw new Error('oversized carrier response');
                }
                const needed = length + value.byteLength;
                const capacity = output ? output.byteLength : 0;
                if (needed > capacity) {
                    if (!output && (!size || needed === size) && value.byteOffset === 0 && needed === value.buffer.byteLength) {
                        // Reuse the first complete buffer. We still wait for
                        // EOF, and any additional bytes require a new buffer.
                        output = value;
                        length = needed;
                        continue;
                    }
                    const grown = new Uint8Array(size || Math.min(limit, Math.max(4096, needed, capacity * 2)));
                    if (output) grown.set(output.subarray(0, length));
                    output = grown;
                }
                if (output) output.set(value, length);
                length = needed;
            }
            if (size && length !== size) throw new Error('truncated carrier response');
            if (!output) return new ArrayBuffer(0);
            return length === output.byteLength ? output.buffer : output.buffer.slice(0, length);
        } catch (error) {
            reader.cancel().catch(() => {});
            throw error;
        } finally {
            reader.releaseLock();
        }
    }

    function delay(ms, signal) {
        return new Promise((resolve, reject) => {
            if (signal.aborted) {
                reject(new Error('carrier stopped'));
                return;
            }
            const timer = setTimeout(() => {
                signal.removeEventListener('abort', cancel);
                resolve();
            }, ms);
            function cancel() {
                clearTimeout(timer);
                reject(new Error('carrier stopped'));
            }
            signal.addEventListener('abort', cancel, {once: true});
        });
    }

    async function exchange(lifetime, path, authorization, body, extra) {
        const deadline = performanceNow() + 90000;
        let failures = 0;
        while (!lifetime.aborted) {
            const left = deadline - performanceNow();
            if (left <= 0) break;
            const pending = new AbortController();
            const cancel = () => pending.abort();
            const timer = setTimeout(cancel, left);
            lifetime.addEventListener('abort', cancel, {once: true});
            let wait;
            try {
                const response = await request(path, 'POST', authorization, body, extra, pending.signal);
                if (response.status !== 503) {
                    if (response.status === 200 && path === 'session') {
                        const issued = response.headers.get('X-Session-Token');
                        if (issued) token = issued;
                        if (closed && token) {
                            removeSession();
                            return {response, entity: null};
                        }
                    }
                    const entity = response.status === 200 ? await readBatch(response, path === 'session' ? 8 : batchLimit) : null;
                    if (response.status !== 200 && response.body) response.body.cancel().catch(() => {});
                    return {response, entity};
                }
                const header = response.headers.get('Retry-After');
                const seconds = Number(header || 1);
                wait = Number.isFinite(seconds) ? Math.max(1000, seconds * 1000) : 1000;
                if (response.body) response.body.cancel().catch(() => {});
            } catch (error) {
                if (lifetime.aborted || ++failures >= 8) throw error;
                wait = Math.min(1000, 50 * 2 ** failures);
            } finally {
                clearTimeout(timer);
                lifetime.removeEventListener('abort', cancel);
            }
            await delay(Math.min(wait, Math.max(0, deadline - performanceNow())), lifetime);
        }
        throw new Error('carrier request expired');
    }

    function performanceNow() {
        return globalThis.performance ? performance.now() : Date.now();
    }

    function newLane(id) {
        return {id, stop: new AbortController(), pending: [], bytes: 0, count: 0,
            browser: 0, prepaid: 0, sequence: 1n, cursor: '0', open: false, sentClose: false};
    }

    function reserveQueue(lane, size, count) {
        updateBuffered(lane);
        if (queuedItems + count > itemLimit ||
            (individual && (lane.bytes + lane.browser + size > laneBytes || lane.count + count > laneItems))) {
            throw new Error('carrier queue full');
        }
        if (queuedBytes + bufferedBytes + size > queueLimit) {
            // A different socket can drain before its next pump runs.
            for (const buffered of bufferedLanes) updateBuffered(buffered);
            if (queuedBytes + bufferedBytes + size > queueLimit) throw new Error('carrier queue full');
        }
        lane.bytes += size;
        lane.count += count;
        queuedBytes += size;
        queuedItems += count;
    }

    function keepBytes(bytes) {
        // Release unrelated frames once their own lanes acknowledge them.
        return bytes.byteLength === bytes.buffer.byteLength ? bytes : bytes.slice();
    }

    function queue(lane, bytes, count) {
        reserveQueue(lane, bytes.byteLength, count);
        lane.pending.push({bytes: keepBytes(bytes), count});
    }

    function queueSplitData(lane, bytes, word) {
        const maxFrames = Math.min(frameLimit, Math.floor(batchLimit / (uplinkDataLimit + 8)));
        const payload = Math.min(bytes.length - 8, maxFrames * uplinkDataLimit);
        const staging = payload + Math.ceil(payload / uplinkDataLimit) * 8;
        // Keep one source frame and reserve space for one encoded batch.
        // A small carrier limit can turn this frame into thousands of pieces.
        const charge = bytes.length + staging;
        reserveQueue(lane, charge, 1);
        lane.pending.push({source: keepBytes(bytes), word, offset: 8, payload, charge});
    }

    function popSplitBatch(lane, entry) {
        const {source, word} = entry;
        let offset = entry.offset;
        const end = Math.min(source.length, offset + entry.payload);
        const size = end - offset;
        const length = size + Math.ceil(size / uplinkDataLimit) * 8;
        const body = new Uint8Array(length);
        const view = new DataView(body.buffer);
        for (let at = 0; offset < end;) {
            const payload = Math.min(uplinkDataLimit, end - offset);
            view.setUint32(at, word);
            view.setUint32(at + 4, payload);
            if (payload < 16) {
                for (let i = 0; i < payload; i++) body[at + 8 + i] = source[offset + i];
            } else {
                body.set(source.subarray(offset, offset + payload), at + 8);
            }
            offset += payload;
            at += 8 + payload;
        }
        entry.offset = end;
        if (end !== source.length) return {body, length, charge: 0, count: 0};
        lane.pending.shift();
        return {body, length, charge: entry.charge, count: 1};
    }

    function release(lane, bytes, items) {
        lane.bytes -= bytes;
        lane.count -= items;
        queuedBytes -= bytes;
        queuedItems -= items;
    }

    function popBatch(lane) {
        if (lane.pending[0].source) return popSplitBatch(lane, lane.pending[0]);
        if (lane.pending.length === 1) {
            const {bytes, count} = lane.pending.pop();
            return {body: bytes, length: bytes.byteLength, charge: bytes.byteLength, count};
        }
        let length = 0, count = 0, entries = 0;
        for (const {bytes, count: frames} of lane.pending) {
            if (!bytes || count + frames > frameLimit || length + bytes.length > batchLimit) break;
            entries++;
            count += frames;
            length += bytes.length;
        }
        if (!count) throw new Error('cannot fit any frame in carrier batch');
        const parts = lane.pending.splice(0, entries);
        if (entries === 1) return {body: parts[0].bytes, length, charge: length, count};
        const body = new Uint8Array(length);
        let at = 0;
        for (const {bytes} of parts) {
            body.set(bytes, at);
            at += bytes.length;
        }
        return {body, length, charge: length, count};
    }

    function laneHeader(lane) {
        return individual ? {'X-Lane-ID': String(lane.id)} : {};
    }

    function counter(value) {
        if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
            (value.length === 20 && value > '18446744073709551615')) throw new Error('invalid carrier counter');
        return value;
    }

    async function upload(lane) {
        if (lane.uploading || lane.stop.signal.aborted) return;
        lane.uploading = true;
        try {
            while (lane.pending.length && !lane.stop.signal.aborted) {
                const batch = popBatch(lane);
                const number = String(lane.sequence);
                const {response} = await exchange(lane.stop.signal, 'up', token, batch.body,
                    {...laneHeader(lane), 'X-Up-Seq': number});
                if (response.status !== 204 || counter(response.headers.get('X-Up-Ack')) !== number) {
                    throw new Error('invalid uplink acknowledgment');
                }
                if (lane.stop.signal.aborted) return;
                release(lane, batch.charge, batch.count);
                lane.sequence++;
                message({t: 'traffic', up: batch.length, down: 0});
                if (individual && lane.id !== 0 && !lane.polling) poll(lane);
            }
        } catch (error) {
            if (!lane.stop.signal.aborted) fail();
        } finally {
            lane.uploading = false;
        }
    }

    async function poll(lane) {
        lane.polling = true;
        try {
            while (!lane.stop.signal.aborted) {
                const {response, entity} = await exchange(lane.stop.signal, 'down', token, undefined,
                    {...laneHeader(lane), 'X-Down-Cursor': lane.cursor});
                if (lane.stop.signal.aborted) return;
                const next = counter(response.headers.get('X-Down-Cursor'));
                if (response.status === 200 && next === String(BigInt(lane.cursor) + 1n)) {
                    deliver(entity, lane);
                    lane.cursor = next;
                } else if (response.status !== 204 || next !== lane.cursor) {
                    throw new Error('invalid downlink cursor');
                }
                if (individual && response.headers.get('X-Lane-Closed') === '1') {
                    retire(lane, !lane.sentClose && !lane.remoteClose);
                    return;
                }
            }
        } catch (error) {
            if (!lane.stop.signal.aborted) fail();
        }
    }

    function updateBuffered(lane, size = lane.socket ? lane.socket.bufferedAmount : 0) {
        // The split frame already reserved these bytes while it is queued.
        if (!size) lane.prepaid = 0;
        size = Math.max(0, size - lane.prepaid);
        if (size === lane.browser) return;
        if (!size) bufferedLanes.delete(lane);
        else if (!lane.browser) bufferedLanes.add(lane);
        bufferedBytes += size - lane.browser;
        lane.browser = size;
    }

    let tick;
    function schedulePump(lane) {
        pumping.add(lane);
        if (tick !== undefined) return;
        tick = setTimeout(() => {
            tick = undefined;
            const ready = Array.from(pumping);
            pumping.clear();
            for (const pending of ready) flush(pending);
        }, 10);
    }

    function flush(lane) {
        // WebSocket.send can discard data once the closing handshake starts.
        if (lane.stop.signal.aborted || !lane.open || lane.socket.readyState !== WebSocket.OPEN) return;
        updateBuffered(lane);
        try {
            // Use available socket capacity before yielding to the next pump.
            for (let sent = 0; sent < 4 && lane.pending.length && lane.browser < batchLimit &&
                (!lane.pending[0].source || !lane.socket.bufferedAmount); sent++) {
                const batch = popBatch(lane);
                const body = batch.body;
                lane.socket.send(body.byteOffset === 0 && body.byteLength === body.buffer.byteLength ? body.buffer : body);
                if (batch.charge === 0) lane.prepaid = batch.length;
                release(lane, batch.charge, batch.count);
                updateBuffered(lane);
                message({t: 'traffic', up: batch.length, down: 0});
            }
            if (lane.pending.length || lane.browser) schedulePump(lane);
        } catch (error) {
            if (individual) retire(lane, !lane.sentClose && !lane.remoteClose);
            else fail();
        }
    }

    function openSocket(lane) {
        const protocol = individual ? 'tproxy-lane-v1.' + token + '.' + lane.id : 'tproxy-v1.' + token;
        const url = new URL('ws', endpoint);
        url.protocol = 'wss:';
        const socket = lane.socket = new WebSocket(url.href, protocol);
        socket.binaryType = 'arraybuffer';
        lane.handshake = setTimeout(() => {
            if (!lane.open && !lane.stop.signal.aborted) fail();
        }, 30000);
        socket.onopen = () => {
            if (lane.stop.signal.aborted) {
                socket.close();
                return;
            }
            clearTimeout(lane.handshake);
            if (socket.protocol !== undefined && socket.protocol !== protocol) {
                fail();
                return;
            }
            lane.open = true;
            message({t: 'status', state: 'connected'});
            flush(lane);
        };
        socket.onmessage = event => {
            if (lane.stop.signal.aborted) return;
            try {
                deliver(event.data, lane);
            } catch (error) {
                fail();
            }
        };
        socket.onclose = () => {
            // close() can leave queued bytes in the browser until the event.
            updateBuffered(lane, 0);
            if (lane.stop.signal.aborted) return;
            if (!individual || !lane.open) fail();
            else retire(lane, !lane.sentClose && !lane.remoteClose);
        };
    }

    function retire(lane, notify) {
        if (!lane || lane.stop.signal.aborted) return;
        lane.stop.abort();
        lanes.delete(lane.id);
        pumping.delete(lane);
        if (lane.id !== 0) {
            tombstones.add(lane.id);
            if (tombstones.size > 4096) tombstones.delete(tombstones.values().next().value);
        }
        if (lane.prepaid) {
            // A closing socket can still hold a batch after its reservation ends.
            lane.prepaid = 0;
            updateBuffered(lane);
        }
        release(lane, lane.bytes, lane.count);
        lane.pending.length = 0;
        if (lane.handshake) clearTimeout(lane.handshake);
        if (lane.socket) {
            try { lane.socket.close(); } catch (error) {}
        }
        if (notify) {
            const buffer = new ArrayBuffer(8);
            new DataView(buffer).setUint32(0, (3 << 24) | lane.id);
            sendFrames(buffer);
        }
    }

    function sendPending(lane) {
        if (lane.stop.signal.aborted) return;
        if (!websocket) upload(lane);
        else if (!lane.socket) openSocket(lane);
        else flush(lane);
    }

    function dispatch(buffer) {
        const view = frameView(buffer, queueLimit);
        // Validate every frame before changing any lane or retaining a view.
        const total = validateAppFrames(view);
        const touched = individual && total > 1 ? new Set() : null;
        for (let offset = 0; offset < view.byteLength;) {
            const start = offset;
            const word = view.getUint32(start);
            const length = view.getUint32(start + 4);
            const kind = word >>> 24, id = word & 0xffffff;
            offset += 8 + length;
            let lane = main;
            if (individual) {
                if (websocket && id === 0) continue;
                lane = lanes.get(id);
                if (!lane) {
                    if (kind !== 1) continue;
                    if (tombstones.has(id) || lanes.size >= 1024) throw new Error('invalid stream allocation');
                    lane = newLane(id);
                    lanes.set(id, lane);
                }
                if (kind === 3) {
                    if (websocket && !lane.open) {
                        retire(lane, false);
                        continue;
                    }
                    lane.sentClose = true;
                }
            }
            if (websocket && lane.open && lane.socket.readyState !== WebSocket.OPEN) continue;
            if (kind === 2 && length > uplinkDataLimit) {
                queueSplitData(lane, new Uint8Array(buffer, start, offset - start), word);
            } else {
                let count = 1;
                // Keep a contiguous span that starts a batch. Existing queued
                // frames can still be packed with new frames individually.
                if (!lane.pending.length) {
                    while (offset < view.byteLength && count < frameLimit) {
                        const next = view.getUint32(offset);
                        const size = view.getUint32(offset + 4);
                        const end = offset + 8 + size;
                        const nextKind = next >>> 24;
                        if ((individual && ((next & 0xffffff) !== id || nextKind === 3)) ||
                            end - start > batchLimit || (nextKind === 2 && size > uplinkDataLimit)) break;
                        offset = end;
                        count++;
                    }
                }
                queue(lane, new Uint8Array(buffer, start, offset - start), count);
            }
            if (touched) touched.add(lane);
            else if (individual) sendPending(lane);
        }
        if (touched) for (const lane of touched) sendPending(lane);
        else if (!individual) sendPending(main);
    }

    async function start(buffer) {
        try {
            const hello = frameView(buffer, 9);
            if (hello.byteLength !== 9 || hello.getUint32(0) !== (16 << 24) ||
                hello.getUint32(4) !== 1 || hello.getUint8(8) !== 1) throw new Error('invalid HELLO');
            // Keep reading session headers after close until we know the token
            // needed for deletion. The WELCOME body can still be interrupted.
            const {response, entity} = await exchange(creation.signal, 'session', bootstrap, buffer, {});
            if (closed) return;
            if (response.status !== 200) throw new Error('session creation refused');
            if (!response.headers.get('X-Session-Token')) throw new Error('no session token');
            const welcome = frameView(entity, 8);
            if (response.headers.get('X-Carrier-Mode') !== carrierMode ||
                welcome.getUint32(0) !== (17 << 24) || welcome.getUint32(4) !== 0) {
                throw new Error('invalid WELCOME');
            }
            main = newLane(0);
            if (individual && !websocket) lanes.set(0, main);
            if (!individual && websocket) openSocket(main);
            if (!websocket) poll(main);
            sendFrames(entity);
            if (!websocket) message({t: 'status', state: 'connected'});
        } catch (error) {
            fail();
        }
    }

    function removeSession() {
        if (creation.signal.aborted) return;
        creation.abort();
        request('session', 'DELETE', token, undefined, {}, undefined, true).catch(() => {});
    }

    function shutdown() {
        if (closed) return;
        closed = true;
        if (tick !== undefined) clearTimeout(tick);
        for (const lane of lanes.values()) retire(lane, false);
        retire(main, false);
        if (token) removeSession();
        if (boundary) boundary.close();
    }

    function fail() {
        if (closed) return;
        try {
            message({t: 'status', state: 'failed'});
            message({t: 'close'});
        } finally {
            shutdown();
        }
    }

    function receive(value) {
        if (closed) return;
        if (value && value.t === 'close') {
            shutdown();
            return;
        }
        if (!(value instanceof ArrayBuffer)) return;
        if (!starting) {
            starting = true;
            start(value);
            return;
        }
        try {
            if (!main) throw new Error('app sent data before WELCOME');
            dispatch(value);
        } catch (error) {
            fail();
        }
    }

    addEventListener('message', event => {
        if (closed || boundary || event.source !== parent || !event.data ||
            Object.keys(event.data).length !== 2 || event.data.t !== 'tproxy-init' || event.data.v !== 1 ||
            event.ports.length !== 1 || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(event.origin)) return;
        let origin;
        try { origin = new URL(event.origin); } catch (error) { return; }
        if (origin.origin !== event.origin) return;
        const port = event.ports[0];
        boundary = {port, control: value => port.postMessage(value), close: () => port.close()};
        port.onmessage = event => receive(event.data);
        port.start();
        message({t: 'status', state: 'connecting'});
    });

    if (fragment && native && typeof native.postMessage === 'function') {
        boundary = {native: true, control: value => native.postMessage(JSON.stringify(value)), close: () => { native.onmessage = null; }};
        native.onmessage = event => {
            let value = event.data;
            if (typeof value === 'string') {
                try { value = JSON.parse(value); } catch (error) { return; }
            }
            receive(value);
        };
        message({t: 'status', state: 'connecting'});
        message({t: 'tproxy-android-init', v: 1, nonce: fragment[1]});
    }
    addEventListener('pagehide', shutdown, {once: true});
})();
