'use strict';
// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

/* Encrypted calls over the relay's WebSocket.
 *
 * Both phones connect to the caller's relay and meet in a room. Media is encoded
 * in the browser (Opus audio, VP8 video via WebCodecs) and every frame is
 * encrypted with AES-256-GCM before it leaves the device:
 *
 *   key_dir = HKDF(callKey, "hush/call/v1/" + sender role)     callKey: 32 random bytes,
 *   packet  = type(1) | seq(8) | AES-GCM(key_dir, iv = 0^4|seq,  sent inside the chat's
 *             aad = type|seq, ts(8) | flags(1) | payload)       Double Ratchet
 *
 * The relay forwards opaque packets. seq strictly increases per direction, so
 * replayed or reordered packets are dropped and an IV is never reused.
 */
(function () {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const T_AUDIO = 1, T_VIDEO = 2, T_CTRL = 3;
  const W = 640, H = 360, FPS = 15;

  function b64d(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  }
  async function dirKey(raw, role) {
    const k = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('hush/call/v1/' + role) },
      k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  function header(type, seq) {
    const h = new Uint8Array(9); h[0] = type; new DataView(h.buffer).setBigUint64(1, seq); return h;
  }
  function iv(seq) { const v = new Uint8Array(12); new DataView(v.buffer).setBigUint64(4, seq); return v; }

  class LullwireCall {
    static supported() {
      return typeof WebSocket !== 'undefined' && 'AudioEncoder' in self && 'AudioDecoder' in self &&
        'VideoEncoder' in self && 'VideoDecoder' in self && !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
    }

    // o: { url, room, key, role: 'caller'|'callee', secret, video, canvas, localVideo, onState(state, info) }
    constructor(o) {
      this.o = o; this.state = 'new'; this.sendSeq = 0n; this.recvSeq = -1n;
      this.chainOut = Promise.resolve(); this.chainIn = Promise.resolve();
      this.muted = false; this.camOff = !o.video; this.forceKey = true; this.gotKey = false; this.frameNo = 0;
      this.stats = { sentAudio: 0, sentVideo: 0, recvAudio: 0, recvVideo: 0, drawn: 0, dropped: 0, bad: 0 };
    }

    set(state, info) { if (this.state === 'ended') return; this.state = state; this.o.onState && this.o.onState(state, info); }

    async start() {
      const raw = b64d(this.o.key);
      if (raw.length !== 32) throw new Error('bad call key');
      const other = this.o.role === 'caller' ? 'callee' : 'caller';
      [this.kSend, this.kRecv] = await Promise.all([dirKey(raw, this.o.role), dirKey(raw, other)]);
      const audio = { echoCancellation: true, noiseSuppression: true, autoGainControl: true, channelCount: 1 };
      // The call can end (hang-up, the other side cancels) while we wait for the camera
      // or the audio engine. Check after each wait, and never leave the camera running.
      const ended = () => {
        if (this.state !== 'ended') return false;
        if (this.media) this.media.getTracks().forEach(t => t.stop());
        try { this.ctx && this.ctx.close(); } catch {}
        return true;
      };
      const grab = async c => {
        const m = await navigator.mediaDevices.getUserMedia(c);
        if (this.state === 'ended') { m.getTracks().forEach(t => t.stop()); throw new Error('ended'); }
        return m;
      };
      try {
        this.media = await grab({ audio, video: this.o.video ? { width: W, height: H, frameRate: FPS } : false });
      } catch (e) {
        if (ended()) return;
        if (!this.o.video) throw new Error('Microphone permission is needed for calls');
        try { this.media = await grab({ audio }); } catch (e2) { if (ended()) return; throw e2; } // camera refused: carry on with voice
        this.camOff = true;
      }
      if (ended()) return;
      if (this.o.localVideo && this.media.getVideoTracks().length) {
        this.o.localVideo.srcObject = this.media; this.o.localVideo.hidden = false;
        try { await this.o.localVideo.play(); } catch {}
      }
      try { await this.setupAudio(); } catch (e) { if (ended()) return; throw e; }
      if (ended()) return;
      this.connect();
    }

    connect() {
      this.set('connecting');
      const ws = this.ws = new WebSocket(this.o.url);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => {
        const hello = this.o.role === 'caller' ? { op: 'open', room: this.o.room, s: this.o.secret } : { op: 'join', room: this.o.room };
        ws.send(JSON.stringify(hello));
      };
      ws.onmessage = ev => {
        if (typeof ev.data === 'string') return this.onControl(JSON.parse(ev.data));
        const data = new Uint8Array(ev.data);
        this.chainIn = this.chainIn.then(() => this.onPacket(data)).catch(() => { this.stats.bad++; });
      };
      ws.onclose = () => { if (this.state !== 'ended') this.end('lost'); };
    }

    onControl(m) {
      if (m.op === 'error') return this.end('error', m.msg);
      if (m.op === 'ready') return m.peer ? this.peerHere() : this.set('waiting');
      if (m.op === 'peer') return m.here ? this.peerHere() : this.end('hangup');
    }

    peerHere() {
      if (this.state === 'live') return;
      this.set('live');
      this.forceKey = true;
      this.sendCtrl({ k: 'kf' }); // ask the other side for a keyframe straight away
      this.sendCtrl({ k: 'av', a: !this.muted, v: !this.camOff });
      this.startVideo();
    }

    // ---- crypto + transport ----
    send(type, payload, ts, flags) {
      if (!this.ws || this.ws.readyState !== 1) return;
      this.chainOut = this.chainOut.then(async () => {
        const seq = this.sendSeq++;
        const hdr = header(type, seq);
        const pt = new Uint8Array(9 + payload.length);
        const dv = new DataView(pt.buffer);
        dv.setFloat64(0, ts || 0); pt[8] = flags || 0; pt.set(payload, 9);
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv(seq), additionalData: hdr }, this.kSend, pt));
        const pkt = new Uint8Array(9 + ct.length); pkt.set(hdr); pkt.set(ct, 9);
        if (this.ws && this.ws.readyState === 1) this.ws.send(pkt);
      }).catch(() => {});
    }
    sendCtrl(obj) { this.send(T_CTRL, enc.encode(JSON.stringify(obj)), 0, 0); }

    async onPacket(data) {
      if (data.length < 9 + 16 + 9) return;
      const hdr = data.subarray(0, 9);
      const type = data[0], seq = new DataView(data.buffer, data.byteOffset).getBigUint64(1);
      if (seq <= this.recvSeq) { this.stats.bad++; return; } // replayed or out of order
      let pt;
      try { pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv(seq), additionalData: hdr }, this.kRecv, data.subarray(9))); }
      catch { this.stats.bad++; return; }
      this.recvSeq = seq;
      const ts = new DataView(pt.buffer).getFloat64(0), flags = pt[8], payload = pt.subarray(9);
      if (type === T_AUDIO) {
        this.stats.recvAudio++;
        if (this.aDec && this.aDec.state === 'configured') this.aDec.decode(new EncodedAudioChunk({ type: 'key', timestamp: ts, data: payload }));
      } else if (type === T_VIDEO) {
        this.stats.recvVideo++;
        const key = (flags & 1) === 1;
        if (!this.gotKey && !key) return;
        this.ensureVideoDecoder();
        if (key) this.gotKey = true;
        try { this.vDec.decode(new EncodedVideoChunk({ type: key ? 'key' : 'delta', timestamp: ts, data: payload })); }
        catch { this.gotKey = false; this.sendCtrl({ k: 'kf' }); }
      } else if (type === T_CTRL) {
        let m; try { m = JSON.parse(dec.decode(payload)); } catch { return; }
        if (m.k === 'kf') this.forceKey = true;
        else if (m.k === 'bye') this.end('hangup');
        else if (m.k === 'av') this.o.onState && this.o.onState('remote-av', { audio: !!m.a, video: !!m.v });
      }
    }

    // ---- audio ----
    async setupAudio() {
      const ctx = this.ctx = new AudioContext({ sampleRate: 48000, latencyHint: 'interactive' });
      // Without a working sound device the audio engine never starts; say so instead of hanging.
      let timer;
      await Promise.race([ctx.audioWorklet.addModule('worklet.js'),
        new Promise((_, bad) => { timer = setTimeout(() => bad(new Error('Sound is not available on this device')), 8000); })])
        .finally(() => clearTimeout(timer));
      const src = ctx.createMediaStreamSource(this.media);
      const cap = new AudioWorkletNode(ctx, 'lullwire-capture', { numberOfInputs: 1, numberOfOutputs: 0, channelCount: 1, channelCountMode: 'explicit' });
      src.connect(cap);
      this.aEnc = new AudioEncoder({
        output: chunk => {
          if (this.state !== 'live' || this.muted) return;
          if (this.ws && this.ws.bufferedAmount > 2e6) { this.stats.dropped++; return; }
          const b = new Uint8Array(chunk.byteLength); chunk.copyTo(b);
          this.stats.sentAudio++;
          this.send(T_AUDIO, b, chunk.timestamp, 0);
        },
        error: () => {}
      });
      this.aEnc.configure({ codec: 'opus', sampleRate: 48000, numberOfChannels: 1, bitrate: 32000 });
      let t = 0;
      cap.port.onmessage = e => {
        if (this.state !== 'live' || this.aEnc.state !== 'configured') { t += 20000; return; }
        const data = new AudioData({ format: 'f32-planar', sampleRate: 48000, numberOfFrames: 960, numberOfChannels: 1, timestamp: t, data: e.data });
        t += 20000;
        this.aEnc.encode(data); data.close();
      };
      // Playback: decoder -> jitter-buffer worklet -> speakers.
      this.play = new AudioWorkletNode(ctx, 'lullwire-playback', { numberOfInputs: 0, numberOfOutputs: 1, outputChannelCount: [2] });
      await this.routePlayback();
      this.aDec = new AudioDecoder({
        output: a => {
          const f = new Float32Array(a.numberOfFrames);
          a.copyTo(f, { planeIndex: 0, format: 'f32-planar' }); a.close();
          this.play.port.postMessage(f, [f.buffer]);
        },
        error: () => {}
      });
      this.aDec.configure({ codec: 'opus', sampleRate: 48000, numberOfChannels: 1 });
      if (ctx.state === 'suspended') { try { await ctx.resume(); } catch {} }
    }

    // Browsers cancel echo only for audio they recognise as call audio, so the
    // decoded voice is passed through a local (on-device) WebRTC loopback into an
    // <audio> element. No network is involved. Falls back to direct output.
    async routePlayback() {
      try {
        if (typeof RTCPeerConnection === 'undefined') throw 0;
        const dest = this.ctx.createMediaStreamDestination();
        this.play.connect(dest);
        const a = new RTCPeerConnection({ iceServers: [] }), b = new RTCPeerConnection({ iceServers: [] });
        a.onicecandidate = e => e.candidate && b.addIceCandidate(e.candidate).catch(() => {});
        b.onicecandidate = e => e.candidate && a.addIceCandidate(e.candidate).catch(() => {});
        const got = new Promise((res, rej) => { b.ontrack = e => res(e.streams[0] || new MediaStream([e.track])); setTimeout(() => rej(0), 4000); });
        dest.stream.getTracks().forEach(tr => a.addTrack(tr, dest.stream));
        await a.setLocalDescription(await a.createOffer()); await b.setRemoteDescription(a.localDescription);
        await b.setLocalDescription(await b.createAnswer()); await a.setRemoteDescription(b.localDescription);
        const stream = await got;
        this.loop = [a, b];
        this.audioEl = new Audio(); this.audioEl.autoplay = true; this.audioEl.srcObject = stream;
        await this.audioEl.play().catch(() => {});
      } catch {
        if (this.loop) this.loop.forEach(p => p.close());
        this.loop = null;
        try { this.play.disconnect(); } catch {}
        this.play.connect(this.ctx.destination);
      }
    }

    // ---- video ----
    startVideo() {
      if (this.vTimer || !this.media.getVideoTracks().length) return;
      this.vEnc = new VideoEncoder({
        output: (chunk) => {
          const b = new Uint8Array(chunk.byteLength); chunk.copyTo(b);
          this.stats.sentVideo++;
          this.send(T_VIDEO, b, chunk.timestamp, chunk.type === 'key' ? 1 : 0);
        },
        error: () => { this.forceKey = true; }
      });
      this.vEnc.configure({ codec: 'vp8', width: W, height: H, bitrate: 600000, framerate: FPS, latencyMode: 'realtime' });
      const cv = typeof OffscreenCanvas !== 'undefined' ? new OffscreenCanvas(W, H) : Object.assign(document.createElement('canvas'), { width: W, height: H });
      const g = cv.getContext('2d');
      const v = this.o.localVideo;
      this.vTimer = setInterval(() => {
        if (this.state !== 'live' || this.camOff || !v || !v.videoWidth || this.vEnc.state !== 'configured') return;
        // Congestion: skip frames while the connection drains, then restart with a keyframe.
        if (this.ws.bufferedAmount > 400000 || this.vEnc.encodeQueueSize > 2) { this.stats.dropped++; this.forceKey = true; return; }
        g.drawImage(v, 0, 0, W, H);
        const frame = new VideoFrame(cv, { timestamp: performance.now() * 1000 });
        const key = this.forceKey || this.frameNo % (FPS * 3) === 0;
        this.forceKey = false; this.frameNo++;
        this.vEnc.encode(frame, { keyFrame: key }); frame.close();
      }, 1000 / FPS);
    }

    ensureVideoDecoder() {
      if (this.vDec) return;
      const c = this.o.canvas, g = c.getContext('2d');
      this.vDec = new VideoDecoder({
        output: f => {
          if (c.width !== f.displayWidth || c.height !== f.displayHeight) { c.width = f.displayWidth; c.height = f.displayHeight; }
          g.drawImage(f, 0, 0); f.close();
          if (this.stats.drawn++ === 0) this.o.onState && this.o.onState('video');
        },
        error: () => { this.gotKey = false; this.vDec = null; this.sendCtrl({ k: 'kf' }); }
      });
      this.vDec.configure({ codec: 'vp8', optimizeForLatency: true });
    }

    // ---- controls ----
    setMuted(m) { this.muted = m; this.media && this.media.getAudioTracks().forEach(t => { t.enabled = !m; }); this.sendCtrl({ k: 'av', a: !m, v: !this.camOff }); }
    setCamera(on) {
      if (!this.media.getVideoTracks().length) return false;
      this.camOff = !on; this.media.getVideoTracks().forEach(t => { t.enabled = on; });
      if (on) { this.forceKey = true; this.startVideo(); }
      this.sendCtrl({ k: 'av', a: !this.muted, v: on });
      return true;
    }
    hangup() { this.sendCtrl({ k: 'bye' }); setTimeout(() => this.end('local'), 150); }

    end(reason, detail) {
      if (this.state === 'ended') return;
      const prev = this.state;
      this.state = 'ended';
      clearInterval(this.vTimer);
      for (const x of [this.aEnc, this.aDec, this.vEnc, this.vDec]) { try { x && x.state !== 'closed' && x.close(); } catch {} }
      try { this.ws && this.ws.close(); } catch {}
      if (this.media) this.media.getTracks().forEach(t => t.stop());
      if (this.o.localVideo) { this.o.localVideo.srcObject = null; this.o.localVideo.hidden = true; }
      if (this.loop) this.loop.forEach(p => p.close());
      if (this.audioEl) this.audioEl.srcObject = null;
      try { this.ctx && this.ctx.close(); } catch {}
      this.o.onState && this.o.onState('ended', { reason, detail, wasLive: prev === 'live' });
    }
  }

  self.LullwireCall = LullwireCall;
})();
