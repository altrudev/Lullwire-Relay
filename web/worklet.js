// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

// Audio worklets for calls: capture the microphone in 20 ms blocks (960 samples
// at 48 kHz) for the Opus encoder, and play decoded audio from a small jitter buffer.

class LullwireCapture extends AudioWorkletProcessor {
  constructor() { super(); this.buf = new Float32Array(960); this.n = 0; }
  process(inputs) {
    const ch = inputs[0] && inputs[0][0];
    if (ch) {
      for (let i = 0; i < ch.length; i++) {
        this.buf[this.n++] = ch[i];
        if (this.n === 960) { this.port.postMessage(this.buf.slice(0)); this.n = 0; }
      }
    }
    return true;
  }
}

class LullwirePlayback extends AudioWorkletProcessor {
  constructor() {
    super();
    this.q = []; this.queued = 0; this.cur = null; this.pos = 0; this.playing = false;
    this.port.onmessage = e => {
      this.q.push(e.data); this.queued += e.data.length;
      // Keep latency low: if more than 300 ms piles up, drop the oldest audio.
      while (this.queued > 14400 && this.q.length > 1) this.queued -= this.q.shift().length;
    };
  }
  process(_inputs, outputs) {
    const out = outputs[0];
    const n = out[0].length;
    if (!this.playing && this.queued < 2880) { for (const c of out) c.fill(0); return true; } // 60 ms prebuffer
    this.playing = true;
    for (let i = 0; i < n; i++) {
      if (!this.cur || this.pos >= this.cur.length) {
        this.cur = this.q.shift(); this.pos = 0;
        if (!this.cur) { for (const c of out) c.fill(0, i); this.playing = false; return true; }
        this.queued -= this.cur.length;
      }
      const s = this.cur[this.pos++];
      for (const c of out) c[i] = s;
    }
    return true;
  }
}

registerProcessor('lullwire-capture', LullwireCapture);
registerProcessor('lullwire-playback', LullwirePlayback);
