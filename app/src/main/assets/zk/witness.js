// witness_calculator.js is a CommonJS module: it assigns its builder to module.exports.
var module = { exports: {} };

(function () {
  "use strict";
  var bridge = window.AgeWitnessBridge;
  var CHUNK_BYTES = 768 * 1024;
  var SLICE_BYTES = 32768;

  function report(stage, error) {
    var name = error && error.name ? error.name : "Error";
    var message = error && error.message ? error.message : String(error);
    bridge.fail(stage, name, message);
  }

  function toBase64(bytes) {
    var parts = [];
    for (var i = 0; i < bytes.length; i += SLICE_BYTES) {
      parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + SLICE_BYTES)));
    }
    return btoa(parts.join(""));
  }

  function toHex(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return out;
  }

  async function sha256Hex(bytes) {
    if (!window.crypto || !window.crypto.subtle) return "";
    return toHex(new Uint8Array(await window.crypto.subtle.digest("SHA-256", bytes)));
  }

  async function run() {
    var stage = "reading the inputs";
    try {
      var input = JSON.parse(bridge.input());
      var started = performance.now();
      stage = "loading age_proof.wasm";
      var response = await fetch("age_proof.wasm");
      if (!response.ok) throw new Error("age_proof.wasm answered HTTP " + response.status);
      var code = await response.arrayBuffer();
      stage = "compiling age_proof.wasm";
      bridge.progress(stage);
      var calculator = await module.exports(code);
      var loaded = performance.now();
      stage = "calculating the witness";
      bridge.progress(stage);
      var witness = await calculator.calculateWTNSBin(input, 0);
      var computed = performance.now();
      stage = "hashing the witness";
      var digest = await sha256Hex(witness);
      stage = "transferring the witness";
      var chunks = Math.ceil(witness.length / CHUNK_BYTES);
      bridge.begin(witness.length, chunks, digest);
      for (var i = 0; i < chunks; i++) {
        bridge.chunk(i, toBase64(witness.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES)));
      }
      bridge.end(loaded - started, computed - loaded);
    } catch (error) {
      report(stage, error);
    }
  }

  window.addEventListener("load", function () { run(); });
})();
