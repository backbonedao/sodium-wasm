"use strict";
Object.defineProperty(exports, "__esModule", {
    value: true
});
function _export(target, all) {
    for(var name in all)Object.defineProperty(target, name, {
        enumerable: true,
        get: all[name]
    });
}
_export(exports, {
    crypto_aead_chacha20poly1305_encrypt: ()=>crypto_aead_chacha20poly1305_encrypt,
    crypto_aead_chacha20poly1305_decrypt: ()=>crypto_aead_chacha20poly1305_decrypt,
    crypto_aead_chacha20poly1305_encrypt_detached: ()=>crypto_aead_chacha20poly1305_encrypt_detached,
    crypto_aead_chacha20poly1305_decrypt_detached: ()=>crypto_aead_chacha20poly1305_decrypt_detached,
    crypto_aead_chacha20poly1305_keygen: ()=>crypto_aead_chacha20poly1305_keygen,
    crypto_aead_chacha20poly1305_ietf_encrypt: ()=>crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_decrypt: ()=>crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_chacha20poly1305_ietf_encrypt_detached: ()=>crypto_aead_chacha20poly1305_ietf_encrypt_detached,
    crypto_aead_chacha20poly1305_ietf_decrypt_detached: ()=>crypto_aead_chacha20poly1305_ietf_decrypt_detached,
    crypto_aead_chacha20poly1305_ietf_keygen: ()=>crypto_aead_chacha20poly1305_ietf_keygen,
    crypto_aead_xchacha20poly1305_ietf_encrypt: ()=>crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt: ()=>crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached: ()=>crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
    crypto_aead_xchacha20poly1305_ietf_decrypt_detached: ()=>crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
    crypto_aead_xchacha20poly1305_ietf_keygen: ()=>crypto_aead_xchacha20poly1305_ietf_keygen,
    crypto_auth: ()=>crypto_auth,
    crypto_auth_verify: ()=>crypto_auth_verify,
    crypto_auth_keygen: ()=>crypto_auth_keygen,
    crypto_box_keypair: ()=>crypto_box_keypair,
    crypto_box_seed_keypair: ()=>crypto_box_seed_keypair,
    crypto_box_easy: ()=>crypto_box_easy,
    crypto_box_open_easy: ()=>crypto_box_open_easy,
    crypto_box_detached: ()=>crypto_box_detached,
    crypto_box_open_detached: ()=>crypto_box_open_detached,
    crypto_core_ed25519_is_valid_point: ()=>crypto_core_ed25519_is_valid_point,
    crypto_core_ed25519_random: ()=>crypto_core_ed25519_random,
    crypto_core_ed25519_from_uniform: ()=>crypto_core_ed25519_from_uniform,
    crypto_core_ed25519_add: ()=>crypto_core_ed25519_add,
    crypto_core_ed25519_sub: ()=>crypto_core_ed25519_sub,
    crypto_core_ed25519_scalar_random: ()=>crypto_core_ed25519_scalar_random,
    crypto_core_ed25519_scalar_reduce: ()=>crypto_core_ed25519_scalar_reduce,
    crypto_core_ed25519_scalar_invert: ()=>crypto_core_ed25519_scalar_invert,
    crypto_core_ed25519_scalar_negate: ()=>crypto_core_ed25519_scalar_negate,
    crypto_core_ed25519_scalar_complement: ()=>crypto_core_ed25519_scalar_complement,
    crypto_core_ed25519_scalar_add: ()=>crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_sub: ()=>crypto_core_ed25519_scalar_sub,
    crypto_core_ed25519_scalar_mul: ()=>crypto_core_ed25519_scalar_mul,
    crypto_generichash_STATEBYTES: ()=>crypto_generichash_STATEBYTES,
    crypto_generichash: ()=>crypto_generichash,
    crypto_generichash_init: ()=>crypto_generichash_init,
    crypto_generichash_update: ()=>crypto_generichash_update,
    crypto_generichash_final: ()=>crypto_generichash_final,
    crypto_generichash_keygen: ()=>crypto_generichash_keygen,
    crypto_hash: ()=>crypto_hash,
    crypto_hash_sha256_STATEBYTES: ()=>crypto_hash_sha256_STATEBYTES,
    crypto_hash_sha256: ()=>crypto_hash_sha256,
    crypto_hash_sha256_init: ()=>crypto_hash_sha256_init,
    crypto_hash_sha256_update: ()=>crypto_hash_sha256_update,
    crypto_hash_sha256_final: ()=>crypto_hash_sha256_final,
    crypto_hash_sha512_STATEBYTES: ()=>crypto_hash_sha512_STATEBYTES,
    crypto_hash_sha512: ()=>crypto_hash_sha512,
    crypto_hash_sha512_init: ()=>crypto_hash_sha512_init,
    crypto_hash_sha512_update: ()=>crypto_hash_sha512_update,
    crypto_hash_sha512_final: ()=>crypto_hash_sha512_final,
    crypto_kdf_keygen: ()=>crypto_kdf_keygen,
    crypto_kdf_derive_from_key: ()=>crypto_kdf_derive_from_key,
    crypto_kx_keypair: ()=>crypto_kx_keypair,
    crypto_kx_seed_keypair: ()=>crypto_kx_seed_keypair,
    crypto_kx_client_session_keys: ()=>crypto_kx_client_session_keys,
    crypto_kx_server_session_keys: ()=>crypto_kx_server_session_keys,
    crypto_onetimeauth_STATEBYTES: ()=>crypto_onetimeauth_STATEBYTES,
    crypto_onetimeauth: ()=>crypto_onetimeauth,
    crypto_onetimeauth_verify: ()=>crypto_onetimeauth_verify,
    crypto_onetimeauth_init: ()=>crypto_onetimeauth_init,
    crypto_onetimeauth_update: ()=>crypto_onetimeauth_update,
    crypto_onetimeauth_final: ()=>crypto_onetimeauth_final,
    crypto_onetimeauth_keygen: ()=>crypto_onetimeauth_keygen,
    crypto_pwhash_ALG_ARGON2I13: ()=>crypto_pwhash_ALG_ARGON2I13,
    crypto_pwhash_ALG_ARGON2ID13: ()=>crypto_pwhash_ALG_ARGON2ID13,
    crypto_pwhash: ()=>crypto_pwhash,
    crypto_pwhash_str: ()=>crypto_pwhash_str,
    crypto_pwhash_str_verify: ()=>crypto_pwhash_str_verify,
    crypto_pwhash_str_needs_rehash: ()=>crypto_pwhash_str_needs_rehash,
    crypto_pwhash_scryptsalsa208sha256: ()=>crypto_pwhash_scryptsalsa208sha256,
    crypto_pwhash_scryptsalsa208sha256_str: ()=>crypto_pwhash_scryptsalsa208sha256_str,
    crypto_pwhash_scryptsalsa208sha256_str_verify: ()=>crypto_pwhash_scryptsalsa208sha256_str_verify,
    crypto_pwhash_scryptsalsa208sha256_str_needs_rehash: ()=>crypto_pwhash_scryptsalsa208sha256_str_needs_rehash,
    crypto_scalarmult_base: ()=>crypto_scalarmult_base,
    crypto_scalarmult: ()=>crypto_scalarmult,
    crypto_scalarmult_ed25519: ()=>crypto_scalarmult_ed25519,
    crypto_scalarmult_ed25519_base: ()=>crypto_scalarmult_ed25519_base,
    crypto_scalarmult_ed25519_noclamp: ()=>crypto_scalarmult_ed25519_noclamp,
    crypto_scalarmult_ed25519_base_noclamp: ()=>crypto_scalarmult_ed25519_base_noclamp,
    crypto_secretbox_easy: ()=>crypto_secretbox_easy,
    crypto_secretbox_open_easy: ()=>crypto_secretbox_open_easy,
    crypto_secretbox_detached: ()=>crypto_secretbox_detached,
    crypto_secretbox_open_detached: ()=>crypto_secretbox_open_detached,
    crypto_secretbox_keygen: ()=>crypto_secretbox_keygen,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: ()=>crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_TAG_PUSH: ()=>crypto_secretstream_xchacha20poly1305_TAG_PUSH,
    crypto_secretstream_xchacha20poly1305_TAG_REKEY: ()=>crypto_secretstream_xchacha20poly1305_TAG_REKEY,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL: ()=>crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_keygen: ()=>crypto_secretstream_xchacha20poly1305_keygen,
    crypto_secretstream_xchacha20poly1305_STATEBYTES: ()=>crypto_secretstream_xchacha20poly1305_STATEBYTES,
    crypto_secretstream_xchacha20poly1305_init_push: ()=>crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_push: ()=>crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_init_pull: ()=>crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_pull: ()=>crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_rekey: ()=>crypto_secretstream_xchacha20poly1305_rekey,
    crypto_shorthash_keygen: ()=>crypto_shorthash_keygen,
    crypto_shorthash: ()=>crypto_shorthash,
    crypto_shorthash_siphashx24: ()=>crypto_shorthash_siphashx24,
    crypto_sign_STATEBYTES: ()=>crypto_sign_STATEBYTES,
    crypto_sign_keypair: ()=>crypto_sign_keypair,
    crypto_sign_seed_keypair: ()=>crypto_sign_seed_keypair,
    crypto_sign: ()=>crypto_sign,
    crypto_sign_open: ()=>crypto_sign_open,
    crypto_sign_detached: ()=>crypto_sign_detached,
    crypto_sign_verify_detached: ()=>crypto_sign_verify_detached,
    crypto_sign_ed25519_sk_to_pk: ()=>crypto_sign_ed25519_sk_to_pk,
    crypto_sign_ed25519_pk_to_curve25519: ()=>crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519: ()=>crypto_sign_ed25519_sk_to_curve25519,
    crypto_stream_chacha20: ()=>crypto_stream_chacha20,
    crypto_stream_chacha20_xor: ()=>crypto_stream_chacha20_xor,
    crypto_stream_chacha20_xor_ic: ()=>crypto_stream_chacha20_xor_ic,
    crypto_stream_chacha20_ietf: ()=>crypto_stream_chacha20_ietf,
    crypto_stream_chacha20_ietf_xor: ()=>crypto_stream_chacha20_ietf_xor,
    crypto_stream_chacha20_ietf_xor_ic: ()=>crypto_stream_chacha20_ietf_xor_ic,
    crypto_stream_xchacha20: ()=>crypto_stream_xchacha20,
    crypto_stream_xchacha20_xor: ()=>crypto_stream_xchacha20_xor,
    crypto_stream_xchacha20_xor_ic: ()=>crypto_stream_xchacha20_xor_ic,
    crypto_stream_salsa20: ()=>crypto_stream_salsa20,
    crypto_stream_salsa20_xor: ()=>crypto_stream_salsa20_xor,
    crypto_stream_salsa20_xor_ic: ()=>crypto_stream_salsa20_xor_ic,
    randombytes_random: ()=>randombytes_random,
    randombytes_uniform: ()=>randombytes_uniform,
    randombytes_buf: ()=>randombytes_buf,
    randombytes_buf_deterministic: ()=>randombytes_buf_deterministic,
    sodium_memcmp: ()=>sodium_memcmp,
    sodium_increment: ()=>sodium_increment,
    sodium_add: ()=>sodium_add,
    sodium_sub: ()=>sodium_sub,
    sodium_compare: ()=>sodium_compare,
    sodium_is_zero: ()=>sodium_is_zero,
    sodium_pad: ()=>sodium_pad,
    sodium_unpad: ()=>sodium_unpad,
    crypto_box_seal: ()=>crypto_box_seal,
    crypto_box_seal_open: ()=>crypto_box_seal_open
});
const _buffer = require("buffer");
const _wasm = require("./wasm");
let Sodium;
let BUFFER;
let HEAPU8;
let HEAPF64;
let HEAP32;
let getRandomValue;
const ASM_CONSTS = {
    35736: function() {
        return getRandomValue === null || getRandomValue === void 0 ? void 0 : getRandomValue();
    },
    35772: function() {
        if (getRandomValue === undefined) {
            try {
                const window_ = "object" === typeof window ? window : self;
                const crypto_ = typeof window_.crypto !== "undefined" ? window_.crypto : window_.msCrypto;
                const randomValuesStandard = function() {
                    var buf = new Uint32Array(1);
                    crypto_.getRandomValues(buf);
                    return buf[0] >>> 0;
                };
                randomValuesStandard();
                getRandomValue = randomValuesStandard;
            } catch (e) {
                try {
                    const crypto = require("crypto");
                    const randomValueNodeJS = function() {
                        var buf = crypto["randomBytes"](4);
                        return (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0;
                    };
                    randomValueNodeJS();
                    getRandomValue = randomValueNodeJS;
                } catch (e1) {
                    throw new Error("No secure random number generator found");
                }
            }
        }
    }
};
function readAsmConstArgs(sigPtr, buf) {
    const readAsmConstArgsArray = [];
    let ch;
    buf >>= 2;
    while(ch = HEAPU8[sigPtr++]){
        var readAsmConstArgsDouble = ch < 105;
        if (readAsmConstArgsDouble && buf & 1) buf++;
        readAsmConstArgsArray.push(readAsmConstArgsDouble ? HEAPF64[buf++ >> 1] : HEAP32[buf]);
        ++buf;
    }
    return readAsmConstArgsArray;
}
function emscripten_asm_const_int(code, sigPtr, argbuf) {
    const args = readAsmConstArgs(sigPtr, argbuf);
    return ASM_CONSTS[code].apply(null, args);
}
function emscripten_notify_memory_growth() {
    const memory = Sodium.memory;
    BUFFER = _buffer.Buffer.from(memory.buffer);
    HEAPU8 = new Uint8Array(memory.buffer);
    HEAPF64 = new Float64Array(memory.buffer);
    HEAP32 = new Int32Array(memory.buffer);
}
function proc_exit(what) {
    throw new WebAssembly.RuntimeError(what);
}
const mod = new WebAssembly.Module(_buffer.Buffer.from(_wasm.WASM, "base64"));
const instance = new WebAssembly.Instance(mod, {
    env: {
        emscripten_asm_const_int,
        emscripten_notify_memory_growth
    },
    wasi_snapshot_preview1: {
        proc_exit
    }
});
Sodium = instance.exports;
emscripten_notify_memory_growth();
if (Sodium.sodium_init() < 0) {
    throw new Error("Failed to initialize Sodium");
}
function malloc(buf) {
    return Sodium.malloc(buf.byteLength);
}
function mallocAndCopy(buf) {
    const ptr = Sodium.malloc(buf.byteLength);
    BUFFER.set(buf, ptr);
    return ptr;
}
function free(ptr) {
    Sodium.free(ptr);
}
function copyAndFree(ptr, buf) {
    const target = _buffer.Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
    BUFFER.copy(target, 0, ptr, ptr + buf.byteLength);
    Sodium.free(ptr);
}
function crypto_aead_chacha20poly1305_encrypt(c, m, ad, nsec, npub, k) {
    const cptr = malloc(c);
    const clenptr = Sodium.malloc(8);
    const mptr = mallocAndCopy(m);
    const adptr = ad === null ? ad : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_aead_chacha20poly1305_encrypt(cptr, clenptr, mptr, BigInt(m.byteLength), adptr, BigInt(adlen), nsec, npubptr, kptr);
    const clen = _buffer.Buffer.alloc(8);
    copyAndFree(clenptr, clen);
    copyAndFree(cptr, c);
    free(mptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    return Number(clen.readBigUInt64LE());
}
function crypto_aead_chacha20poly1305_decrypt(m, nsec, c, ad, npub, k) {
    const mptr = malloc(m);
    const mlenptr = Sodium.malloc(8);
    const cptr = mallocAndCopy(c);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_aead_chacha20poly1305_decrypt(mptr, mlenptr, nsec, cptr, BigInt(c.byteLength), adptr, BigInt(adlen), npubptr, kptr);
    const mlen = _buffer.Buffer.alloc(8);
    copyAndFree(mlenptr, mlen);
    copyAndFree(mptr, m);
    free(cptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    if (ret < 0) {
        throw new Error("Invalid mac");
    }
    return Number(mlen.readBigUInt64LE());
}
function crypto_aead_chacha20poly1305_encrypt_detached(c, mac, m, ad, nsec, npub, k) {
    const cptr = malloc(c);
    const clenptr = Sodium.malloc(8);
    const macptr = malloc(mac);
    const mptr = mallocAndCopy(m);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_aead_chacha20poly1305_encrypt_detached(cptr, macptr, clenptr, mptr, BigInt(m.byteLength), adptr, BigInt(adlen), nsec, npubptr, kptr);
    const clen = _buffer.Buffer.alloc(8);
    copyAndFree(clenptr, clen);
    copyAndFree(cptr, c);
    copyAndFree(macptr, mac);
    free(mptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    return Number(clen.readBigUInt64LE());
}
function crypto_aead_chacha20poly1305_decrypt_detached(m, nsec, c, mac, ad, npub, k) {
    const mptr = malloc(m);
    const cptr = mallocAndCopy(c);
    const macptr = mallocAndCopy(mac);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_aead_chacha20poly1305_decrypt_detached(mptr, nsec, cptr, BigInt(c.byteLength), macptr, adptr, BigInt(adlen), npubptr, kptr);
    copyAndFree(mptr, m);
    free(cptr);
    free(macptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    if (ret < 0) {
        throw new Error("Invalid mac");
    }
}
function crypto_aead_chacha20poly1305_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_aead_chacha20poly1305_keygen(kptr);
    copyAndFree(kptr, k);
}
function crypto_aead_chacha20poly1305_ietf_encrypt(c, m, ad, nsec, npub, k) {
    const cptr = malloc(c);
    const clenptr = Sodium.malloc(8);
    const mptr = mallocAndCopy(m);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(cptr, clenptr, mptr, BigInt(m.byteLength), adptr, BigInt(adlen), nsec, npubptr, kptr);
    const clen = _buffer.Buffer.alloc(8);
    copyAndFree(clenptr, clen);
    copyAndFree(cptr, c);
    free(mptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    return Number(clen.readBigUInt64LE());
}
function crypto_aead_chacha20poly1305_ietf_decrypt(m, nsec, c, ad, npub, k) {
    const mptr = malloc(m);
    const mlenptr = Sodium.malloc(8);
    const cptr = mallocAndCopy(c);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(mptr, mlenptr, nsec, cptr, BigInt(c.byteLength), adptr, BigInt(adlen), npubptr, kptr);
    const mlen = _buffer.Buffer.alloc(8);
    copyAndFree(mlenptr, mlen);
    copyAndFree(mptr, m);
    free(cptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    if (ret < 0) {
        throw new Error("Invalid mac");
    }
    return Number(mlen.readBigUInt64LE());
}
function crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, m, ad, nsec, npub, k) {
    const cptr = malloc(c);
    const clenptr = Sodium.malloc(8);
    const macptr = malloc(mac);
    const mptr = mallocAndCopy(m);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(cptr, macptr, clenptr, mptr, BigInt(m.byteLength), adptr, BigInt(adlen), nsec, npubptr, kptr);
    const clen = _buffer.Buffer.alloc(8);
    copyAndFree(clenptr, clen);
    copyAndFree(cptr, c);
    copyAndFree(macptr, mac);
    free(mptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    return Number(clen.readBigUInt64LE());
}
function crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nsec, c, mac, ad, npub, k) {
    const mptr = malloc(m);
    const cptr = mallocAndCopy(c);
    const macptr = mallocAndCopy(mac);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(mptr, nsec, cptr, BigInt(c.byteLength), macptr, adptr, BigInt(adlen), npubptr, kptr);
    copyAndFree(mptr, m);
    free(cptr);
    free(macptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    if (ret < 0) {
        throw new Error("Invalid mac");
    }
}
function crypto_aead_chacha20poly1305_ietf_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_aead_chacha20poly1305_ietf_keygen(kptr);
    copyAndFree(kptr, k);
}
function crypto_aead_xchacha20poly1305_ietf_encrypt(c, m, ad, nsec, npub, k) {
    const cptr = malloc(c);
    const clenptr = Sodium.malloc(8);
    const mptr = mallocAndCopy(m);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cptr, clenptr, mptr, BigInt(m.byteLength), adptr, BigInt(adlen), nsec, npubptr, kptr);
    const clen = _buffer.Buffer.alloc(8);
    copyAndFree(clenptr, clen);
    copyAndFree(cptr, c);
    free(mptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    return Number(clen.readBigUInt64LE());
}
function crypto_aead_xchacha20poly1305_ietf_decrypt(m, nsec, c, ad, npub, k) {
    const mptr = malloc(m);
    const mlenptr = Sodium.malloc(8);
    const cptr = mallocAndCopy(c);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(mptr, mlenptr, nsec, cptr, BigInt(c.byteLength), adptr, BigInt(adlen), npubptr, kptr);
    const mlen = _buffer.Buffer.alloc(8);
    copyAndFree(mlenptr, mlen);
    copyAndFree(mptr, m);
    free(cptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    if (ret < 0) {
        throw new Error("Invalid mac");
    }
    return Number(mlen.readBigUInt64LE());
}
function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, m, ad, nsec, npub, k) {
    const cptr = malloc(c);
    const macptr = malloc(mac);
    const maclenptr = Sodium.malloc(8);
    const mptr = mallocAndCopy(m);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(cptr, macptr, maclenptr, mptr, BigInt(m.byteLength), adptr, BigInt(adlen), nsec, npubptr, kptr);
    const maclen = _buffer.Buffer.alloc(8);
    copyAndFree(maclenptr, maclen);
    copyAndFree(cptr, c);
    copyAndFree(macptr, mac);
    free(mptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    return Number(maclen.readBigUInt64LE());
}
function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, nsec, c, mac, ad, npub, k) {
    const mptr = malloc(m);
    const cptr = mallocAndCopy(c);
    const macptr = mallocAndCopy(mac);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const npubptr = mallocAndCopy(npub);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(mptr, nsec, cptr, BigInt(c.byteLength), macptr, adptr, BigInt(adlen), npubptr, kptr);
    copyAndFree(mptr, m);
    free(cptr);
    free(macptr);
    free(npubptr);
    free(kptr);
    if (adptr) {
        free(adptr);
    }
    if (ret < 0) {
        throw new Error("Invalid mac");
    }
}
function crypto_aead_xchacha20poly1305_ietf_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_aead_xchacha20poly1305_ietf_keygen(kptr);
    copyAndFree(kptr, k);
}
function crypto_auth(out, inp, k) {
    const outptr = malloc(out);
    const inpptr = mallocAndCopy(inp);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_auth(outptr, inpptr, BigInt(inp.byteLength), kptr);
    copyAndFree(outptr, out);
    free(inpptr);
    free(kptr);
}
function crypto_auth_verify(h, inp, k) {
    const hptr = mallocAndCopy(h);
    const inpptr = mallocAndCopy(inp);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_auth_verify(hptr, inpptr, BigInt(inp.byteLength), kptr);
    free(hptr);
    free(inpptr);
    free(kptr);
    return !!(ret + 1);
}
function crypto_auth_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_auth_keygen(kptr);
    copyAndFree(kptr, k);
}
function crypto_box_keypair(pk, sk) {
    const pkptr = malloc(pk);
    const skptr = malloc(sk);
    const ret = Sodium.crypto_box_keypair(pkptr, skptr);
    copyAndFree(pkptr, pk);
    copyAndFree(skptr, sk);
    return ret;
}
function crypto_box_seed_keypair(pk, sk, seed) {
    const pkptr = malloc(pk);
    const skptr = malloc(sk);
    const seedptr = mallocAndCopy(seed);
    const ret = Sodium.crypto_box_seed_keypair(pkptr, skptr, seedptr);
    copyAndFree(pkptr, pk);
    copyAndFree(skptr, sk);
    free(seedptr);
    if (ret < 0) {
        throw new Error("Invalid data");
    }
}
function crypto_box_easy(c, m, n, pk, sk) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const pkptr = mallocAndCopy(pk);
    const skptr = mallocAndCopy(sk);
    const ret = Sodium.crypto_box_easy(cptr, mptr, BigInt(m.byteLength), nptr, pkptr, skptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(pkptr);
    free(skptr);
    if (ret < 0) {
        throw new Error("Invalid data");
    }
}
function crypto_box_open_easy(m, c, n, pk, sk) {
    const mptr = malloc(m);
    const cptr = mallocAndCopy(c);
    const nptr = mallocAndCopy(n);
    const pkptr = mallocAndCopy(pk);
    const skptr = mallocAndCopy(sk);
    const ret = Sodium.crypto_box_open_easy(mptr, cptr, BigInt(c.byteLength), nptr, pkptr, skptr);
    copyAndFree(mptr, m);
    free(cptr);
    free(nptr);
    free(pkptr);
    free(skptr);
    return !!(ret + 1);
}
function crypto_box_detached(c, mac, m, n, pk, sk) {
    const cptr = malloc(c);
    const macptr = malloc(mac);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const pkptr = mallocAndCopy(pk);
    const skptr = mallocAndCopy(sk);
    const ret = Sodium.crypto_box_detached(cptr, macptr, mptr, BigInt(m.byteLength), nptr, pkptr, skptr);
    copyAndFree(cptr, c);
    copyAndFree(macptr, mac);
    free(mptr);
    free(nptr);
    free(pkptr);
    free(skptr);
    if (ret < 0) {
        throw new Error("Invalid data");
    }
}
function crypto_box_open_detached(m, c, mac, n, pk, sk) {
    const mptr = malloc(m);
    const cptr = mallocAndCopy(c);
    const macptr = mallocAndCopy(mac);
    const nptr = mallocAndCopy(n);
    const pkptr = mallocAndCopy(pk);
    const skptr = mallocAndCopy(sk);
    const ret = Sodium.crypto_box_open_detached(mptr, cptr, macptr, BigInt(c.byteLength), nptr, pkptr, skptr);
    copyAndFree(mptr, m);
    free(cptr);
    free(macptr);
    free(nptr);
    free(pkptr);
    free(skptr);
    return !!(ret + 1);
}
function crypto_core_ed25519_is_valid_point(p) {
    const pptr = mallocAndCopy(p);
    const ret = Sodium.crypto_core_ed25519_is_valid_point(pptr);
    free(pptr);
    return !!ret;
}
function crypto_core_ed25519_random(p) {
    const pptr = malloc(p);
    Sodium.crypto_core_ed25519_random(pptr);
    copyAndFree(pptr, p);
}
function crypto_core_ed25519_from_uniform(p, r) {
    const pptr = malloc(p);
    const rptr = mallocAndCopy(r);
    const ret = Sodium.crypto_core_ed25519_from_uniform(pptr, rptr);
    copyAndFree(pptr, p);
    free(rptr);
    if (ret < 0) {
        throw new Error("Invalid data");
    }
}
function crypto_core_ed25519_add(r, p, q) {
    const rptr = malloc(r);
    const pptr = mallocAndCopy(p);
    const qptr = mallocAndCopy(q);
    const ret = Sodium.crypto_core_ed25519_add(rptr, pptr, qptr);
    copyAndFree(rptr, r);
    free(pptr);
    free(qptr);
    if (ret < 0) {
        throw new Error("Not a valid curve point");
    }
}
function crypto_core_ed25519_sub(r, p, q) {
    const rptr = malloc(r);
    const pptr = mallocAndCopy(p);
    const qptr = mallocAndCopy(q);
    const ret = Sodium.crypto_core_ed25519_sub(rptr, pptr, qptr);
    copyAndFree(rptr, r);
    free(pptr);
    free(qptr);
    if (ret < 0) {
        throw new Error("Not a valid curve point");
    }
}
function crypto_core_ed25519_scalar_random(r) {
    const rptr = malloc(r);
    Sodium.crypto_core_ed25519_scalar_random(rptr);
    copyAndFree(rptr, r);
}
function crypto_core_ed25519_scalar_reduce(r, s) {
    const rptr = malloc(r);
    const sptr = mallocAndCopy(s);
    Sodium.crypto_core_ed25519_scalar_reduce(rptr, sptr);
    copyAndFree(rptr, r);
    free(sptr);
}
function crypto_core_ed25519_scalar_invert(recip, s) {
    const recipptr = malloc(recip);
    const sptr = mallocAndCopy(s);
    const ret = Sodium.crypto_core_ed25519_scalar_invert(recipptr, sptr);
    copyAndFree(recipptr, recip);
    free(sptr);
    if (ret < 0) {
        throw new Error("Invalid data");
    }
}
function crypto_core_ed25519_scalar_negate(neg, s) {
    const negptr = malloc(neg);
    const sptr = mallocAndCopy(s);
    Sodium.crypto_core_ed25519_scalar_negate(negptr, sptr);
    copyAndFree(negptr, neg);
    free(sptr);
}
function crypto_core_ed25519_scalar_complement(comp, s) {
    const compptr = malloc(comp);
    const sptr = mallocAndCopy(s);
    Sodium.crypto_core_ed25519_scalar_complement(compptr, sptr);
    copyAndFree(compptr, comp);
    free(sptr);
}
function crypto_core_ed25519_scalar_add(z, x, y) {
    const zptr = malloc(z);
    const xptr = mallocAndCopy(x);
    const yptr = mallocAndCopy(y);
    Sodium.crypto_core_ed25519_scalar_add(zptr, xptr, yptr);
    copyAndFree(zptr, z);
    free(xptr);
    free(yptr);
}
function crypto_core_ed25519_scalar_sub(z, x, y) {
    const zptr = malloc(z);
    const xptr = mallocAndCopy(x);
    const yptr = mallocAndCopy(y);
    Sodium.crypto_core_ed25519_scalar_sub(zptr, xptr, yptr);
    copyAndFree(zptr, z);
    free(xptr);
    free(yptr);
}
function crypto_core_ed25519_scalar_mul(z, x, y) {
    const zptr = malloc(z);
    const xptr = mallocAndCopy(x);
    const yptr = mallocAndCopy(y);
    Sodium.crypto_core_ed25519_scalar_mul(zptr, xptr, yptr);
    copyAndFree(zptr, z);
    free(xptr);
    free(yptr);
}
const crypto_generichash_STATEBYTES = Sodium.crypto_generichash_statebytes();
function crypto_generichash(out, inp, key) {
    const outptr = malloc(out);
    const inpptr = mallocAndCopy(inp);
    const keyptr = key === null || typeof key === "undefined" ? null : mallocAndCopy(key);
    const keylen = key === null || typeof key === "undefined" ? 0 : key.byteLength;
    const ret = Sodium.crypto_generichash(outptr, out.byteLength, inpptr, BigInt(inp.byteLength), keyptr, keylen);
    copyAndFree(outptr, out);
    free(inpptr);
    if (keyptr) {
        free(keyptr);
    }
    if (ret < 0) {
        throw new Error("Invalid data");
    }
}
function crypto_generichash_init(state, key, outlen) {
    const stateptr = malloc(state);
    const keyptr = key === null || typeof key === "undefined" ? null : mallocAndCopy(key);
    const keylen = key === null || typeof key === "undefined" ? 0 : key.byteLength;
    Sodium.crypto_generichash_init(stateptr, keyptr, keylen, outlen);
    copyAndFree(stateptr, state);
    if (keyptr) {
        free(keyptr);
    }
}
function crypto_generichash_update(state, inp) {
    const stateptr = mallocAndCopy(state);
    const inpptr = mallocAndCopy(inp);
    Sodium.crypto_generichash_update(stateptr, inpptr, BigInt(inp.byteLength));
    copyAndFree(stateptr, state);
    free(inpptr);
}
function crypto_generichash_final(state, out) {
    const stateptr = mallocAndCopy(state);
    const outptr = malloc(out);
    Sodium.crypto_generichash_final(stateptr, outptr, out.byteLength);
    copyAndFree(stateptr, state);
    copyAndFree(outptr, out);
}
function crypto_generichash_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_generichash_keygen(kptr);
    copyAndFree(kptr, k);
}
function crypto_hash(out, inp) {
    const outptr = malloc(out);
    const inpptr = mallocAndCopy(inp);
    Sodium.crypto_hash(outptr, inpptr, BigInt(inp.byteLength));
    copyAndFree(outptr, out);
    free(inpptr);
}
const crypto_hash_sha256_STATEBYTES = Sodium.crypto_hash_sha256_statebytes();
function crypto_hash_sha256(out, inp) {
    const outptr = malloc(out);
    const inpptr = mallocAndCopy(inp);
    Sodium.crypto_hash_sha256(outptr, inpptr, BigInt(inp.byteLength));
    copyAndFree(outptr, out);
    free(inpptr);
}
function crypto_hash_sha256_init(state) {
    const stateptr = malloc(state);
    Sodium.crypto_hash_sha256_init(stateptr);
    copyAndFree(stateptr, state);
}
function crypto_hash_sha256_update(state, inp) {
    const stateptr = mallocAndCopy(state);
    const inpptr = mallocAndCopy(inp);
    Sodium.crypto_hash_sha256_update(stateptr, inpptr, BigInt(inp.byteLength));
    copyAndFree(stateptr, state);
    free(inpptr);
}
function crypto_hash_sha256_final(state, out) {
    const stateptr = mallocAndCopy(state);
    const outptr = malloc(out);
    Sodium.crypto_hash_sha256_final(stateptr, outptr);
    copyAndFree(stateptr, state);
    copyAndFree(outptr, out);
}
const crypto_hash_sha512_STATEBYTES = Sodium.crypto_hash_sha512_statebytes();
function crypto_hash_sha512(out, inp) {
    const outptr = malloc(out);
    const inpptr = mallocAndCopy(inp);
    Sodium.crypto_hash_sha512(outptr, inpptr, BigInt(inp.byteLength));
    copyAndFree(outptr, out);
    free(inpptr);
}
function crypto_hash_sha512_init(state) {
    const stateptr = malloc(state);
    Sodium.crypto_hash_sha512_init(stateptr);
    copyAndFree(stateptr, state);
}
function crypto_hash_sha512_update(state, inp) {
    const stateptr = mallocAndCopy(state);
    const inpptr = mallocAndCopy(inp);
    Sodium.crypto_hash_sha512_update(stateptr, inpptr, BigInt(inp.byteLength));
    copyAndFree(stateptr, state);
    free(inpptr);
}
function crypto_hash_sha512_final(state, out) {
    const stateptr = mallocAndCopy(state);
    const outptr = malloc(out);
    Sodium.crypto_hash_sha512_final(stateptr, outptr);
    copyAndFree(stateptr, state);
    copyAndFree(outptr, out);
}
function crypto_kdf_keygen(key) {
    const keyptr = malloc(key);
    Sodium.crypto_kdf_keygen(keyptr);
    copyAndFree(keyptr, key);
}
function crypto_kdf_derive_from_key(subkey, subkey_id, ctx, key) {
    const subkeyptr = malloc(subkey);
    const ctxptr = mallocAndCopy(ctx);
    const keyptr = mallocAndCopy(key);
    Sodium.crypto_kdf_derive_from_key(subkeyptr, subkey.byteLength, BigInt(subkey_id), ctxptr, keyptr);
    copyAndFree(subkeyptr, subkey);
    free(ctxptr);
    free(keyptr);
}
function crypto_kx_keypair(pk, sk) {
    const pkptr = malloc(pk);
    const skptr = malloc(sk);
    Sodium.crypto_kx_keypair(pkptr, skptr);
    copyAndFree(pkptr, pk);
    copyAndFree(skptr, sk);
}
function crypto_kx_seed_keypair(pk, sk, seed) {
    const pkptr = malloc(pk);
    const skptr = malloc(sk);
    const seedptr = mallocAndCopy(seed);
    Sodium.crypto_kx_seed_keypair(pkptr, skptr, seedptr);
    copyAndFree(pkptr, pk);
    copyAndFree(skptr, sk);
    free(seedptr);
}
function crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) {
    const rxptr = rx === null ? null : malloc(rx);
    const txptr = tx === null ? null : malloc(tx);
    const cpkptr = mallocAndCopy(client_pk);
    const cskptr = mallocAndCopy(client_sk);
    const spkptr = mallocAndCopy(server_pk);
    Sodium.crypto_kx_client_session_keys(rxptr, txptr, cpkptr, cskptr, spkptr);
    if (rx && rxptr) copyAndFree(rxptr, rx);
    if (tx && txptr) copyAndFree(txptr, tx);
    free(cpkptr);
    free(cskptr);
    free(spkptr);
}
function crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk) {
    const rxptr = rx === null ? null : malloc(rx);
    const txptr = tx === null ? null : malloc(tx);
    const spkptr = mallocAndCopy(server_pk);
    const sskptr = mallocAndCopy(server_sk);
    const cpkptr = mallocAndCopy(client_pk);
    Sodium.crypto_kx_server_session_keys(rxptr, txptr, spkptr, sskptr, cpkptr);
    if (rx && rxptr) copyAndFree(rxptr, rx);
    if (tx && txptr) copyAndFree(txptr, tx);
    free(spkptr);
    free(sskptr);
    free(cpkptr);
}
const crypto_onetimeauth_STATEBYTES = Sodium.crypto_onetimeauth_statebytes();
function crypto_onetimeauth(out, inp, k) {
    const outptr = malloc(out);
    const inpptr = mallocAndCopy(inp);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_onetimeauth(outptr, inpptr, BigInt(inp.byteLength), kptr);
    copyAndFree(outptr, out);
    free(inpptr);
    free(kptr);
}
function crypto_onetimeauth_verify(h, inp, k) {
    const hptr = mallocAndCopy(h);
    const inpptr = mallocAndCopy(inp);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_onetimeauth_verify(hptr, inpptr, BigInt(inp.byteLength), kptr);
    free(hptr);
    free(inpptr);
    free(kptr);
    return !!(ret + 1);
}
function crypto_onetimeauth_init(state, key) {
    const stateptr = malloc(state);
    const keyptr = mallocAndCopy(key);
    Sodium.crypto_onetimeauth_init(stateptr, keyptr);
    copyAndFree(stateptr, state);
    free(keyptr);
}
function crypto_onetimeauth_update(state, inp) {
    const stateptr = mallocAndCopy(state);
    const inpptr = mallocAndCopy(inp);
    Sodium.crypto_onetimeauth_update(stateptr, inpptr, BigInt(inp.byteLength));
    copyAndFree(stateptr, state);
    free(inpptr);
}
function crypto_onetimeauth_final(state, out) {
    const stateptr = mallocAndCopy(state);
    const outptr = malloc(out);
    Sodium.crypto_onetimeauth_final(stateptr, outptr);
    copyAndFree(stateptr, state);
    copyAndFree(outptr, out);
}
function crypto_onetimeauth_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_onetimeauth_keygen(kptr);
    copyAndFree(kptr, k);
}
const crypto_pwhash_ALG_ARGON2I13 = 1;
const crypto_pwhash_ALG_ARGON2ID13 = 2;
function crypto_pwhash(out, passwd, salt, opslimit, memlimit, alg) {
    const outptr = malloc(out);
    const passwdptr = mallocAndCopy(passwd);
    const saltptr = mallocAndCopy(salt);
    Sodium.crypto_pwhash(outptr, BigInt(out.byteLength), passwdptr, BigInt(passwd.byteLength), saltptr, BigInt(opslimit), memlimit, alg);
    copyAndFree(outptr, out);
    free(passwdptr);
    free(saltptr);
}
function crypto_pwhash_str(out, passwd, opslimit, memlimit) {
    const outptr = malloc(out);
    const passwdptr = mallocAndCopy(passwd);
    Sodium.crypto_pwhash_str(outptr, passwdptr, BigInt(passwd.byteLength), BigInt(opslimit), memlimit);
    copyAndFree(outptr, out);
    free(passwdptr);
}
function crypto_pwhash_str_verify(str, passwd) {
    const strptr = mallocAndCopy(str);
    const passwdptr = mallocAndCopy(passwd);
    const ret = Sodium.crypto_pwhash_str_verify(strptr, passwdptr, BigInt(passwd.byteLength));
    free(strptr);
    free(passwdptr);
    return !!(ret + 1);
}
function crypto_pwhash_str_needs_rehash(str, opslimit, memlimit) {
    const strptr = mallocAndCopy(str);
    const ret = Sodium.crypto_pwhash_str_needs_rehash(strptr, BigInt(opslimit), memlimit);
    free(strptr);
    return !!ret;
}
function crypto_pwhash_scryptsalsa208sha256(out, passwd, salt, opslimit, memlimit) {
    const outptr = malloc(out);
    const passwdptr = mallocAndCopy(passwd);
    const saltptr = mallocAndCopy(salt);
    Sodium.crypto_pwhash_scryptsalsa208sha256(outptr, BigInt(out.byteLength), passwdptr, BigInt(passwd.byteLength), saltptr, BigInt(opslimit), memlimit);
    copyAndFree(outptr, out);
    free(passwdptr);
    free(saltptr);
}
function crypto_pwhash_scryptsalsa208sha256_str(out, passwd, opslimit, memlimit) {
    const outptr = malloc(out);
    const passwdptr = mallocAndCopy(passwd);
    Sodium.crypto_pwhash_scryptsalsa208sha256_str(outptr, passwdptr, BigInt(passwd.byteLength), BigInt(opslimit), memlimit);
    copyAndFree(outptr, out);
    free(passwdptr);
}
function crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd) {
    const strptr = mallocAndCopy(str);
    const passwdptr = mallocAndCopy(passwd);
    const ret = Sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(strptr, passwdptr, BigInt(passwd.byteLength));
    free(strptr);
    free(passwdptr);
    return !!(ret + 1);
}
function crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(str, opslimit, memlimit) {
    const strptr = mallocAndCopy(str);
    const ret = Sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(strptr, BigInt(opslimit), memlimit);
    free(strptr);
    return !!ret;
}
function crypto_scalarmult_base(q, n) {
    const qptr = malloc(q);
    const nptr = mallocAndCopy(n);
    Sodium.crypto_scalarmult_base(qptr, nptr);
    copyAndFree(qptr, q);
    free(nptr);
}
function crypto_scalarmult(q, n, p) {
    const qptr = malloc(q);
    const nptr = mallocAndCopy(n);
    const pptr = mallocAndCopy(p);
    Sodium.crypto_scalarmult(qptr, nptr, pptr);
    copyAndFree(qptr, q);
    free(nptr);
    free(pptr);
}
function crypto_scalarmult_ed25519(q, n, p) {
    const qptr = malloc(q);
    const nptr = mallocAndCopy(n);
    const pptr = mallocAndCopy(p);
    Sodium.crypto_scalarmult_ed25519(qptr, nptr, pptr);
    copyAndFree(qptr, q);
    free(nptr);
    free(pptr);
}
function crypto_scalarmult_ed25519_base(q, n) {
    const qptr = malloc(q);
    const nptr = mallocAndCopy(n);
    Sodium.crypto_scalarmult_ed25519_base(qptr, nptr);
    copyAndFree(qptr, q);
    free(nptr);
}
function crypto_scalarmult_ed25519_noclamp(q, n, p) {
    const qptr = malloc(q);
    const nptr = mallocAndCopy(n);
    const pptr = mallocAndCopy(p);
    Sodium.crypto_scalarmult_ed25519_noclamp(qptr, nptr, pptr);
    copyAndFree(qptr, q);
    free(nptr);
    free(pptr);
}
function crypto_scalarmult_ed25519_base_noclamp(q, n) {
    const qptr = malloc(q);
    const nptr = mallocAndCopy(n);
    Sodium.crypto_scalarmult_ed25519_base_noclamp(qptr, nptr);
    copyAndFree(qptr, q);
    free(nptr);
}
function crypto_secretbox_easy(c, m, n, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_secretbox_easy(cptr, mptr, BigInt(m.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_secretbox_open_easy(m, c, n, k) {
    const mptr = mallocAndCopy(m);
    const cptr = mallocAndCopy(c);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_secretbox_open_easy(mptr, cptr, BigInt(c.byteLength), nptr, kptr);
    copyAndFree(mptr, m);
    free(cptr);
    free(nptr);
    free(kptr);
    return !!(ret + 1);
}
function crypto_secretbox_detached(c, mac, m, n, k) {
    const cptr = malloc(c);
    const macptr = malloc(mac);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_secretbox_detached(cptr, macptr, mptr, BigInt(m.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    copyAndFree(macptr, mac);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_secretbox_open_detached(m, c, mac, n, k) {
    const mptr = mallocAndCopy(m);
    const cptr = mallocAndCopy(c);
    const macptr = mallocAndCopy(mac);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    const ret = Sodium.crypto_secretbox_open_detached(mptr, cptr, macptr, BigInt(c.byteLength), nptr, kptr);
    copyAndFree(mptr, m);
    free(cptr);
    free(macptr);
    free(nptr);
    free(kptr);
    return !!(ret + 1);
}
function crypto_secretbox_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_secretbox_keygen(kptr);
    copyAndFree(kptr, k);
}
const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = _buffer.Buffer.from([
    Sodium.crypto_secretstream_xchacha20poly1305_tag_message(), 
]);
const crypto_secretstream_xchacha20poly1305_TAG_PUSH = _buffer.Buffer.from([
    Sodium.crypto_secretstream_xchacha20poly1305_tag_push(), 
]);
const crypto_secretstream_xchacha20poly1305_TAG_REKEY = _buffer.Buffer.from([
    Sodium.crypto_secretstream_xchacha20poly1305_tag_rekey(), 
]);
const crypto_secretstream_xchacha20poly1305_TAG_FINAL = _buffer.Buffer.from([
    Sodium.crypto_secretstream_xchacha20poly1305_tag_final(), 
]);
function crypto_secretstream_xchacha20poly1305_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_secretstream_xchacha20poly1305_keygen(kptr);
    copyAndFree(kptr, k);
}
const crypto_secretstream_xchacha20poly1305_STATEBYTES = Sodium.crypto_secretstream_xchacha20poly1305_statebytes();
function crypto_secretstream_xchacha20poly1305_init_push(state, header, k) {
    const stateptr = malloc(state);
    const headerptr = malloc(header);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_secretstream_xchacha20poly1305_init_push(stateptr, headerptr, kptr);
    copyAndFree(stateptr, state);
    copyAndFree(headerptr, header);
    free(kptr);
}
function crypto_secretstream_xchacha20poly1305_push(state, c, m, ad, tag) {
    const stateptr = mallocAndCopy(state);
    const cptr = malloc(c);
    const clenptr = Sodium.malloc(8);
    const mptr = mallocAndCopy(m);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    Sodium.crypto_secretstream_xchacha20poly1305_push(stateptr, cptr, clenptr, mptr, BigInt(m.byteLength), adptr, BigInt(adlen), tag[0]);
    const clen = _buffer.Buffer.alloc(8);
    copyAndFree(clenptr, clen);
    copyAndFree(stateptr, state);
    copyAndFree(cptr, c);
    free(mptr);
    if (adptr) {
        free(adptr);
    }
    return Number(clen.readBigUInt64LE());
}
function crypto_secretstream_xchacha20poly1305_init_pull(state, header, k) {
    const stateptr = malloc(state);
    const headerptr = mallocAndCopy(header);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_secretstream_xchacha20poly1305_init_pull(stateptr, headerptr, kptr);
    copyAndFree(stateptr, state);
    free(headerptr);
    free(kptr);
}
function crypto_secretstream_xchacha20poly1305_pull(state, m, tag, c, ad) {
    const stateptr = mallocAndCopy(state);
    const mptr = mallocAndCopy(m);
    const mlenptr = Sodium.malloc(8);
    const tagptr = Sodium.malloc(1);
    const cptr = mallocAndCopy(c);
    const adptr = ad === null ? null : mallocAndCopy(ad);
    const adlen = ad === null ? 0 : ad.byteLength;
    const ret = Sodium.crypto_secretstream_xchacha20poly1305_pull(stateptr, mptr, mlenptr, tagptr, cptr, BigInt(c.byteLength), adptr, BigInt(adlen));
    const mlen = _buffer.Buffer.alloc(8);
    copyAndFree(mlenptr, mlen);
    copyAndFree(stateptr, state);
    copyAndFree(mptr, m);
    const tagIn = _buffer.Buffer.alloc(1);
    copyAndFree(tagptr, tagIn);
    const t = tagIn.readInt8();
    tag[0] = t;
    free(cptr);
    if (adptr) {
        free(adptr);
    }
    if (ret < 0) {
        throw new Error("Invalid cipher");
    }
    return Number(mlen.readBigUInt64LE());
}
function crypto_secretstream_xchacha20poly1305_rekey(state) {
    const stateptr = mallocAndCopy(state);
    Sodium.crypto_secretstream_xchacha20poly1305_rekey(stateptr);
    copyAndFree(stateptr, state);
}
function crypto_shorthash_keygen(k) {
    const kptr = malloc(k);
    Sodium.crypto_shorthash_keygen(kptr);
    copyAndFree(kptr, k);
}
function crypto_shorthash(out, inp, k) {
    const outptr = malloc(out);
    const inpptr = mallocAndCopy(inp);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_shorthash(outptr, inpptr, BigInt(inp.byteLength), kptr);
    copyAndFree(outptr, out);
    free(inpptr);
    free(kptr);
}
function crypto_shorthash_siphashx24(out, inp, k) {
    const outptr = malloc(out);
    const inpptr = mallocAndCopy(inp);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_shorthash_siphashx24(outptr, inpptr, BigInt(inp.byteLength), kptr);
    copyAndFree(outptr, out);
    free(inpptr);
    free(kptr);
}
const crypto_sign_STATEBYTES = Sodium.crypto_sign_statebytes();
function crypto_sign_keypair(pk, sk) {
    const pkptr = malloc(pk);
    const skptr = malloc(sk);
    Sodium.crypto_sign_keypair(pkptr, skptr);
    copyAndFree(pkptr, pk);
    copyAndFree(skptr, sk);
}
function crypto_sign_seed_keypair(pk, sk, seed) {
    const pkptr = malloc(pk);
    const skptr = malloc(sk);
    const seedptr = mallocAndCopy(seed);
    Sodium.crypto_sign_seed_keypair(pkptr, skptr, seedptr);
    copyAndFree(pkptr, pk);
    copyAndFree(skptr, sk);
    free(seedptr);
}
function crypto_sign(sm, m, sk) {
    const smptr = malloc(sm);
    const smlenptr = Sodium.malloc(8);
    const mptr = mallocAndCopy(m);
    const skptr = mallocAndCopy(sk);
    Sodium.crypto_sign(smptr, smlenptr, mptr, BigInt(m.byteLength), skptr);
    const smlen = _buffer.Buffer.alloc(8);
    copyAndFree(smlenptr, smlen);
    copyAndFree(smptr, sm);
    free(mptr);
    free(skptr);
    return Number(smlen.readBigUInt64LE());
}
function crypto_sign_open(m, sm, pk) {
    const mptr = malloc(m);
    const smptr = mallocAndCopy(sm);
    const pkptr = mallocAndCopy(pk);
    const ret = Sodium.crypto_sign_open(mptr, null, smptr, BigInt(sm.byteLength), pkptr);
    copyAndFree(mptr, m);
    free(smptr);
    free(pkptr);
    return ret === 0;
}
function crypto_sign_detached(sig, m, sk) {
    const sigptr = malloc(sig);
    const mptr = mallocAndCopy(m);
    const skptr = mallocAndCopy(sk);
    Sodium.crypto_sign_detached(sigptr, null, mptr, BigInt(m.byteLength), skptr);
    copyAndFree(sigptr, sig);
    free(mptr);
    free(skptr);
}
function crypto_sign_verify_detached(sig, m, pk) {
    const sigptr = mallocAndCopy(sig);
    const mptr = mallocAndCopy(m);
    const pkptr = mallocAndCopy(pk);
    const ret = Sodium.crypto_sign_verify_detached(sigptr, mptr, BigInt(m.byteLength), pkptr);
    free(sigptr);
    free(mptr);
    free(pkptr);
    return ret === 0;
}
function crypto_sign_ed25519_sk_to_pk(pk, sk) {
    const pkptr = malloc(pk);
    const skptr = mallocAndCopy(sk);
    Sodium.crypto_sign_ed25519_sk_to_pk(pkptr, skptr);
    copyAndFree(pkptr, pk);
    free(skptr);
}
function crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk) {
    const xpkptr = malloc(x25519_pk);
    const epkptr = mallocAndCopy(ed25519_pk);
    const ret = Sodium.crypto_sign_ed25519_pk_to_curve25519(xpkptr, epkptr);
    copyAndFree(xpkptr, x25519_pk);
    free(epkptr);
    if (ret < 0) {
        throw new Error("Invalid public key");
    }
}
function crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_sk) {
    const xskptr = malloc(x25519_sk);
    const eskptr = mallocAndCopy(ed25519_sk);
    const ret = Sodium.crypto_sign_ed25519_sk_to_curve25519(xskptr, eskptr);
    copyAndFree(xskptr, x25519_sk);
    free(eskptr);
    if (ret < 0) {
        throw new Error("Invalid secret key");
    }
}
function crypto_stream_chacha20(c, n, k) {
    const cptr = malloc(c);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_chacha20(cptr, BigInt(c.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(nptr);
    free(kptr);
}
function crypto_stream_chacha20_xor(c, m, n, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_chacha20_xor(cptr, mptr, BigInt(m.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_stream_chacha20_xor_ic(c, m, n, ic, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_chacha20_xor_ic(cptr, mptr, BigInt(m.byteLength), nptr, BigInt(ic), kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_stream_chacha20_ietf(c, n, k) {
    const cptr = malloc(c);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_chacha20_ietf(cptr, BigInt(c.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(nptr);
    free(kptr);
}
function crypto_stream_chacha20_ietf_xor(c, m, n, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_chacha20_ietf_xor(cptr, mptr, BigInt(m.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_stream_chacha20_ietf_xor_ic(c, m, n, ic, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_chacha20_ietf_xor_ic(cptr, mptr, BigInt(m.byteLength), nptr, ic, kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_stream_xchacha20(c, n, k) {
    const cptr = malloc(c);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_xchacha20(cptr, BigInt(c.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(nptr);
    free(kptr);
}
function crypto_stream_xchacha20_xor(c, m, n, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_xchacha20_xor(cptr, mptr, BigInt(m.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_stream_xchacha20_xor_ic(c, m, n, ic, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_xchacha20_xor_ic(cptr, mptr, BigInt(m.byteLength), nptr, BigInt(ic), kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_stream_salsa20(c, n, k) {
    const cptr = malloc(c);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_salsa20(cptr, BigInt(c.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(nptr);
    free(kptr);
}
function crypto_stream_salsa20_xor(c, m, n, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_salsa20_xor(cptr, mptr, BigInt(m.byteLength), nptr, kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function crypto_stream_salsa20_xor_ic(c, m, n, ic, k) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const nptr = mallocAndCopy(n);
    const kptr = mallocAndCopy(k);
    Sodium.crypto_stream_salsa20_xor_ic(cptr, mptr, BigInt(m.byteLength), nptr, BigInt(ic), kptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(nptr);
    free(kptr);
}
function randombytes_random() {
    return Sodium.randombytes_random() >>> 0;
}
function randombytes_uniform(upper_bound) {
    return Sodium.randombytes_uniform(upper_bound) >>> 0;
}
function randombytes_buf(buf) {
    const bufptr = malloc(buf);
    Sodium.randombytes_buf(bufptr, buf.byteLength);
    copyAndFree(bufptr, buf);
}
function randombytes_buf_deterministic(buf, seed) {
    const bufptr = malloc(buf);
    const seedptr = mallocAndCopy(seed);
    Sodium.randombytes_buf_deterministic(bufptr, buf.byteLength, seedptr);
    copyAndFree(bufptr, buf);
    free(seedptr);
}
function sodium_memcmp(b1_, b2_) {
    if (b1_.byteLength !== b2_.byteLength) {
        throw new Error("Arguments must be of equal length");
    }
    const b1ptr = mallocAndCopy(b1_);
    const b2ptr = mallocAndCopy(b2_);
    const ret = Sodium.sodium_memcmp(b1ptr, b2ptr, b1_.byteLength);
    free(b1ptr);
    free(b2ptr);
    return !!(ret + 1);
}
function sodium_increment(n) {
    const nptr = mallocAndCopy(n);
    Sodium.sodium_increment(nptr, n.byteLength);
    copyAndFree(nptr, n);
}
function sodium_add(a, b) {
    const aptr = mallocAndCopy(a);
    const bptr = mallocAndCopy(b);
    Sodium.sodium_add(aptr, bptr, a.byteLength);
    copyAndFree(aptr, a);
    free(bptr);
}
function sodium_sub(a, b) {
    const aptr = mallocAndCopy(a);
    const bptr = mallocAndCopy(b);
    Sodium.sodium_sub(aptr, bptr, a.byteLength);
    copyAndFree(aptr, a);
    free(bptr);
}
function sodium_compare(b1_, b2_) {
    const b1ptr = mallocAndCopy(b1_);
    const b2ptr = mallocAndCopy(b2_);
    const ret = Sodium.sodium_compare(b1ptr, b2ptr, b1_.byteLength);
    free(b1ptr);
    free(b2ptr);
    return ret;
}
function sodium_is_zero(n) {
    const nptr = mallocAndCopy(n);
    const ret = Sodium.sodium_is_zero(nptr, n.byteLength);
    free(nptr);
    return !!ret;
}
function sodium_pad(buf, unpaddedLength, blocksize) {
    if (unpaddedLength > buf.byteLength) {
        throw new Error("unpadded length cannot exceed buffer length");
    }
    if (blocksize > buf.byteLength) {
        throw new Error("block size cannot exceed buffer length");
    }
    if (blocksize < 1) {
        throw new Error("block sizemust be at least 1 byte");
    }
    if (buf.byteLength < unpaddedLength + (blocksize - unpaddedLength % blocksize)) {
        throw new Error("buf not long enough");
    }
    const paddedLenghtptr = Sodium.malloc(4);
    const bufptr = mallocAndCopy(buf);
    const ret = Sodium.sodium_pad(paddedLenghtptr, bufptr, unpaddedLength, blocksize, buf.byteLength);
    const paddedLength = _buffer.Buffer.alloc(4);
    copyAndFree(paddedLenghtptr, paddedLength);
    copyAndFree(bufptr, buf);
    if (ret < 0) {
        throw new Error("Invalid data");
    }
    return paddedLength.readInt32LE();
}
function sodium_unpad(buf, paddedLength, blocksize) {
    if (paddedLength > buf.byteLength) {
        throw new Error("unpadded length cannot exceed buffer length");
    }
    if (blocksize > buf.byteLength) {
        throw new Error("block size cannot exceed buffer length");
    }
    if (blocksize < 1) {
        throw new Error("block size must be at least 1 byte");
    }
    const unpaddedLengthptr = Sodium.malloc(4);
    const bufptr = mallocAndCopy(buf);
    Sodium.sodium_unpad(unpaddedLengthptr, bufptr, paddedLength, blocksize);
    const unpaddedLength = _buffer.Buffer.alloc(4);
    copyAndFree(unpaddedLengthptr, unpaddedLength);
    copyAndFree(bufptr, buf);
    return unpaddedLength.readInt32LE();
}
function crypto_box_seal(c, m, pk) {
    const cptr = malloc(c);
    const mptr = mallocAndCopy(m);
    const pkptr = mallocAndCopy(pk);
    Sodium.crypto_box_seal(cptr, mptr, BigInt(m.byteLength), pkptr);
    copyAndFree(cptr, c);
    free(mptr);
    free(pkptr);
}
function crypto_box_seal_open(m, c, pk, sk) {
    const mptr = malloc(m);
    const cptr = mallocAndCopy(c);
    const pkptr = mallocAndCopy(pk);
    const skptr = mallocAndCopy(sk);
    const ret = Sodium.crypto_box_seal_open(mptr, cptr, BigInt(c.byteLength), pkptr, skptr);
    copyAndFree(mptr, m);
    free(cptr);
    free(pkptr);
    free(skptr);
    return !!(ret + 1);
}
