/// <reference types="node" />
import { Buffer } from "buffer";
export declare function crypto_aead_chacha20poly1305_encrypt(c: Uint8Array, m: Uint8Array, ad: Uint8Array | null, nsec: null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_chacha20poly1305_decrypt(m: Uint8Array, nsec: null, c: Uint8Array, ad: Uint8Array | null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_chacha20poly1305_encrypt_detached(c: Uint8Array, mac: Uint8Array, m: Uint8Array, ad: Uint8Array | null, nsec: null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_chacha20poly1305_decrypt_detached(m: Uint8Array, nsec: null, c: Uint8Array, mac: Uint8Array, ad: Uint8Array | null, npub: Uint8Array, k: Uint8Array): void;
export declare function crypto_aead_chacha20poly1305_keygen(k: Uint8Array): void;
export declare function crypto_aead_chacha20poly1305_ietf_encrypt(c: Uint8Array, m: Uint8Array, ad: Uint8Array | null, nsec: null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_chacha20poly1305_ietf_decrypt(m: Uint8Array, nsec: null, c: Uint8Array, ad: Uint8Array | null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_chacha20poly1305_ietf_encrypt_detached(c: Uint8Array, mac: Uint8Array, m: Uint8Array, ad: Uint8Array | null, nsec: null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_chacha20poly1305_ietf_decrypt_detached(m: Uint8Array, nsec: null, c: Uint8Array, mac: Uint8Array, ad: Uint8Array | null, npub: Uint8Array, k: Uint8Array): void;
export declare function crypto_aead_chacha20poly1305_ietf_keygen(k: Uint8Array): void;
export declare function crypto_aead_xchacha20poly1305_ietf_encrypt(c: Uint8Array, m: Uint8Array, ad: Uint8Array | null, nsec: null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_xchacha20poly1305_ietf_decrypt(m: Uint8Array, nsec: null, c: Uint8Array, ad: Uint8Array | null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c: Uint8Array, mac: Uint8Array, m: Uint8Array, ad: Uint8Array | null, nsec: null, npub: Uint8Array, k: Uint8Array): number;
export declare function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m: Uint8Array, nsec: null, c: Uint8Array, mac: Uint8Array, ad: Uint8Array | null, npub: Uint8Array, k: Uint8Array): void;
export declare function crypto_aead_xchacha20poly1305_ietf_keygen(k: Uint8Array): void;
export declare function crypto_auth(out: Uint8Array, inp: Uint8Array, k: Uint8Array): void;
export declare function crypto_auth_verify(h: Uint8Array, inp: Uint8Array, k: Uint8Array): boolean;
export declare function crypto_auth_keygen(k: Uint8Array): void;
export declare function crypto_box_keypair(pk: Uint8Array, sk: Uint8Array): number;
export declare function crypto_box_seed_keypair(pk: Uint8Array, sk: Uint8Array, seed: Uint8Array): void;
export declare function crypto_box_easy(c: Uint8Array, m: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array): void;
export declare function crypto_box_open_easy(m: Uint8Array, c: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array): boolean;
export declare function crypto_box_detached(c: Uint8Array, mac: Uint8Array, m: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array): void;
export declare function crypto_box_open_detached(m: Uint8Array, c: Uint8Array, mac: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array): boolean;
export declare function crypto_core_ed25519_is_valid_point(p: Uint8Array): boolean;
export declare function crypto_core_ed25519_random(p: Uint8Array): void;
export declare function crypto_core_ed25519_from_uniform(p: Uint8Array, r: Uint8Array): void;
export declare function crypto_core_ed25519_add(r: Uint8Array, p: Uint8Array, q: Uint8Array): void;
export declare function crypto_core_ed25519_sub(r: Uint8Array, p: Uint8Array, q: Uint8Array): void;
export declare function crypto_core_ed25519_scalar_random(r: Uint8Array): void;
export declare function crypto_core_ed25519_scalar_reduce(r: Uint8Array, s: Uint8Array): void;
export declare function crypto_core_ed25519_scalar_invert(recip: Uint8Array, s: Uint8Array): void;
export declare function crypto_core_ed25519_scalar_negate(neg: Uint8Array, s: Uint8Array): void;
export declare function crypto_core_ed25519_scalar_complement(comp: Uint8Array, s: Uint8Array): void;
export declare function crypto_core_ed25519_scalar_add(z: Uint8Array, x: Uint8Array, y: Uint8Array): void;
export declare function crypto_core_ed25519_scalar_sub(z: Uint8Array, x: Uint8Array, y: Uint8Array): void;
export declare function crypto_core_ed25519_scalar_mul(z: Uint8Array, x: Uint8Array, y: Uint8Array): void;
export declare const crypto_generichash_STATEBYTES: any;
export declare function crypto_generichash(out: Uint8Array, inp: Uint8Array, key: Uint8Array | null): void;
export declare function crypto_generichash_init(state: Uint8Array, key: Uint8Array | null, outlen: number): void;
export declare function crypto_generichash_update(state: Uint8Array, inp: Uint8Array): void;
export declare function crypto_generichash_final(state: Uint8Array, out: Uint8Array): void;
export declare function crypto_generichash_keygen(k: Uint8Array): void;
export declare function crypto_hash(out: Uint8Array, inp: Uint8Array): void;
export declare const crypto_hash_sha256_STATEBYTES: any;
export declare function crypto_hash_sha256(out: Uint8Array, inp: Uint8Array): void;
export declare function crypto_hash_sha256_init(state: Uint8Array): void;
export declare function crypto_hash_sha256_update(state: Uint8Array, inp: Uint8Array): void;
export declare function crypto_hash_sha256_final(state: Uint8Array, out: Uint8Array): void;
export declare const crypto_hash_sha512_STATEBYTES: any;
export declare function crypto_hash_sha512(out: Uint8Array, inp: Uint8Array): void;
export declare function crypto_hash_sha512_init(state: Uint8Array): void;
export declare function crypto_hash_sha512_update(state: Uint8Array, inp: Uint8Array): void;
export declare function crypto_hash_sha512_final(state: Uint8Array, out: Uint8Array): void;
export declare function crypto_kdf_keygen(key: Uint8Array): void;
export declare function crypto_kdf_derive_from_key(subkey: Uint8Array, subkey_id: number, ctx: Uint8Array, key: Uint8Array): void;
export declare function crypto_kx_keypair(pk: Uint8Array, sk: Uint8Array): void;
export declare function crypto_kx_seed_keypair(pk: Uint8Array, sk: Uint8Array, seed: Uint8Array): void;
export declare function crypto_kx_client_session_keys(rx: Uint8Array, tx: Uint8Array, client_pk: Uint8Array, client_sk: Uint8Array, server_pk: Uint8Array): void;
export declare function crypto_kx_server_session_keys(rx: Uint8Array, tx: Uint8Array, server_pk: Uint8Array, server_sk: Uint8Array, client_pk: Uint8Array): void;
export declare const crypto_onetimeauth_STATEBYTES: any;
export declare function crypto_onetimeauth(out: Uint8Array, inp: Uint8Array, k: Uint8Array): void;
export declare function crypto_onetimeauth_verify(h: Uint8Array, inp: Uint8Array, k: Uint8Array): boolean;
export declare function crypto_onetimeauth_init(state: Uint8Array, key: Uint8Array): void;
export declare function crypto_onetimeauth_update(state: Uint8Array, inp: Uint8Array): void;
export declare function crypto_onetimeauth_final(state: Uint8Array, out: Uint8Array): void;
export declare function crypto_onetimeauth_keygen(k: Uint8Array): void;
export declare const crypto_pwhash_ALG_ARGON2I13 = 1;
export declare const crypto_pwhash_ALG_ARGON2ID13 = 2;
export declare function crypto_pwhash(out: Uint8Array, passwd: Uint8Array, salt: Uint8Array, opslimit: number, memlimit: number, alg: number): void;
export declare function crypto_pwhash_str(out: Uint8Array, passwd: Uint8Array, opslimit: number, memlimit: number): void;
export declare function crypto_pwhash_str_verify(str: Uint8Array, passwd: Uint8Array): boolean;
export declare function crypto_pwhash_str_needs_rehash(str: Uint8Array, opslimit: number, memlimit: number): boolean;
export declare function crypto_pwhash_scryptsalsa208sha256(out: Uint8Array, passwd: Uint8Array, salt: Uint8Array, opslimit: number, memlimit: number): void;
export declare function crypto_pwhash_scryptsalsa208sha256_str(out: Uint8Array, passwd: Uint8Array, opslimit: number, memlimit: number): void;
export declare function crypto_pwhash_scryptsalsa208sha256_str_verify(str: Uint8Array, passwd: Uint8Array): boolean;
export declare function crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(str: Uint8Array, opslimit: number, memlimit: number): boolean;
export declare function crypto_scalarmult_base(q: Uint8Array, n: Uint8Array): void;
export declare function crypto_scalarmult(q: Uint8Array, n: Uint8Array, p: Uint8Array): void;
export declare function crypto_scalarmult_ed25519(q: Uint8Array, n: Uint8Array, p: Uint8Array): void;
export declare function crypto_scalarmult_ed25519_base(q: Uint8Array, n: Uint8Array): void;
export declare function crypto_scalarmult_ed25519_noclamp(q: Uint8Array, n: Uint8Array, p: Uint8Array): void;
export declare function crypto_scalarmult_ed25519_base_noclamp(q: Uint8Array, n: Uint8Array): void;
export declare function crypto_secretbox_easy(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_secretbox_open_easy(m: Uint8Array, c: Uint8Array, n: Uint8Array, k: Uint8Array): boolean;
export declare function crypto_secretbox_detached(c: Uint8Array, mac: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_secretbox_open_detached(m: Uint8Array, c: Uint8Array, mac: Uint8Array, n: Uint8Array, k: Uint8Array): boolean;
export declare function crypto_secretbox_keygen(k: Uint8Array): void;
export declare const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: Buffer;
export declare const crypto_secretstream_xchacha20poly1305_TAG_PUSH: Buffer;
export declare const crypto_secretstream_xchacha20poly1305_TAG_REKEY: Buffer;
export declare const crypto_secretstream_xchacha20poly1305_TAG_FINAL: Buffer;
export declare function crypto_secretstream_xchacha20poly1305_keygen(k: Uint8Array): void;
export declare const crypto_secretstream_xchacha20poly1305_STATEBYTES: any;
export declare function crypto_secretstream_xchacha20poly1305_init_push(state: Uint8Array, header: Uint8Array, k: Uint8Array): void;
export declare function crypto_secretstream_xchacha20poly1305_push(state: Uint8Array, c: Uint8Array, m: Uint8Array, ad: Uint8Array | null, tag: Uint8Array): number;
export declare function crypto_secretstream_xchacha20poly1305_init_pull(state: Uint8Array, header: Uint8Array, k: Uint8Array): void;
export declare function crypto_secretstream_xchacha20poly1305_pull(state: Uint8Array, m: Uint8Array, tag: Uint8Array, c: Uint8Array, ad: Uint8Array | null): number;
export declare function crypto_secretstream_xchacha20poly1305_rekey(state: Uint8Array): void;
export declare function crypto_shorthash_keygen(k: Uint8Array): void;
export declare function crypto_shorthash(out: Uint8Array, inp: Uint8Array, k: Uint8Array): void;
export declare function crypto_shorthash_siphashx24(out: Uint8Array, inp: Uint8Array, k: Uint8Array): void;
export declare const crypto_sign_STATEBYTES: any;
export declare function crypto_sign_keypair(pk: Uint8Array, sk: Uint8Array): void;
export declare function crypto_sign_seed_keypair(pk: Uint8Array, sk: Uint8Array, seed: Uint8Array): void;
export declare function crypto_sign(sm: Uint8Array, m: Uint8Array, sk: Uint8Array): number;
export declare function crypto_sign_open(m: Uint8Array, sm: Uint8Array, pk: Uint8Array): boolean;
export declare function crypto_sign_detached(sig: Uint8Array, m: Uint8Array, sk: Uint8Array): void;
export declare function crypto_sign_verify_detached(sig: Uint8Array, m: Uint8Array, pk: Uint8Array): boolean;
export declare function crypto_sign_ed25519_sk_to_pk(pk: Uint8Array, sk: Uint8Array): void;
export declare function crypto_sign_ed25519_pk_to_curve25519(x25519_pk: Uint8Array, ed25519_pk: Uint8Array): void;
export declare function crypto_sign_ed25519_sk_to_curve25519(x25519_sk: Uint8Array, ed25519_sk: Uint8Array): void;
export declare function crypto_stream_chacha20(c: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_stream_chacha20_xor(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_stream_chacha20_xor_ic(c: Uint8Array, m: Uint8Array, n: Uint8Array, ic: number, k: Uint8Array): void;
export declare function crypto_stream_chacha20_ietf(c: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_stream_chacha20_ietf_xor(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_stream_chacha20_ietf_xor_ic(c: Uint8Array, m: Uint8Array, n: Uint8Array, ic: number, k: Uint8Array): void;
export declare function crypto_stream_xchacha20(c: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_stream_xchacha20_xor(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_stream_xchacha20_xor_ic(c: Uint8Array, m: Uint8Array, n: Uint8Array, ic: number, k: Uint8Array): void;
export declare function crypto_stream_salsa20(c: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_stream_salsa20_xor(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void;
export declare function crypto_stream_salsa20_xor_ic(c: Uint8Array, m: Uint8Array, n: Uint8Array, ic: number, k: Uint8Array): void;
export declare function randombytes_random(): number;
export declare function randombytes_uniform(upper_bound: number): number;
export declare function randombytes_buf(buf: Uint8Array): void;
export declare function randombytes_buf_deterministic(buf: Uint8Array, seed: Uint8Array): void;
export declare function sodium_memcmp(b1_: Uint8Array, b2_: Uint8Array): boolean;
export declare function sodium_increment(n: Uint8Array): void;
export declare function sodium_add(a: Uint8Array, b: Uint8Array): void;
export declare function sodium_sub(a: Uint8Array, b: Uint8Array): void;
export declare function sodium_compare(b1_: Uint8Array, b2_: Uint8Array): number;
export declare function sodium_is_zero(n: Uint8Array): boolean;
export declare function sodium_pad(buf: Uint8Array, unpaddedLength: number, blocksize: number): number;
export declare function sodium_unpad(buf: Uint8Array, paddedLength: number, blocksize: number): number;
export declare function crypto_box_seal(c: Uint8Array, m: Uint8Array, pk: Uint8Array): void;
export declare function crypto_box_seal_open(m: Uint8Array, c: Uint8Array, pk: Uint8Array, sk: Uint8Array): boolean;