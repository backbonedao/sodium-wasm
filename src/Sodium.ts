import { Buffer } from "buffer"
import { WASM } from "./wasm"

let Sodium: any
let BUFFER: Buffer
let HEAPU8: Uint8Array
let HEAPF64: Float64Array
let HEAP32: Int32Array
let getRandomValue: () => number

const ASM_CONSTS: Record<number, Function> = {
  35736: function () {
    return getRandomValue?.()
  },
  35772: function () {
    if (getRandomValue === undefined) {
      try {
        const window_ = "object" === typeof window ? window : self
        const crypto_ = typeof window_.crypto !== "undefined" ? window_.crypto : (window_ as any).msCrypto
        const randomValuesStandard = function () {
          var buf = new Uint32Array(1)
          crypto_.getRandomValues(buf)
          return buf[0] >>> 0
        }
        randomValuesStandard()
        getRandomValue = randomValuesStandard
      } catch (e) {
        try {
          const crypto = require("crypto")
          const randomValueNodeJS = function () {
            var buf = crypto["randomBytes"](4)
            return ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0
          }
          randomValueNodeJS()
          getRandomValue = randomValueNodeJS
        } catch (e) {
          throw new Error("No secure random number generator found")
        }
      }
    }
  },
}

function readAsmConstArgs(sigPtr: number, buf: number): number[] {
  const readAsmConstArgsArray = []
  let ch
  buf >>= 2
  while ((ch = HEAPU8[sigPtr++])) {
    var readAsmConstArgsDouble = ch < 105
    if (readAsmConstArgsDouble && buf & 1) buf++
    readAsmConstArgsArray.push(
      // @ts-ignore
      readAsmConstArgsDouble ? HEAPF64[buf++ >> 1] : HEAP32[buf]
    )
    ++buf
  }
  return readAsmConstArgsArray
}

function emscripten_asm_const_int(code: number, sigPtr: number, argbuf: number): number {
  const args = readAsmConstArgs(sigPtr, argbuf)
  return ASM_CONSTS[code].apply(null, args)
}

function emscripten_notify_memory_growth() {
  const memory: WebAssembly.Memory = Sodium.memory as WebAssembly.Memory
  BUFFER = Buffer.from(memory.buffer)
  HEAPU8 = new Uint8Array(memory.buffer)
  HEAPF64 = new Float64Array(memory.buffer)
  HEAP32 = new Int32Array(memory.buffer)
}

function proc_exit(what: string) {
  throw new WebAssembly.RuntimeError(what)
}

export let crypto_generichash_STATEBYTES: number
export let crypto_hash_sha256_STATEBYTES: number
export let crypto_hash_sha512_STATEBYTES: number
export let crypto_onetimeauth_STATEBYTES: number
export let crypto_pwhash_ALG_ARGON2I13: number
export let crypto_pwhash_ALG_ARGON2ID13: number
export let crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: Buffer
export let crypto_secretstream_xchacha20poly1305_TAG_PUSH: Buffer
export let crypto_secretstream_xchacha20poly1305_TAG_REKEY: Buffer
export let crypto_secretstream_xchacha20poly1305_TAG_FINAL: Buffer
export let crypto_secretstream_xchacha20poly1305_STATEBYTES: Buffer
export let crypto_sign_STATEBYTES: number

export async function init() {
  // const mod = new WebAssembly.Module(Buffer.from(WASM, "base64"));
  const mod = await WebAssembly.compile(Buffer.from(WASM, "base64"))
  // const instance = new WebAssembly.Instance(mod, {
  const instance = await WebAssembly.instantiate(mod, {
    env: { emscripten_asm_const_int, emscripten_notify_memory_growth },
    wasi_snapshot_preview1: { proc_exit },
  })
  Sodium = instance.exports
  emscripten_notify_memory_growth()
  if (Sodium.sodium_init() < 0) {
    throw new Error("Failed to initialize Sodium")
  }

  crypto_generichash_STATEBYTES = Sodium.crypto_generichash_statebytes()

  crypto_hash_sha256_STATEBYTES = Sodium.crypto_hash_sha256_statebytes()

  crypto_hash_sha512_STATEBYTES = Sodium.crypto_hash_sha512_statebytes()

  crypto_onetimeauth_STATEBYTES = Sodium.crypto_onetimeauth_statebytes()

  crypto_pwhash_ALG_ARGON2I13 = 1
  crypto_pwhash_ALG_ARGON2ID13 = 2

  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = Buffer.from([
    Sodium.crypto_secretstream_xchacha20poly1305_tag_message(),
  ])
  crypto_secretstream_xchacha20poly1305_TAG_PUSH = Buffer.from([
    Sodium.crypto_secretstream_xchacha20poly1305_tag_push(),
  ])

  crypto_secretstream_xchacha20poly1305_TAG_REKEY = Buffer.from([
    Sodium.crypto_secretstream_xchacha20poly1305_tag_rekey(),
  ])

  crypto_secretstream_xchacha20poly1305_TAG_FINAL = Buffer.from([
    Sodium.crypto_secretstream_xchacha20poly1305_tag_final(),
  ])

  crypto_secretstream_xchacha20poly1305_STATEBYTES = Sodium.crypto_secretstream_xchacha20poly1305_statebytes()

  crypto_sign_STATEBYTES = Sodium.crypto_sign_statebytes()
}

function malloc(buf: Uint8Array): number {
  return Sodium.malloc(buf.byteLength)
}

function mallocAndCopy(buf: Uint8Array): number {
  const ptr = Sodium.malloc(buf.byteLength)
  BUFFER.set(buf, ptr)
  return ptr
}

function free(ptr: number): void {
  Sodium.free(ptr)
}

function copyAndFree(ptr: number, buf: Uint8Array): void {
  const target = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength)
  BUFFER.copy(target, 0, ptr, ptr + buf.byteLength)
  Sodium.free(ptr)
}

export function crypto_aead_chacha20poly1305_encrypt(
  c: Uint8Array,
  m: Uint8Array,
  ad: Uint8Array | null,
  nsec: null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const cptr = malloc(c)
  const clenptr = Sodium.malloc(8)
  const mptr = mallocAndCopy(m)
  const adptr: any = ad === null ? ad : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_aead_chacha20poly1305_encrypt(
    cptr,
    clenptr,
    mptr,
    BigInt(m.byteLength),
    adptr,
    BigInt(adlen),
    nsec,
    npubptr,
    kptr
  )
  const clen = Buffer.alloc(8)
  copyAndFree(clenptr, clen)
  copyAndFree(cptr, c)
  free(mptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  return Number(clen.readBigUInt64LE())
}

export function crypto_aead_chacha20poly1305_decrypt(
  m: Uint8Array,
  nsec: null,
  c: Uint8Array,
  ad: Uint8Array | null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const mptr = malloc(m)
  const mlenptr = Sodium.malloc(8)
  const cptr = mallocAndCopy(c)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_aead_chacha20poly1305_decrypt(
    mptr,
    mlenptr,
    nsec,
    cptr,
    BigInt(c.byteLength),
    adptr,
    BigInt(adlen),
    npubptr,
    kptr
  )
  const mlen = Buffer.alloc(8)
  copyAndFree(mlenptr, mlen)
  copyAndFree(mptr, m)
  free(cptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  if (ret < 0) {
    throw new Error("Invalid mac")
  }
  return Number(mlen.readBigUInt64LE())
}

export function crypto_aead_chacha20poly1305_encrypt_detached(
  c: Uint8Array,
  mac: Uint8Array,
  m: Uint8Array,
  ad: Uint8Array | null,
  nsec: null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const cptr = malloc(c)
  const clenptr = Sodium.malloc(8)
  const macptr = malloc(mac)
  const mptr = mallocAndCopy(m)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_aead_chacha20poly1305_encrypt_detached(
    cptr,
    macptr,
    clenptr,
    mptr,
    BigInt(m.byteLength),
    adptr,
    BigInt(adlen),
    nsec,
    npubptr,
    kptr
  )
  const clen = Buffer.alloc(8)
  copyAndFree(clenptr, clen)
  copyAndFree(cptr, c)
  copyAndFree(macptr, mac)
  free(mptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  return Number(clen.readBigUInt64LE())
}

export function crypto_aead_chacha20poly1305_decrypt_detached(
  m: Uint8Array,
  nsec: null,
  c: Uint8Array,
  mac: Uint8Array,
  ad: Uint8Array | null,
  npub: Uint8Array,
  k: Uint8Array
): void {
  const mptr = malloc(m)
  const cptr = mallocAndCopy(c)
  const macptr = mallocAndCopy(mac)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_aead_chacha20poly1305_decrypt_detached(
    mptr,
    nsec,
    cptr,
    BigInt(c.byteLength),
    macptr,
    adptr,
    BigInt(adlen),
    npubptr,
    kptr
  )
  copyAndFree(mptr, m)
  free(cptr)
  free(macptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  if (ret < 0) {
    throw new Error("Invalid mac")
  }
}

export function crypto_aead_chacha20poly1305_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_aead_chacha20poly1305_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_aead_chacha20poly1305_ietf_encrypt(
  c: Uint8Array,
  m: Uint8Array,
  ad: Uint8Array | null,
  nsec: null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const cptr = malloc(c)
  const clenptr = Sodium.malloc(8)
  const mptr = mallocAndCopy(m)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    cptr,
    clenptr,
    mptr,
    BigInt(m.byteLength),
    adptr,
    BigInt(adlen),
    nsec,
    npubptr,
    kptr
  )
  const clen = Buffer.alloc(8)
  copyAndFree(clenptr, clen)
  copyAndFree(cptr, c)
  free(mptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  return Number(clen.readBigUInt64LE())
}

export function crypto_aead_chacha20poly1305_ietf_decrypt(
  m: Uint8Array,
  nsec: null,
  c: Uint8Array,
  ad: Uint8Array | null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const mptr = malloc(m)
  const mlenptr = Sodium.malloc(8)
  const cptr = mallocAndCopy(c)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    mptr,
    mlenptr,
    nsec,
    cptr,
    BigInt(c.byteLength),
    adptr,
    BigInt(adlen),
    npubptr,
    kptr
  )
  const mlen = Buffer.alloc(8)
  copyAndFree(mlenptr, mlen)
  copyAndFree(mptr, m)
  free(cptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  if (ret < 0) {
    throw new Error("Invalid mac")
  }
  return Number(mlen.readBigUInt64LE())
}

export function crypto_aead_chacha20poly1305_ietf_encrypt_detached(
  c: Uint8Array,
  mac: Uint8Array,
  m: Uint8Array,
  ad: Uint8Array | null,
  nsec: null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const cptr = malloc(c)
  const clenptr = Sodium.malloc(8)
  const macptr = malloc(mac)
  const mptr = mallocAndCopy(m)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(
    cptr,
    macptr,
    clenptr,
    mptr,
    BigInt(m.byteLength),
    adptr,
    BigInt(adlen),
    nsec,
    npubptr,
    kptr
  )
  const clen = Buffer.alloc(8)
  copyAndFree(clenptr, clen)
  copyAndFree(cptr, c)
  copyAndFree(macptr, mac)
  free(mptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  return Number(clen.readBigUInt64LE())
}

export function crypto_aead_chacha20poly1305_ietf_decrypt_detached(
  m: Uint8Array,
  nsec: null,
  c: Uint8Array,
  mac: Uint8Array,
  ad: Uint8Array | null,
  npub: Uint8Array,
  k: Uint8Array
): void {
  const mptr = malloc(m)
  const cptr = mallocAndCopy(c)
  const macptr = mallocAndCopy(mac)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
    mptr,
    nsec,
    cptr,
    BigInt(c.byteLength),
    macptr,
    adptr,
    BigInt(adlen),
    npubptr,
    kptr
  )
  copyAndFree(mptr, m)
  free(cptr)
  free(macptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  if (ret < 0) {
    throw new Error("Invalid mac")
  }
}

export function crypto_aead_chacha20poly1305_ietf_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_aead_chacha20poly1305_ietf_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  c: Uint8Array,
  m: Uint8Array,
  ad: Uint8Array | null,
  nsec: null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const cptr = malloc(c)
  const clenptr = Sodium.malloc(8)
  const mptr = mallocAndCopy(m)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    cptr,
    clenptr,
    mptr,
    BigInt(m.byteLength),
    adptr,
    BigInt(adlen),
    nsec,
    npubptr,
    kptr
  )
  const clen = Buffer.alloc(8)
  copyAndFree(clenptr, clen)
  copyAndFree(cptr, c)
  free(mptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  return Number(clen.readBigUInt64LE())
}

export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  m: Uint8Array,
  nsec: null,
  c: Uint8Array,
  ad: Uint8Array | null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const mptr = malloc(m)
  const mlenptr = Sodium.malloc(8)
  const cptr = mallocAndCopy(c)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    mptr,
    mlenptr,
    nsec,
    cptr,
    BigInt(c.byteLength),
    adptr,
    BigInt(adlen),
    npubptr,
    kptr
  )
  const mlen = Buffer.alloc(8)
  copyAndFree(mlenptr, mlen)
  copyAndFree(mptr, m)
  free(cptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  if (ret < 0) {
    throw new Error("Invalid mac")
  }
  return Number(mlen.readBigUInt64LE())
}

export function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  c: Uint8Array,
  mac: Uint8Array,
  m: Uint8Array,
  ad: Uint8Array | null,
  nsec: null,
  npub: Uint8Array,
  k: Uint8Array
): number {
  const cptr = malloc(c)
  const macptr = malloc(mac)
  const maclenptr = Sodium.malloc(8)
  const mptr = mallocAndCopy(m)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
    cptr,
    macptr,
    maclenptr,
    mptr,
    BigInt(m.byteLength),
    adptr,
    BigInt(adlen),
    nsec,
    npubptr,
    kptr
  )
  const maclen = Buffer.alloc(8)
  copyAndFree(maclenptr, maclen)
  copyAndFree(cptr, c)
  copyAndFree(macptr, mac)
  free(mptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  return Number(maclen.readBigUInt64LE())
}

export function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
  m: Uint8Array,
  nsec: null,
  c: Uint8Array,
  mac: Uint8Array,
  ad: Uint8Array | null,
  npub: Uint8Array,
  k: Uint8Array
): void {
  const mptr = malloc(m)
  const cptr = mallocAndCopy(c)
  const macptr = mallocAndCopy(mac)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const npubptr = mallocAndCopy(npub)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
    mptr,
    nsec,
    cptr,
    BigInt(c.byteLength),
    macptr,
    adptr,
    BigInt(adlen),
    npubptr,
    kptr
  )
  copyAndFree(mptr, m)
  free(cptr)
  free(macptr)
  free(npubptr)
  free(kptr)
  if (adptr) {
    free(adptr)
  }
  if (ret < 0) {
    throw new Error("Invalid mac")
  }
}

export function crypto_aead_xchacha20poly1305_ietf_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_aead_xchacha20poly1305_ietf_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_auth(out: Uint8Array, inp: Uint8Array, k: Uint8Array): void {
  const outptr = malloc(out)
  const inpptr = mallocAndCopy(inp)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_auth(outptr, inpptr, BigInt(inp.byteLength), kptr)
  copyAndFree(outptr, out)
  free(inpptr)
  free(kptr)
}

export function crypto_auth_verify(h: Uint8Array, inp: Uint8Array, k: Uint8Array): boolean {
  const hptr = mallocAndCopy(h)
  const inpptr = mallocAndCopy(inp)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_auth_verify(hptr, inpptr, BigInt(inp.byteLength), kptr)
  free(hptr)
  free(inpptr)
  free(kptr)
  return !!(ret + 1)
}

export function crypto_auth_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_auth_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_box_keypair(pk: Uint8Array, sk: Uint8Array): number {
  const pkptr = malloc(pk)
  const skptr = malloc(sk)
  const ret = Sodium.crypto_box_keypair(pkptr, skptr)
  copyAndFree(pkptr, pk)
  copyAndFree(skptr, sk)
  return ret
}

export function crypto_box_seed_keypair(pk: Uint8Array, sk: Uint8Array, seed: Uint8Array): void {
  const pkptr = malloc(pk)
  const skptr = malloc(sk)
  const seedptr = mallocAndCopy(seed)
  const ret = Sodium.crypto_box_seed_keypair(pkptr, skptr, seedptr)
  copyAndFree(pkptr, pk)
  copyAndFree(skptr, sk)
  free(seedptr)
  if (ret < 0) {
    throw new Error("Invalid data")
  }
}

export function crypto_box_easy(c: Uint8Array, m: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const pkptr = mallocAndCopy(pk)
  const skptr = mallocAndCopy(sk)
  const ret = Sodium.crypto_box_easy(cptr, mptr, BigInt(m.byteLength), nptr, pkptr, skptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(pkptr)
  free(skptr)
  if (ret < 0) {
    throw new Error("Invalid data")
  }
}

export function crypto_box_open_easy(
  m: Uint8Array,
  c: Uint8Array,
  n: Uint8Array,
  pk: Uint8Array,
  sk: Uint8Array
): boolean {
  const mptr = malloc(m)
  const cptr = mallocAndCopy(c)
  const nptr = mallocAndCopy(n)
  const pkptr = mallocAndCopy(pk)
  const skptr = mallocAndCopy(sk)
  const ret = Sodium.crypto_box_open_easy(mptr, cptr, BigInt(c.byteLength), nptr, pkptr, skptr)
  copyAndFree(mptr, m)
  free(cptr)
  free(nptr)
  free(pkptr)
  free(skptr)
  return !!(ret + 1)
}

export function crypto_box_detached(
  c: Uint8Array,
  mac: Uint8Array,
  m: Uint8Array,
  n: Uint8Array,
  pk: Uint8Array,
  sk: Uint8Array
): void {
  const cptr = malloc(c)
  const macptr = malloc(mac)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const pkptr = mallocAndCopy(pk)
  const skptr = mallocAndCopy(sk)
  const ret = Sodium.crypto_box_detached(cptr, macptr, mptr, BigInt(m.byteLength), nptr, pkptr, skptr)
  copyAndFree(cptr, c)
  copyAndFree(macptr, mac)
  free(mptr)
  free(nptr)
  free(pkptr)
  free(skptr)
  if (ret < 0) {
    throw new Error("Invalid data")
  }
}

export function crypto_box_open_detached(
  m: Uint8Array,
  c: Uint8Array,
  mac: Uint8Array,
  n: Uint8Array,
  pk: Uint8Array,
  sk: Uint8Array
): boolean {
  const mptr = malloc(m)
  const cptr = mallocAndCopy(c)
  const macptr = mallocAndCopy(mac)
  const nptr = mallocAndCopy(n)
  const pkptr = mallocAndCopy(pk)
  const skptr = mallocAndCopy(sk)
  const ret = Sodium.crypto_box_open_detached(mptr, cptr, macptr, BigInt(c.byteLength), nptr, pkptr, skptr)
  copyAndFree(mptr, m)
  free(cptr)
  free(macptr)
  free(nptr)
  free(pkptr)
  free(skptr)
  return !!(ret + 1)
}

export function crypto_core_ed25519_is_valid_point(p: Uint8Array): boolean {
  const pptr = mallocAndCopy(p)
  const ret = Sodium.crypto_core_ed25519_is_valid_point(pptr)
  free(pptr)
  return !!ret
}

export function crypto_core_ed25519_random(p: Uint8Array): void {
  const pptr = malloc(p)
  Sodium.crypto_core_ed25519_random(pptr)
  copyAndFree(pptr, p)
}

export function crypto_core_ed25519_from_uniform(p: Uint8Array, r: Uint8Array): void {
  const pptr = malloc(p)
  const rptr = mallocAndCopy(r)
  const ret = Sodium.crypto_core_ed25519_from_uniform(pptr, rptr)
  copyAndFree(pptr, p)
  free(rptr)
  if (ret < 0) {
    throw new Error("Invalid data")
  }
}

export function crypto_core_ed25519_add(r: Uint8Array, p: Uint8Array, q: Uint8Array): void {
  const rptr = malloc(r)
  const pptr = mallocAndCopy(p)
  const qptr = mallocAndCopy(q)
  const ret = Sodium.crypto_core_ed25519_add(rptr, pptr, qptr)
  copyAndFree(rptr, r)
  free(pptr)
  free(qptr)
  if (ret < 0) {
    throw new Error("Not a valid curve point")
  }
}

export function crypto_core_ed25519_sub(r: Uint8Array, p: Uint8Array, q: Uint8Array): void {
  const rptr = malloc(r)
  const pptr = mallocAndCopy(p)
  const qptr = mallocAndCopy(q)
  const ret = Sodium.crypto_core_ed25519_sub(rptr, pptr, qptr)
  copyAndFree(rptr, r)
  free(pptr)
  free(qptr)
  if (ret < 0) {
    throw new Error("Not a valid curve point")
  }
}

export function crypto_core_ed25519_scalar_random(r: Uint8Array): void {
  const rptr = malloc(r)
  Sodium.crypto_core_ed25519_scalar_random(rptr)
  copyAndFree(rptr, r)
}

export function crypto_core_ed25519_scalar_reduce(r: Uint8Array, s: Uint8Array): void {
  const rptr = malloc(r)
  const sptr = mallocAndCopy(s)
  Sodium.crypto_core_ed25519_scalar_reduce(rptr, sptr)
  copyAndFree(rptr, r)
  free(sptr)
}

export function crypto_core_ed25519_scalar_invert(recip: Uint8Array, s: Uint8Array): void {
  const recipptr = malloc(recip)
  const sptr = mallocAndCopy(s)
  const ret = Sodium.crypto_core_ed25519_scalar_invert(recipptr, sptr)
  copyAndFree(recipptr, recip)
  free(sptr)
  if (ret < 0) {
    throw new Error("Invalid data")
  }
}

export function crypto_core_ed25519_scalar_negate(neg: Uint8Array, s: Uint8Array): void {
  const negptr = malloc(neg)
  const sptr = mallocAndCopy(s)
  Sodium.crypto_core_ed25519_scalar_negate(negptr, sptr)
  copyAndFree(negptr, neg)
  free(sptr)
}

export function crypto_core_ed25519_scalar_complement(comp: Uint8Array, s: Uint8Array): void {
  const compptr = malloc(comp)
  const sptr = mallocAndCopy(s)
  Sodium.crypto_core_ed25519_scalar_complement(compptr, sptr)
  copyAndFree(compptr, comp)
  free(sptr)
}

export function crypto_core_ed25519_scalar_add(z: Uint8Array, x: Uint8Array, y: Uint8Array): void {
  const zptr = malloc(z)
  const xptr = mallocAndCopy(x)
  const yptr = mallocAndCopy(y)
  Sodium.crypto_core_ed25519_scalar_add(zptr, xptr, yptr)
  copyAndFree(zptr, z)
  free(xptr)
  free(yptr)
}

export function crypto_core_ed25519_scalar_sub(z: Uint8Array, x: Uint8Array, y: Uint8Array): void {
  const zptr = malloc(z)
  const xptr = mallocAndCopy(x)
  const yptr = mallocAndCopy(y)
  Sodium.crypto_core_ed25519_scalar_sub(zptr, xptr, yptr)
  copyAndFree(zptr, z)
  free(xptr)
  free(yptr)
}

export function crypto_core_ed25519_scalar_mul(z: Uint8Array, x: Uint8Array, y: Uint8Array): void {
  const zptr = malloc(z)
  const xptr = mallocAndCopy(x)
  const yptr = mallocAndCopy(y)
  Sodium.crypto_core_ed25519_scalar_mul(zptr, xptr, yptr)
  copyAndFree(zptr, z)
  free(xptr)
  free(yptr)
}

export function crypto_generichash(out: Uint8Array, inp: Uint8Array, key: Uint8Array | null): void {
  const outptr = malloc(out)
  const inpptr = mallocAndCopy(inp)
  const keyptr = key === null || typeof key === "undefined" ? null : mallocAndCopy(key)
  const keylen = key === null || typeof key === "undefined" ? 0 : key.byteLength
  const ret = Sodium.crypto_generichash(outptr, out.byteLength, inpptr, BigInt(inp.byteLength), keyptr, keylen)
  copyAndFree(outptr, out)
  free(inpptr)
  if (keyptr) {
    free(keyptr)
  }
  if (ret < 0) {
    throw new Error("Invalid data")
  }
}

export function crypto_generichash_init(state: Uint8Array, key: Uint8Array | null, outlen: number): void {
  const stateptr = malloc(state)
  const keyptr = key === null || typeof key === "undefined" ? null : mallocAndCopy(key)
  const keylen = key === null || typeof key === "undefined" ? 0 : key.byteLength
  Sodium.crypto_generichash_init(stateptr, keyptr, keylen, outlen)
  copyAndFree(stateptr, state)
  if (keyptr) {
    free(keyptr)
  }
}

export function crypto_generichash_update(state: Uint8Array, inp: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  const inpptr = mallocAndCopy(inp)
  Sodium.crypto_generichash_update(stateptr, inpptr, BigInt(inp.byteLength))
  copyAndFree(stateptr, state)
  free(inpptr)
}

export function crypto_generichash_final(state: Uint8Array, out: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  const outptr = malloc(out)
  Sodium.crypto_generichash_final(stateptr, outptr, out.byteLength)
  copyAndFree(stateptr, state)
  copyAndFree(outptr, out)
}

export function crypto_generichash_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_generichash_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_hash(out: Uint8Array, inp: Uint8Array): void {
  const outptr = malloc(out)
  const inpptr = mallocAndCopy(inp)
  Sodium.crypto_hash(outptr, inpptr, BigInt(inp.byteLength))
  copyAndFree(outptr, out)
  free(inpptr)
}

export function crypto_hash_sha256(out: Uint8Array, inp: Uint8Array): void {
  const outptr = malloc(out)
  const inpptr = mallocAndCopy(inp)
  Sodium.crypto_hash_sha256(outptr, inpptr, BigInt(inp.byteLength))
  copyAndFree(outptr, out)
  free(inpptr)
}

export function crypto_hash_sha256_init(state: Uint8Array): void {
  const stateptr = malloc(state)
  Sodium.crypto_hash_sha256_init(stateptr)
  copyAndFree(stateptr, state)
}

export function crypto_hash_sha256_update(state: Uint8Array, inp: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  const inpptr = mallocAndCopy(inp)
  Sodium.crypto_hash_sha256_update(stateptr, inpptr, BigInt(inp.byteLength))
  copyAndFree(stateptr, state)
  free(inpptr)
}

export function crypto_hash_sha256_final(state: Uint8Array, out: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  const outptr = malloc(out)
  Sodium.crypto_hash_sha256_final(stateptr, outptr)
  copyAndFree(stateptr, state)
  copyAndFree(outptr, out)
}

export function crypto_hash_sha512(out: Uint8Array, inp: Uint8Array): void {
  const outptr = malloc(out)
  const inpptr = mallocAndCopy(inp)
  Sodium.crypto_hash_sha512(outptr, inpptr, BigInt(inp.byteLength))
  copyAndFree(outptr, out)
  free(inpptr)
}

export function crypto_hash_sha512_init(state: Uint8Array): void {
  const stateptr = malloc(state)
  Sodium.crypto_hash_sha512_init(stateptr)
  copyAndFree(stateptr, state)
}

export function crypto_hash_sha512_update(state: Uint8Array, inp: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  const inpptr = mallocAndCopy(inp)
  Sodium.crypto_hash_sha512_update(stateptr, inpptr, BigInt(inp.byteLength))
  copyAndFree(stateptr, state)
  free(inpptr)
}

export function crypto_hash_sha512_final(state: Uint8Array, out: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  const outptr = malloc(out)
  Sodium.crypto_hash_sha512_final(stateptr, outptr)
  copyAndFree(stateptr, state)
  copyAndFree(outptr, out)
}

export function crypto_kdf_keygen(key: Uint8Array): void {
  const keyptr = malloc(key)
  Sodium.crypto_kdf_keygen(keyptr)
  copyAndFree(keyptr, key)
}

export function crypto_kdf_derive_from_key(
  subkey: Uint8Array,
  subkey_id: number,
  ctx: Uint8Array,
  key: Uint8Array
): void {
  const subkeyptr = malloc(subkey)
  const ctxptr = mallocAndCopy(ctx)
  const keyptr = mallocAndCopy(key)
  Sodium.crypto_kdf_derive_from_key(subkeyptr, subkey.byteLength, BigInt(subkey_id), ctxptr, keyptr)
  copyAndFree(subkeyptr, subkey)
  free(ctxptr)
  free(keyptr)
}

export function crypto_kx_keypair(pk: Uint8Array, sk: Uint8Array): void {
  const pkptr = malloc(pk)
  const skptr = malloc(sk)
  Sodium.crypto_kx_keypair(pkptr, skptr)
  copyAndFree(pkptr, pk)
  copyAndFree(skptr, sk)
}

export function crypto_kx_seed_keypair(pk: Uint8Array, sk: Uint8Array, seed: Uint8Array): void {
  const pkptr = malloc(pk)
  const skptr = malloc(sk)
  const seedptr = mallocAndCopy(seed)
  Sodium.crypto_kx_seed_keypair(pkptr, skptr, seedptr)
  copyAndFree(pkptr, pk)
  copyAndFree(skptr, sk)
  free(seedptr)
}

export function crypto_kx_client_session_keys(
  rx: Uint8Array,
  tx: Uint8Array,
  client_pk: Uint8Array,
  client_sk: Uint8Array,
  server_pk: Uint8Array
): void {
  const rxptr = rx === null ? null : malloc(rx)
  const txptr = tx === null ? null : malloc(tx)
  const cpkptr = mallocAndCopy(client_pk)
  const cskptr = mallocAndCopy(client_sk)
  const spkptr = mallocAndCopy(server_pk)
  Sodium.crypto_kx_client_session_keys(rxptr, txptr, cpkptr, cskptr, spkptr)
  if (rx && rxptr) copyAndFree(rxptr, rx)
  if (tx && txptr) copyAndFree(txptr, tx)
  free(cpkptr)
  free(cskptr)
  free(spkptr)
}

export function crypto_kx_server_session_keys(
  rx: Uint8Array,
  tx: Uint8Array,
  server_pk: Uint8Array,
  server_sk: Uint8Array,
  client_pk: Uint8Array
): void {
  const rxptr = rx === null ? null : malloc(rx)
  const txptr = tx === null ? null : malloc(tx)
  const spkptr = mallocAndCopy(server_pk)
  const sskptr = mallocAndCopy(server_sk)
  const cpkptr = mallocAndCopy(client_pk)
  Sodium.crypto_kx_server_session_keys(rxptr, txptr, spkptr, sskptr, cpkptr)
  if (rx && rxptr) copyAndFree(rxptr, rx)
  if (tx && txptr) copyAndFree(txptr, tx)
  free(spkptr)
  free(sskptr)
  free(cpkptr)
}

export function crypto_onetimeauth(out: Uint8Array, inp: Uint8Array, k: Uint8Array): void {
  const outptr = malloc(out)
  const inpptr = mallocAndCopy(inp)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_onetimeauth(outptr, inpptr, BigInt(inp.byteLength), kptr)
  copyAndFree(outptr, out)
  free(inpptr)
  free(kptr)
}

export function crypto_onetimeauth_verify(h: Uint8Array, inp: Uint8Array, k: Uint8Array): boolean {
  const hptr = mallocAndCopy(h)
  const inpptr = mallocAndCopy(inp)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_onetimeauth_verify(hptr, inpptr, BigInt(inp.byteLength), kptr)
  free(hptr)
  free(inpptr)
  free(kptr)
  return !!(ret + 1)
}

export function crypto_onetimeauth_init(state: Uint8Array, key: Uint8Array): void {
  const stateptr = malloc(state)
  const keyptr = mallocAndCopy(key)
  Sodium.crypto_onetimeauth_init(stateptr, keyptr)
  copyAndFree(stateptr, state)
  free(keyptr)
}

export function crypto_onetimeauth_update(state: Uint8Array, inp: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  const inpptr = mallocAndCopy(inp)
  Sodium.crypto_onetimeauth_update(stateptr, inpptr, BigInt(inp.byteLength))
  copyAndFree(stateptr, state)
  free(inpptr)
}

export function crypto_onetimeauth_final(state: Uint8Array, out: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  const outptr = malloc(out)
  Sodium.crypto_onetimeauth_final(stateptr, outptr)
  copyAndFree(stateptr, state)
  copyAndFree(outptr, out)
}

export function crypto_onetimeauth_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_onetimeauth_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_pwhash(
  out: Uint8Array,
  passwd: Uint8Array,
  salt: Uint8Array,
  opslimit: number,
  memlimit: number,
  alg: number
): void {
  const outptr = malloc(out)
  const passwdptr = mallocAndCopy(passwd)
  const saltptr = mallocAndCopy(salt)
  Sodium.crypto_pwhash(
    outptr,
    BigInt(out.byteLength),
    passwdptr,
    BigInt(passwd.byteLength),
    saltptr,
    BigInt(opslimit),
    memlimit,
    alg
  )
  copyAndFree(outptr, out)
  free(passwdptr)
  free(saltptr)
}

export function crypto_pwhash_str(out: Uint8Array, passwd: Uint8Array, opslimit: number, memlimit: number): void {
  const outptr = malloc(out)
  const passwdptr = mallocAndCopy(passwd)
  Sodium.crypto_pwhash_str(outptr, passwdptr, BigInt(passwd.byteLength), BigInt(opslimit), memlimit)
  copyAndFree(outptr, out)
  free(passwdptr)
}

export function crypto_pwhash_str_verify(str: Uint8Array, passwd: Uint8Array): boolean {
  const strptr = mallocAndCopy(str)
  const passwdptr = mallocAndCopy(passwd)
  const ret = Sodium.crypto_pwhash_str_verify(strptr, passwdptr, BigInt(passwd.byteLength))
  free(strptr)
  free(passwdptr)
  return !!(ret + 1)
}

export function crypto_pwhash_str_needs_rehash(str: Uint8Array, opslimit: number, memlimit: number): boolean {
  const strptr = mallocAndCopy(str)
  const ret = Sodium.crypto_pwhash_str_needs_rehash(strptr, BigInt(opslimit), memlimit)
  free(strptr)
  return !!ret
}

export function crypto_pwhash_scryptsalsa208sha256(
  out: Uint8Array,
  passwd: Uint8Array,
  salt: Uint8Array,
  opslimit: number,
  memlimit: number
): void {
  const outptr = malloc(out)
  const passwdptr = mallocAndCopy(passwd)
  const saltptr = mallocAndCopy(salt)
  Sodium.crypto_pwhash_scryptsalsa208sha256(
    outptr,
    BigInt(out.byteLength),
    passwdptr,
    BigInt(passwd.byteLength),
    saltptr,
    BigInt(opslimit),
    memlimit
  )
  copyAndFree(outptr, out)
  free(passwdptr)
  free(saltptr)
}

export function crypto_pwhash_scryptsalsa208sha256_str(
  out: Uint8Array,
  passwd: Uint8Array,
  opslimit: number,
  memlimit: number
): void {
  const outptr = malloc(out)
  const passwdptr = mallocAndCopy(passwd)
  Sodium.crypto_pwhash_scryptsalsa208sha256_str(
    outptr,
    passwdptr,
    BigInt(passwd.byteLength),
    BigInt(opslimit),
    memlimit
  )
  copyAndFree(outptr, out)
  free(passwdptr)
}

export function crypto_pwhash_scryptsalsa208sha256_str_verify(str: Uint8Array, passwd: Uint8Array): boolean {
  const strptr = mallocAndCopy(str)
  const passwdptr = mallocAndCopy(passwd)
  const ret = Sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(strptr, passwdptr, BigInt(passwd.byteLength))
  free(strptr)
  free(passwdptr)
  return !!(ret + 1)
}

export function crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(
  str: Uint8Array,
  opslimit: number,
  memlimit: number
): boolean {
  const strptr = mallocAndCopy(str)
  const ret = Sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(strptr, BigInt(opslimit), memlimit)
  free(strptr)
  return !!ret
}

export function crypto_scalarmult_base(q: Uint8Array, n: Uint8Array): void {
  const qptr = malloc(q)
  const nptr = mallocAndCopy(n)
  Sodium.crypto_scalarmult_base(qptr, nptr)
  copyAndFree(qptr, q)
  free(nptr)
}

export function crypto_scalarmult(q: Uint8Array, n: Uint8Array, p: Uint8Array): void {
  const qptr = malloc(q)
  const nptr = mallocAndCopy(n)
  const pptr = mallocAndCopy(p)
  Sodium.crypto_scalarmult(qptr, nptr, pptr)
  copyAndFree(qptr, q)
  free(nptr)
  free(pptr)
}

export function crypto_scalarmult_ed25519(q: Uint8Array, n: Uint8Array, p: Uint8Array): void {
  const qptr = malloc(q)
  const nptr = mallocAndCopy(n)
  const pptr = mallocAndCopy(p)
  Sodium.crypto_scalarmult_ed25519(qptr, nptr, pptr)
  copyAndFree(qptr, q)
  free(nptr)
  free(pptr)
}

export function crypto_scalarmult_ed25519_base(q: Uint8Array, n: Uint8Array): void {
  const qptr = malloc(q)
  const nptr = mallocAndCopy(n)
  Sodium.crypto_scalarmult_ed25519_base(qptr, nptr)
  copyAndFree(qptr, q)
  free(nptr)
}

export function crypto_scalarmult_ed25519_noclamp(q: Uint8Array, n: Uint8Array, p: Uint8Array): void {
  const qptr = malloc(q)
  const nptr = mallocAndCopy(n)
  const pptr = mallocAndCopy(p)
  Sodium.crypto_scalarmult_ed25519_noclamp(qptr, nptr, pptr)
  copyAndFree(qptr, q)
  free(nptr)
  free(pptr)
}

export function crypto_scalarmult_ed25519_base_noclamp(q: Uint8Array, n: Uint8Array): void {
  const qptr = malloc(q)
  const nptr = mallocAndCopy(n)
  Sodium.crypto_scalarmult_ed25519_base_noclamp(qptr, nptr)
  copyAndFree(qptr, q)
  free(nptr)
}

export function crypto_secretbox_easy(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_secretbox_easy(cptr, mptr, BigInt(m.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_secretbox_open_easy(m: Uint8Array, c: Uint8Array, n: Uint8Array, k: Uint8Array): boolean {
  const mptr = mallocAndCopy(m)
  const cptr = mallocAndCopy(c)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_secretbox_open_easy(mptr, cptr, BigInt(c.byteLength), nptr, kptr)
  copyAndFree(mptr, m)
  free(cptr)
  free(nptr)
  free(kptr)
  return !!(ret + 1)
}

export function crypto_secretbox_detached(
  c: Uint8Array,
  mac: Uint8Array,
  m: Uint8Array,
  n: Uint8Array,
  k: Uint8Array
): void {
  const cptr = malloc(c)
  const macptr = malloc(mac)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_secretbox_detached(cptr, macptr, mptr, BigInt(m.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  copyAndFree(macptr, mac)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_secretbox_open_detached(
  m: Uint8Array,
  c: Uint8Array,
  mac: Uint8Array,
  n: Uint8Array,
  k: Uint8Array
): boolean {
  const mptr = mallocAndCopy(m)
  const cptr = mallocAndCopy(c)
  const macptr = mallocAndCopy(mac)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  const ret = Sodium.crypto_secretbox_open_detached(mptr, cptr, macptr, BigInt(c.byteLength), nptr, kptr)
  copyAndFree(mptr, m)
  free(cptr)
  free(macptr)
  free(nptr)
  free(kptr)
  return !!(ret + 1)
}

export function crypto_secretbox_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_secretbox_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_secretstream_xchacha20poly1305_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_secretstream_xchacha20poly1305_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_secretstream_xchacha20poly1305_init_push(
  state: Uint8Array,
  header: Uint8Array,
  k: Uint8Array
): void {
  const stateptr = malloc(state)
  const headerptr = malloc(header)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_secretstream_xchacha20poly1305_init_push(stateptr, headerptr, kptr)
  copyAndFree(stateptr, state)
  copyAndFree(headerptr, header)
  free(kptr)
}

export function crypto_secretstream_xchacha20poly1305_push(
  state: Uint8Array,
  c: Uint8Array,
  m: Uint8Array,
  ad: Uint8Array | null,
  tag: Uint8Array
): number {
  const stateptr = mallocAndCopy(state)
  const cptr = malloc(c)
  const clenptr = Sodium.malloc(8)
  const mptr = mallocAndCopy(m)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  Sodium.crypto_secretstream_xchacha20poly1305_push(
    stateptr,
    cptr,
    clenptr,
    mptr,
    BigInt(m.byteLength),
    adptr,
    BigInt(adlen),
    tag[0]
  )
  const clen = Buffer.alloc(8)
  copyAndFree(clenptr, clen)
  copyAndFree(stateptr, state)
  copyAndFree(cptr, c)
  free(mptr)
  if (adptr) {
    free(adptr)
  }
  return Number(clen.readBigUInt64LE())
}

export function crypto_secretstream_xchacha20poly1305_init_pull(
  state: Uint8Array,
  header: Uint8Array,
  k: Uint8Array
): void {
  const stateptr = malloc(state)
  const headerptr = mallocAndCopy(header)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_secretstream_xchacha20poly1305_init_pull(stateptr, headerptr, kptr)
  copyAndFree(stateptr, state)
  free(headerptr)
  free(kptr)
}

export function crypto_secretstream_xchacha20poly1305_pull(
  state: Uint8Array,
  m: Uint8Array,
  tag: Uint8Array,
  c: Uint8Array,
  ad: Uint8Array | null
): number {
  const stateptr = mallocAndCopy(state)
  const mptr = mallocAndCopy(m)
  const mlenptr = Sodium.malloc(8)
  const tagptr = Sodium.malloc(1)
  const cptr = mallocAndCopy(c)
  const adptr = ad === null ? null : mallocAndCopy(ad)
  const adlen = ad === null ? 0 : ad.byteLength
  const ret = Sodium.crypto_secretstream_xchacha20poly1305_pull(
    stateptr,
    mptr,
    mlenptr,
    tagptr,
    cptr,
    BigInt(c.byteLength),
    adptr,
    BigInt(adlen)
  )
  const mlen = Buffer.alloc(8)
  copyAndFree(mlenptr, mlen)
  copyAndFree(stateptr, state)
  copyAndFree(mptr, m)
  const tagIn = Buffer.alloc(1)
  copyAndFree(tagptr, tagIn)
  const t = tagIn.readInt8()
  tag[0] = t
  free(cptr)
  if (adptr) {
    free(adptr)
  }
  if (ret < 0) {
    throw new Error("Invalid cipher")
  }
  return Number(mlen.readBigUInt64LE())
}

export function crypto_secretstream_xchacha20poly1305_rekey(state: Uint8Array): void {
  const stateptr = mallocAndCopy(state)
  Sodium.crypto_secretstream_xchacha20poly1305_rekey(stateptr)
  copyAndFree(stateptr, state)
}

export function crypto_shorthash_keygen(k: Uint8Array): void {
  const kptr = malloc(k)
  Sodium.crypto_shorthash_keygen(kptr)
  copyAndFree(kptr, k)
}

export function crypto_shorthash(out: Uint8Array, inp: Uint8Array, k: Uint8Array): void {
  const outptr = malloc(out)
  const inpptr = mallocAndCopy(inp)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_shorthash(outptr, inpptr, BigInt(inp.byteLength), kptr)
  copyAndFree(outptr, out)
  free(inpptr)
  free(kptr)
}

export function crypto_shorthash_siphashx24(out: Uint8Array, inp: Uint8Array, k: Uint8Array): void {
  const outptr = malloc(out)
  const inpptr = mallocAndCopy(inp)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_shorthash_siphashx24(outptr, inpptr, BigInt(inp.byteLength), kptr)
  copyAndFree(outptr, out)
  free(inpptr)
  free(kptr)
}

export function crypto_sign_keypair(pk: Uint8Array, sk: Uint8Array): void {
  const pkptr = malloc(pk)
  const skptr = malloc(sk)
  Sodium.crypto_sign_keypair(pkptr, skptr)
  copyAndFree(pkptr, pk)
  copyAndFree(skptr, sk)
}

export function crypto_sign_seed_keypair(pk: Uint8Array, sk: Uint8Array, seed: Uint8Array): void {
  const pkptr = malloc(pk)
  const skptr = malloc(sk)
  const seedptr = mallocAndCopy(seed)
  Sodium.crypto_sign_seed_keypair(pkptr, skptr, seedptr)
  copyAndFree(pkptr, pk)
  copyAndFree(skptr, sk)
  free(seedptr)
}

export function crypto_sign(sm: Uint8Array, m: Uint8Array, sk: Uint8Array): number {
  const smptr = malloc(sm)
  const smlenptr = Sodium.malloc(8)
  const mptr = mallocAndCopy(m)
  const skptr = mallocAndCopy(sk)
  Sodium.crypto_sign(smptr, smlenptr, mptr, BigInt(m.byteLength), skptr)
  const smlen = Buffer.alloc(8)
  copyAndFree(smlenptr, smlen)
  copyAndFree(smptr, sm)
  free(mptr)
  free(skptr)
  return Number(smlen.readBigUInt64LE())
}

export function crypto_sign_open(m: Uint8Array, sm: Uint8Array, pk: Uint8Array): boolean {
  const mptr = malloc(m)
  const smptr = mallocAndCopy(sm)
  const pkptr = mallocAndCopy(pk)
  const ret = Sodium.crypto_sign_open(mptr, null, smptr, BigInt(sm.byteLength), pkptr)
  copyAndFree(mptr, m)
  free(smptr)
  free(pkptr)
  return ret === 0
}

export function crypto_sign_detached(sig: Uint8Array, m: Uint8Array, sk: Uint8Array): void {
  const sigptr = malloc(sig)
  const mptr = mallocAndCopy(m)
  const skptr = mallocAndCopy(sk)
  Sodium.crypto_sign_detached(sigptr, null, mptr, BigInt(m.byteLength), skptr)
  copyAndFree(sigptr, sig)
  free(mptr)
  free(skptr)
}

export function crypto_sign_verify_detached(sig: Uint8Array, m: Uint8Array, pk: Uint8Array): boolean {
  const sigptr = mallocAndCopy(sig)
  const mptr = mallocAndCopy(m)
  const pkptr = mallocAndCopy(pk)
  const ret = Sodium.crypto_sign_verify_detached(sigptr, mptr, BigInt(m.byteLength), pkptr)
  free(sigptr)
  free(mptr)
  free(pkptr)
  return ret === 0
}

export function crypto_sign_ed25519_sk_to_pk(pk: Uint8Array, sk: Uint8Array): void {
  const pkptr = malloc(pk)
  const skptr = mallocAndCopy(sk)
  Sodium.crypto_sign_ed25519_sk_to_pk(pkptr, skptr)
  copyAndFree(pkptr, pk)
  free(skptr)
}

export function crypto_sign_ed25519_pk_to_curve25519(x25519_pk: Uint8Array, ed25519_pk: Uint8Array): void {
  const xpkptr = malloc(x25519_pk)
  const epkptr = mallocAndCopy(ed25519_pk)
  const ret = Sodium.crypto_sign_ed25519_pk_to_curve25519(xpkptr, epkptr)
  copyAndFree(xpkptr, x25519_pk)
  free(epkptr)
  if (ret < 0) {
    throw new Error("Invalid public key")
  }
}

export function crypto_sign_ed25519_sk_to_curve25519(x25519_sk: Uint8Array, ed25519_sk: Uint8Array): void {
  const xskptr = malloc(x25519_sk)
  const eskptr = mallocAndCopy(ed25519_sk)
  const ret = Sodium.crypto_sign_ed25519_sk_to_curve25519(xskptr, eskptr)
  copyAndFree(xskptr, x25519_sk)
  free(eskptr)
  if (ret < 0) {
    throw new Error("Invalid secret key")
  }
}

export function crypto_stream_chacha20(c: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_chacha20(cptr, BigInt(c.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(nptr)
  free(kptr)
}

export function crypto_stream_chacha20_xor(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_chacha20_xor(cptr, mptr, BigInt(m.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_stream_chacha20_xor_ic(
  c: Uint8Array,
  m: Uint8Array,
  n: Uint8Array,
  ic: number,
  k: Uint8Array
): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_chacha20_xor_ic(cptr, mptr, BigInt(m.byteLength), nptr, BigInt(ic), kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_stream_chacha20_ietf(c: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_chacha20_ietf(cptr, BigInt(c.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(nptr)
  free(kptr)
}

export function crypto_stream_chacha20_ietf_xor(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_chacha20_ietf_xor(cptr, mptr, BigInt(m.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_stream_chacha20_ietf_xor_ic(
  c: Uint8Array,
  m: Uint8Array,
  n: Uint8Array,
  ic: number,
  k: Uint8Array
): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_chacha20_ietf_xor_ic(cptr, mptr, BigInt(m.byteLength), nptr, ic, kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_stream_xchacha20(c: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_xchacha20(cptr, BigInt(c.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(nptr)
  free(kptr)
}

export function crypto_stream_xchacha20_xor(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_xchacha20_xor(cptr, mptr, BigInt(m.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_stream_xchacha20_xor_ic(
  c: Uint8Array,
  m: Uint8Array,
  n: Uint8Array,
  ic: number,
  k: Uint8Array
): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_xchacha20_xor_ic(cptr, mptr, BigInt(m.byteLength), nptr, BigInt(ic), kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_stream_salsa20(c: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_salsa20(cptr, BigInt(c.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(nptr)
  free(kptr)
}

export function crypto_stream_salsa20_xor(c: Uint8Array, m: Uint8Array, n: Uint8Array, k: Uint8Array): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_salsa20_xor(cptr, mptr, BigInt(m.byteLength), nptr, kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function crypto_stream_salsa20_xor_ic(
  c: Uint8Array,
  m: Uint8Array,
  n: Uint8Array,
  ic: number,
  k: Uint8Array
): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const nptr = mallocAndCopy(n)
  const kptr = mallocAndCopy(k)
  Sodium.crypto_stream_salsa20_xor_ic(cptr, mptr, BigInt(m.byteLength), nptr, BigInt(ic), kptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(nptr)
  free(kptr)
}

export function randombytes_random(): number {
  return Sodium.randombytes_random() >>> 0
}

export function randombytes_uniform(upper_bound: number): number {
  return Sodium.randombytes_uniform(upper_bound) >>> 0
}

export function randombytes_buf(buf: Uint8Array): void {
  const bufptr = malloc(buf)
  Sodium.randombytes_buf(bufptr, buf.byteLength)
  copyAndFree(bufptr, buf)
}

export function randombytes_buf_deterministic(buf: Uint8Array, seed: Uint8Array): void {
  const bufptr = malloc(buf)
  const seedptr = mallocAndCopy(seed)
  Sodium.randombytes_buf_deterministic(bufptr, buf.byteLength, seedptr)
  copyAndFree(bufptr, buf)
  free(seedptr)
}

export function sodium_memcmp(b1_: Uint8Array, b2_: Uint8Array): boolean {
  if (b1_.byteLength !== b2_.byteLength) {
    throw new Error("Arguments must be of equal length")
  }
  const b1ptr = mallocAndCopy(b1_)
  const b2ptr = mallocAndCopy(b2_)
  const ret = Sodium.sodium_memcmp(b1ptr, b2ptr, b1_.byteLength)
  free(b1ptr)
  free(b2ptr)
  return !!(ret + 1)
}

export function sodium_increment(n: Uint8Array): void {
  const nptr = mallocAndCopy(n)
  Sodium.sodium_increment(nptr, n.byteLength)
  copyAndFree(nptr, n)
}

export function sodium_add(a: Uint8Array, b: Uint8Array): void {
  const aptr = mallocAndCopy(a)
  const bptr = mallocAndCopy(b)
  Sodium.sodium_add(aptr, bptr, a.byteLength)
  copyAndFree(aptr, a)
  free(bptr)
}

export function sodium_sub(a: Uint8Array, b: Uint8Array): void {
  const aptr = mallocAndCopy(a)
  const bptr = mallocAndCopy(b)
  Sodium.sodium_sub(aptr, bptr, a.byteLength)
  copyAndFree(aptr, a)
  free(bptr)
}

export function sodium_compare(b1_: Uint8Array, b2_: Uint8Array): number {
  const b1ptr = mallocAndCopy(b1_)
  const b2ptr = mallocAndCopy(b2_)
  const ret = Sodium.sodium_compare(b1ptr, b2ptr, b1_.byteLength)
  free(b1ptr)
  free(b2ptr)
  return ret
}

export function sodium_is_zero(n: Uint8Array): boolean {
  const nptr = mallocAndCopy(n)
  const ret = Sodium.sodium_is_zero(nptr, n.byteLength)
  free(nptr)
  return !!ret
}

export function sodium_pad(buf: Uint8Array, unpaddedLength: number, blocksize: number): number {
  if (unpaddedLength > buf.byteLength) {
    throw new Error("unpadded length cannot exceed buffer length")
  }
  if (blocksize > buf.byteLength) {
    throw new Error("block size cannot exceed buffer length")
  }
  if (blocksize < 1) {
    throw new Error("block sizemust be at least 1 byte")
  }
  if (buf.byteLength < unpaddedLength + (blocksize - (unpaddedLength % blocksize))) {
    throw new Error("buf not long enough")
  }
  const paddedLenghtptr = Sodium.malloc(4)
  const bufptr = mallocAndCopy(buf)
  const ret = Sodium.sodium_pad(paddedLenghtptr, bufptr, unpaddedLength, blocksize, buf.byteLength)
  const paddedLength = Buffer.alloc(4)
  copyAndFree(paddedLenghtptr, paddedLength)
  copyAndFree(bufptr, buf)
  if (ret < 0) {
    throw new Error("Invalid data")
  }
  return paddedLength.readInt32LE()
}

export function sodium_unpad(buf: Uint8Array, paddedLength: number, blocksize: number): number {
  if (paddedLength > buf.byteLength) {
    throw new Error("unpadded length cannot exceed buffer length")
  }
  if (blocksize > buf.byteLength) {
    throw new Error("block size cannot exceed buffer length")
  }
  if (blocksize < 1) {
    throw new Error("block size must be at least 1 byte")
  }
  const unpaddedLengthptr = Sodium.malloc(4)
  const bufptr = mallocAndCopy(buf)
  Sodium.sodium_unpad(unpaddedLengthptr, bufptr, paddedLength, blocksize)
  const unpaddedLength = Buffer.alloc(4)
  copyAndFree(unpaddedLengthptr, unpaddedLength)
  copyAndFree(bufptr, buf)
  return unpaddedLength.readInt32LE()
}

export function crypto_box_seal(c: Uint8Array, m: Uint8Array, pk: Uint8Array): void {
  const cptr = malloc(c)
  const mptr = mallocAndCopy(m)
  const pkptr = mallocAndCopy(pk)
  Sodium.crypto_box_seal(cptr, mptr, BigInt(m.byteLength), pkptr)
  copyAndFree(cptr, c)
  free(mptr)
  free(pkptr)
}

export function crypto_box_seal_open(m: Uint8Array, c: Uint8Array, pk: Uint8Array, sk: Uint8Array): boolean {
  const mptr = malloc(m)
  const cptr = mallocAndCopy(c)
  const pkptr = mallocAndCopy(pk)
  const skptr = mallocAndCopy(sk)
  const ret = Sodium.crypto_box_seal_open(mptr, cptr, BigInt(c.byteLength), pkptr, skptr)
  copyAndFree(mptr, m)
  free(cptr)
  free(pkptr)
  free(skptr)
  return !!(ret + 1)
}
