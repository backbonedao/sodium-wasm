import { Buffer } from "buffer";

export function sodium_malloc(n: number) {
	return Buffer.alloc(n);
}

export function sodium_free(n: Uint8Array) {
	sodium_memzero(n);
}

export function sodium_memzero(n: Uint8Array) {
	n.fill(0);
}
