import { Buffer } from "buffer";
import * as Const from "./constants";
import * as Mem from "./memory";
import * as Sodium from "./Sodium";

export function crypto_generichash_batch(
	out: Uint8Array,
	inArray: Uint8Array[],
	key?: Uint8Array | null,
): void {
	const state = Buffer.alloc(Sodium.crypto_generichash_STATEBYTES);
	Sodium.crypto_generichash_init(state, key || null, out.byteLength);
	inArray.forEach((buf) => Sodium.crypto_generichash_update(state, buf));
	Sodium.crypto_generichash_final(state, out);
}

class GenerichashInstance {
	private state = Buffer.alloc(Sodium.crypto_generichash_STATEBYTES);

	constructor(key?: Uint8Array | null, outlen?: number) {
		Sodium.crypto_generichash_init(
			this.state,
			key || null,
			outlen || Const.crypto_generichash_BYTES,
		);
	}

	update(inp: Uint8Array): void {
		Sodium.crypto_generichash_update(this.state, inp);
	}

	final(out: Uint8Array): void {
		Sodium.crypto_generichash_final(this.state, out);
	}
}

export function crypto_generichash_instance(
	key: Uint8Array | null,
	outlen: number,
): GenerichashInstance {
	return new GenerichashInstance(key, outlen);
}

export * from "./Sodium";
export * from "./constants";
export * from "./memory";

export default {
	...Sodium,
	...Const,
	...Mem,
	crypto_generichash_batch,
	crypto_generichash_instance,
};
