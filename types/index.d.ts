export declare function crypto_generichash_batch(out: Uint8Array, inArray: Uint8Array[], key?: Uint8Array | null): void;
declare class GenerichashInstance {
    private state;
    constructor(key?: Uint8Array | null, outlen?: number);
    update(inp: Uint8Array): void;
    final(out: Uint8Array): void;
}
export declare function crypto_generichash_instance(key: Uint8Array | null, outlen: number): GenerichashInstance;
export * from "./Sodium";
export * from "./constants";
export * from "./memory";
