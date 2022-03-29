/// <reference types="node" />
import { Buffer } from "buffer";
export declare function sodium_malloc(n: number): Buffer;
export declare function sodium_free(n: Uint8Array): void;
export declare function sodium_memzero(n: Uint8Array): void;
