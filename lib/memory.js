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
    sodium_malloc: ()=>sodium_malloc,
    sodium_free: ()=>sodium_free,
    sodium_memzero: ()=>sodium_memzero
});
const _buffer = require("buffer");
function sodium_malloc(n) {
    return _buffer.Buffer.alloc(n);
}
function sodium_free(n) {
    sodium_memzero(n);
}
function sodium_memzero(n) {
    n.fill(0);
}
