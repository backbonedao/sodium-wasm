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
    crypto_generichash_batch: ()=>crypto_generichash_batch,
    crypto_generichash_instance: ()=>crypto_generichash_instance,
    default: ()=>_default
});
const _buffer = require("buffer");
const _constants = /*#__PURE__*/ _interopRequireWildcard(_exportStar(require("./constants"), exports));
const _memory = /*#__PURE__*/ _interopRequireWildcard(_exportStar(require("./memory"), exports));
const _sodium = /*#__PURE__*/ _interopRequireWildcard(_exportStar(require("./Sodium"), exports));
function _exportStar(from, to) {
    Object.keys(from).forEach(function(k) {
        if (k !== "default" && !Object.prototype.hasOwnProperty.call(to, k)) Object.defineProperty(to, k, {
            enumerable: true,
            get: function() {
                return from[k];
            }
        });
    });
    return from;
}
function _getRequireWildcardCache(nodeInterop) {
    if (typeof WeakMap !== "function") return null;
    var cacheBabelInterop = new WeakMap();
    var cacheNodeInterop = new WeakMap();
    return (_getRequireWildcardCache = function(nodeInterop) {
        return nodeInterop ? cacheNodeInterop : cacheBabelInterop;
    })(nodeInterop);
}
function _interopRequireWildcard(obj, nodeInterop) {
    if (!nodeInterop && obj && obj.__esModule) {
        return obj;
    }
    if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
        return {
            default: obj
        };
    }
    var cache = _getRequireWildcardCache(nodeInterop);
    if (cache && cache.has(obj)) {
        return cache.get(obj);
    }
    var newObj = {};
    var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;
    for(var key in obj){
        if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) {
            var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;
            if (desc && (desc.get || desc.set)) {
                Object.defineProperty(newObj, key, desc);
            } else {
                newObj[key] = obj[key];
            }
        }
    }
    newObj.default = obj;
    if (cache) {
        cache.set(obj, newObj);
    }
    return newObj;
}
function crypto_generichash_batch(out, inArray, key) {
    const state = _buffer.Buffer.alloc(_sodium.crypto_generichash_STATEBYTES);
    _sodium.crypto_generichash_init(state, key || null, out.byteLength);
    inArray.forEach((buf)=>_sodium.crypto_generichash_update(state, buf));
    _sodium.crypto_generichash_final(state, out);
}
class GenerichashInstance {
    update(inp) {
        _sodium.crypto_generichash_update(this.state, inp);
    }
    final(out) {
        _sodium.crypto_generichash_final(this.state, out);
    }
    constructor(key, outlen){
        this.state = _buffer.Buffer.alloc(_sodium.crypto_generichash_STATEBYTES);
        _sodium.crypto_generichash_init(this.state, key || null, outlen || _constants.crypto_generichash_BYTES);
    }
}
function crypto_generichash_instance(key, outlen) {
    return new GenerichashInstance(key, outlen);
}
const _default = {
    ..._sodium,
    ..._constants,
    ..._memory,
    crypto_generichash_batch,
    crypto_generichash_instance
};
