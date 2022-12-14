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
    SODIUM_SIZE_MAX: ()=>SODIUM_SIZE_MAX,
    crypto_aead_aes256gcm_KEYBYTES: ()=>crypto_aead_aes256gcm_KEYBYTES,
    crypto_aead_aes256gcm_NSECBYTES: ()=>crypto_aead_aes256gcm_NSECBYTES,
    crypto_aead_aes256gcm_NPUBBYTES: ()=>crypto_aead_aes256gcm_NPUBBYTES,
    crypto_aead_aes256gcm_ABYTES: ()=>crypto_aead_aes256gcm_ABYTES,
    crypto_aead_aes256gcm_MESSAGEBYTES_MAX: ()=>crypto_aead_aes256gcm_MESSAGEBYTES_MAX,
    crypto_aead_chacha20poly1305_ietf_KEYBYTES: ()=>crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    crypto_aead_chacha20poly1305_ietf_NSECBYTES: ()=>crypto_aead_chacha20poly1305_ietf_NSECBYTES,
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES: ()=>crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_chacha20poly1305_ietf_ABYTES: ()=>crypto_aead_chacha20poly1305_ietf_ABYTES,
    crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX: ()=>crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX,
    crypto_aead_chacha20poly1305_KEYBYTES: ()=>crypto_aead_chacha20poly1305_KEYBYTES,
    crypto_aead_chacha20poly1305_NSECBYTES: ()=>crypto_aead_chacha20poly1305_NSECBYTES,
    crypto_aead_chacha20poly1305_NPUBBYTES: ()=>crypto_aead_chacha20poly1305_NPUBBYTES,
    crypto_aead_chacha20poly1305_ABYTES: ()=>crypto_aead_chacha20poly1305_ABYTES,
    crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX: ()=>crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX,
    crypto_aead_chacha20poly1305_IETF_KEYBYTES: ()=>crypto_aead_chacha20poly1305_IETF_KEYBYTES,
    crypto_aead_chacha20poly1305_IETF_NSECBYTES: ()=>crypto_aead_chacha20poly1305_IETF_NSECBYTES,
    crypto_aead_chacha20poly1305_IETF_NPUBBYTES: ()=>crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
    crypto_aead_chacha20poly1305_IETF_ABYTES: ()=>crypto_aead_chacha20poly1305_IETF_ABYTES,
    crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX: ()=>crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES: ()=>crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NSECBYTES: ()=>crypto_aead_xchacha20poly1305_ietf_NSECBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: ()=>crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_ABYTES: ()=>crypto_aead_xchacha20poly1305_ietf_ABYTES,
    crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX: ()=>crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX,
    crypto_aead_xchacha20poly1305_IETF_KEYBYTES: ()=>crypto_aead_xchacha20poly1305_IETF_KEYBYTES,
    crypto_aead_xchacha20poly1305_IETF_NSECBYTES: ()=>crypto_aead_xchacha20poly1305_IETF_NSECBYTES,
    crypto_aead_xchacha20poly1305_IETF_NPUBBYTES: ()=>crypto_aead_xchacha20poly1305_IETF_NPUBBYTES,
    crypto_aead_xchacha20poly1305_IETF_ABYTES: ()=>crypto_aead_xchacha20poly1305_IETF_ABYTES,
    crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX: ()=>crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX,
    crypto_auth_BYTES: ()=>crypto_auth_BYTES,
    crypto_auth_KEYBYTES: ()=>crypto_auth_KEYBYTES,
    crypto_auth_PRIMITIVE: ()=>crypto_auth_PRIMITIVE,
    crypto_auth_hmacsha256_BYTES: ()=>crypto_auth_hmacsha256_BYTES,
    crypto_auth_hmacsha256_KEYBYTES: ()=>crypto_auth_hmacsha256_KEYBYTES,
    crypto_auth_hmacsha512_BYTES: ()=>crypto_auth_hmacsha512_BYTES,
    crypto_auth_hmacsha512_KEYBYTES: ()=>crypto_auth_hmacsha512_KEYBYTES,
    crypto_auth_hmacsha512256_BYTES: ()=>crypto_auth_hmacsha512256_BYTES,
    crypto_auth_hmacsha512256_KEYBYTES: ()=>crypto_auth_hmacsha512256_KEYBYTES,
    crypto_box_SEEDBYTES: ()=>crypto_box_SEEDBYTES,
    crypto_box_PUBLICKEYBYTES: ()=>crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES: ()=>crypto_box_SECRETKEYBYTES,
    crypto_box_NONCEBYTES: ()=>crypto_box_NONCEBYTES,
    crypto_box_MACBYTES: ()=>crypto_box_MACBYTES,
    crypto_box_MESSAGEBYTES_MAX: ()=>crypto_box_MESSAGEBYTES_MAX,
    crypto_box_PRIMITIVE: ()=>crypto_box_PRIMITIVE,
    crypto_box_BEFORENMBYTES: ()=>crypto_box_BEFORENMBYTES,
    crypto_box_SEALBYTES: ()=>crypto_box_SEALBYTES,
    crypto_box_ZEROBYTES: ()=>crypto_box_ZEROBYTES,
    crypto_box_BOXZEROBYTES: ()=>crypto_box_BOXZEROBYTES,
    crypto_box_curve25519xchacha20poly1305_SEEDBYTES: ()=>crypto_box_curve25519xchacha20poly1305_SEEDBYTES,
    crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES: ()=>crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
    crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES: ()=>crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES,
    crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES: ()=>crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES,
    crypto_box_curve25519xchacha20poly1305_NONCEBYTES: ()=>crypto_box_curve25519xchacha20poly1305_NONCEBYTES,
    crypto_box_curve25519xchacha20poly1305_MACBYTES: ()=>crypto_box_curve25519xchacha20poly1305_MACBYTES,
    crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX: ()=>crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX,
    crypto_box_curve25519xchacha20poly1305_SEALBYTES: ()=>crypto_box_curve25519xchacha20poly1305_SEALBYTES,
    crypto_box_curve25519xsalsa20poly1305_SEEDBYTES: ()=>crypto_box_curve25519xsalsa20poly1305_SEEDBYTES,
    crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES: ()=>crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
    crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES: ()=>crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
    crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES: ()=>crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES,
    crypto_box_curve25519xsalsa20poly1305_NONCEBYTES: ()=>crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
    crypto_box_curve25519xsalsa20poly1305_MACBYTES: ()=>crypto_box_curve25519xsalsa20poly1305_MACBYTES,
    crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX: ()=>crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX,
    crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES: ()=>crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES,
    crypto_box_curve25519xsalsa20poly1305_ZEROBYTES: ()=>crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,
    crypto_core_ed25519_BYTES: ()=>crypto_core_ed25519_BYTES,
    crypto_core_ed25519_UNIFORMBYTES: ()=>crypto_core_ed25519_UNIFORMBYTES,
    crypto_core_ed25519_HASHBYTES: ()=>crypto_core_ed25519_HASHBYTES,
    crypto_core_ed25519_SCALARBYTES: ()=>crypto_core_ed25519_SCALARBYTES,
    crypto_core_ed25519_NONREDUCEDSCALARBYTES: ()=>crypto_core_ed25519_NONREDUCEDSCALARBYTES,
    crypto_core_hchacha20_OUTPUTBYTES: ()=>crypto_core_hchacha20_OUTPUTBYTES,
    crypto_core_hchacha20_INPUTBYTES: ()=>crypto_core_hchacha20_INPUTBYTES,
    crypto_core_hchacha20_KEYBYTES: ()=>crypto_core_hchacha20_KEYBYTES,
    crypto_core_hchacha20_CONSTBYTES: ()=>crypto_core_hchacha20_CONSTBYTES,
    crypto_core_hsalsa20_OUTPUTBYTES: ()=>crypto_core_hsalsa20_OUTPUTBYTES,
    crypto_core_hsalsa20_INPUTBYTES: ()=>crypto_core_hsalsa20_INPUTBYTES,
    crypto_core_hsalsa20_KEYBYTES: ()=>crypto_core_hsalsa20_KEYBYTES,
    crypto_core_hsalsa20_CONSTBYTES: ()=>crypto_core_hsalsa20_CONSTBYTES,
    crypto_core_ristretto255_BYTES: ()=>crypto_core_ristretto255_BYTES,
    crypto_core_ristretto255_HASHBYTES: ()=>crypto_core_ristretto255_HASHBYTES,
    crypto_core_ristretto255_SCALARBYTES: ()=>crypto_core_ristretto255_SCALARBYTES,
    crypto_core_ristretto255_NONREDUCEDSCALARBYTES: ()=>crypto_core_ristretto255_NONREDUCEDSCALARBYTES,
    crypto_core_salsa20_OUTPUTBYTES: ()=>crypto_core_salsa20_OUTPUTBYTES,
    crypto_core_salsa20_INPUTBYTES: ()=>crypto_core_salsa20_INPUTBYTES,
    crypto_core_salsa20_KEYBYTES: ()=>crypto_core_salsa20_KEYBYTES,
    crypto_core_salsa20_CONSTBYTES: ()=>crypto_core_salsa20_CONSTBYTES,
    crypto_core_salsa2012_OUTPUTBYTES: ()=>crypto_core_salsa2012_OUTPUTBYTES,
    crypto_core_salsa2012_INPUTBYTES: ()=>crypto_core_salsa2012_INPUTBYTES,
    crypto_core_salsa2012_KEYBYTES: ()=>crypto_core_salsa2012_KEYBYTES,
    crypto_core_salsa2012_CONSTBYTES: ()=>crypto_core_salsa2012_CONSTBYTES,
    crypto_core_salsa208_OUTPUTBYTES: ()=>crypto_core_salsa208_OUTPUTBYTES,
    crypto_core_salsa208_INPUTBYTES: ()=>crypto_core_salsa208_INPUTBYTES,
    crypto_core_salsa208_KEYBYTES: ()=>crypto_core_salsa208_KEYBYTES,
    crypto_core_salsa208_CONSTBYTES: ()=>crypto_core_salsa208_CONSTBYTES,
    crypto_generichash_BYTES_MIN: ()=>crypto_generichash_BYTES_MIN,
    crypto_generichash_BYTES_MAX: ()=>crypto_generichash_BYTES_MAX,
    crypto_generichash_BYTES: ()=>crypto_generichash_BYTES,
    crypto_generichash_KEYBYTES_MIN: ()=>crypto_generichash_KEYBYTES_MIN,
    crypto_generichash_KEYBYTES_MAX: ()=>crypto_generichash_KEYBYTES_MAX,
    crypto_generichash_KEYBYTES: ()=>crypto_generichash_KEYBYTES,
    crypto_generichash_PRIMITIVE: ()=>crypto_generichash_PRIMITIVE,
    crypto_generichash_blake2b_BYTES_MIN: ()=>crypto_generichash_blake2b_BYTES_MIN,
    crypto_generichash_blake2b_BYTES_MAX: ()=>crypto_generichash_blake2b_BYTES_MAX,
    crypto_generichash_blake2b_BYTES: ()=>crypto_generichash_blake2b_BYTES,
    crypto_generichash_blake2b_KEYBYTES_MIN: ()=>crypto_generichash_blake2b_KEYBYTES_MIN,
    crypto_generichash_blake2b_KEYBYTES_MAX: ()=>crypto_generichash_blake2b_KEYBYTES_MAX,
    crypto_generichash_blake2b_KEYBYTES: ()=>crypto_generichash_blake2b_KEYBYTES,
    crypto_generichash_blake2b_SALTBYTES: ()=>crypto_generichash_blake2b_SALTBYTES,
    crypto_generichash_blake2b_PERSONALBYTES: ()=>crypto_generichash_blake2b_PERSONALBYTES,
    crypto_hash_BYTES: ()=>crypto_hash_BYTES,
    crypto_hash_PRIMITIVE: ()=>crypto_hash_PRIMITIVE,
    crypto_hash_sha256_BYTES: ()=>crypto_hash_sha256_BYTES,
    crypto_hash_sha512_BYTES: ()=>crypto_hash_sha512_BYTES,
    crypto_kdf_BYTES_MIN: ()=>crypto_kdf_BYTES_MIN,
    crypto_kdf_BYTES_MAX: ()=>crypto_kdf_BYTES_MAX,
    crypto_kdf_CONTEXTBYTES: ()=>crypto_kdf_CONTEXTBYTES,
    crypto_kdf_KEYBYTES: ()=>crypto_kdf_KEYBYTES,
    crypto_kdf_PRIMITIVE: ()=>crypto_kdf_PRIMITIVE,
    crypto_kdf_blake2b_BYTES_MIN: ()=>crypto_kdf_blake2b_BYTES_MIN,
    crypto_kdf_blake2b_BYTES_MAX: ()=>crypto_kdf_blake2b_BYTES_MAX,
    crypto_kdf_blake2b_CONTEXTBYTES: ()=>crypto_kdf_blake2b_CONTEXTBYTES,
    crypto_kdf_blake2b_KEYBYTES: ()=>crypto_kdf_blake2b_KEYBYTES,
    crypto_kx_PUBLICKEYBYTES: ()=>crypto_kx_PUBLICKEYBYTES,
    crypto_kx_SECRETKEYBYTES: ()=>crypto_kx_SECRETKEYBYTES,
    crypto_kx_SEEDBYTES: ()=>crypto_kx_SEEDBYTES,
    crypto_kx_SESSIONKEYBYTES: ()=>crypto_kx_SESSIONKEYBYTES,
    crypto_kx_PRIMITIVE: ()=>crypto_kx_PRIMITIVE,
    crypto_onetimeauth_BYTES: ()=>crypto_onetimeauth_BYTES,
    crypto_onetimeauth_KEYBYTES: ()=>crypto_onetimeauth_KEYBYTES,
    crypto_onetimeauth_PRIMITIVE: ()=>crypto_onetimeauth_PRIMITIVE,
    crypto_onetimeauth_poly1305_BYTES: ()=>crypto_onetimeauth_poly1305_BYTES,
    crypto_onetimeauth_poly1305_KEYBYTES: ()=>crypto_onetimeauth_poly1305_KEYBYTES,
    crypto_pwhash_ALG_DEFAULT: ()=>crypto_pwhash_ALG_DEFAULT,
    crypto_pwhash_BYTES_MIN: ()=>crypto_pwhash_BYTES_MIN,
    crypto_pwhash_BYTES_MAX: ()=>crypto_pwhash_BYTES_MAX,
    crypto_pwhash_PASSWD_MIN: ()=>crypto_pwhash_PASSWD_MIN,
    crypto_pwhash_PASSWD_MAX: ()=>crypto_pwhash_PASSWD_MAX,
    crypto_pwhash_SALTBYTES: ()=>crypto_pwhash_SALTBYTES,
    crypto_pwhash_STRBYTES: ()=>crypto_pwhash_STRBYTES,
    crypto_pwhash_STRPREFIX: ()=>crypto_pwhash_STRPREFIX,
    crypto_pwhash_OPSLIMIT_MIN: ()=>crypto_pwhash_OPSLIMIT_MIN,
    crypto_pwhash_OPSLIMIT_MAX: ()=>crypto_pwhash_OPSLIMIT_MAX,
    crypto_pwhash_MEMLIMIT_MIN: ()=>crypto_pwhash_MEMLIMIT_MIN,
    crypto_pwhash_MEMLIMIT_MAX: ()=>crypto_pwhash_MEMLIMIT_MAX,
    crypto_pwhash_OPSLIMIT_INTERACTIVE: ()=>crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE: ()=>crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_OPSLIMIT_MODERATE: ()=>crypto_pwhash_OPSLIMIT_MODERATE,
    crypto_pwhash_MEMLIMIT_MODERATE: ()=>crypto_pwhash_MEMLIMIT_MODERATE,
    crypto_pwhash_OPSLIMIT_SENSITIVE: ()=>crypto_pwhash_OPSLIMIT_SENSITIVE,
    crypto_pwhash_MEMLIMIT_SENSITIVE: ()=>crypto_pwhash_MEMLIMIT_SENSITIVE,
    crypto_pwhash_PRIMITIVE: ()=>crypto_pwhash_PRIMITIVE,
    crypto_pwhash_argon2i_BYTES_MIN: ()=>crypto_pwhash_argon2i_BYTES_MIN,
    crypto_pwhash_argon2i_BYTES_MAX: ()=>crypto_pwhash_argon2i_BYTES_MAX,
    crypto_pwhash_argon2i_PASSWD_MIN: ()=>crypto_pwhash_argon2i_PASSWD_MIN,
    crypto_pwhash_argon2i_PASSWD_MAX: ()=>crypto_pwhash_argon2i_PASSWD_MAX,
    crypto_pwhash_argon2i_SALTBYTES: ()=>crypto_pwhash_argon2i_SALTBYTES,
    crypto_pwhash_argon2i_STRBYTES: ()=>crypto_pwhash_argon2i_STRBYTES,
    crypto_pwhash_argon2i_STRPREFIX: ()=>crypto_pwhash_argon2i_STRPREFIX,
    crypto_pwhash_argon2i_OPSLIMIT_MIN: ()=>crypto_pwhash_argon2i_OPSLIMIT_MIN,
    crypto_pwhash_argon2i_OPSLIMIT_MAX: ()=>crypto_pwhash_argon2i_OPSLIMIT_MAX,
    crypto_pwhash_argon2i_MEMLIMIT_MIN: ()=>crypto_pwhash_argon2i_MEMLIMIT_MIN,
    crypto_pwhash_argon2i_MEMLIMIT_MAX: ()=>crypto_pwhash_argon2i_MEMLIMIT_MAX,
    crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE: ()=>crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE: ()=>crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_argon2i_OPSLIMIT_MODERATE: ()=>crypto_pwhash_argon2i_OPSLIMIT_MODERATE,
    crypto_pwhash_argon2i_MEMLIMIT_MODERATE: ()=>crypto_pwhash_argon2i_MEMLIMIT_MODERATE,
    crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE: ()=>crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE,
    crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE: ()=>crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE,
    crypto_pwhash_argon2id_BYTES_MIN: ()=>crypto_pwhash_argon2id_BYTES_MIN,
    crypto_pwhash_argon2id_BYTES_MAX: ()=>crypto_pwhash_argon2id_BYTES_MAX,
    crypto_pwhash_argon2id_PASSWD_MIN: ()=>crypto_pwhash_argon2id_PASSWD_MIN,
    crypto_pwhash_argon2id_PASSWD_MAX: ()=>crypto_pwhash_argon2id_PASSWD_MAX,
    crypto_pwhash_argon2id_SALTBYTES: ()=>crypto_pwhash_argon2id_SALTBYTES,
    crypto_pwhash_argon2id_STRBYTES: ()=>crypto_pwhash_argon2id_STRBYTES,
    crypto_pwhash_argon2id_STRPREFIX: ()=>crypto_pwhash_argon2id_STRPREFIX,
    crypto_pwhash_argon2id_OPSLIMIT_MIN: ()=>crypto_pwhash_argon2id_OPSLIMIT_MIN,
    crypto_pwhash_argon2id_OPSLIMIT_MAX: ()=>crypto_pwhash_argon2id_OPSLIMIT_MAX,
    crypto_pwhash_argon2id_MEMLIMIT_MIN: ()=>crypto_pwhash_argon2id_MEMLIMIT_MIN,
    crypto_pwhash_argon2id_MEMLIMIT_MAX: ()=>crypto_pwhash_argon2id_MEMLIMIT_MAX,
    crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE: ()=>crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE: ()=>crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_argon2id_OPSLIMIT_MODERATE: ()=>crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
    crypto_pwhash_argon2id_MEMLIMIT_MODERATE: ()=>crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
    crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE: ()=>crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE,
    crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE: ()=>crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE,
    crypto_pwhash_scryptsalsa208sha256_BYTES_MIN: ()=>crypto_pwhash_scryptsalsa208sha256_BYTES_MIN,
    crypto_pwhash_scryptsalsa208sha256_BYTES_MAX: ()=>crypto_pwhash_scryptsalsa208sha256_BYTES_MAX,
    crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN: ()=>crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN,
    crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX: ()=>crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX,
    crypto_pwhash_scryptsalsa208sha256_SALTBYTES: ()=>crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
    crypto_pwhash_scryptsalsa208sha256_STRBYTES: ()=>crypto_pwhash_scryptsalsa208sha256_STRBYTES,
    crypto_pwhash_scryptsalsa208sha256_STRPREFIX: ()=>crypto_pwhash_scryptsalsa208sha256_STRPREFIX,
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN: ()=>crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX: ()=>crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX,
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN: ()=>crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN,
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX: ()=>crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX,
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: ()=>crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: ()=>crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE: ()=>crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE: ()=>crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE,
    crypto_scalarmult_BYTES: ()=>crypto_scalarmult_BYTES,
    crypto_scalarmult_SCALARBYTES: ()=>crypto_scalarmult_SCALARBYTES,
    crypto_scalarmult_PRIMITIVE: ()=>crypto_scalarmult_PRIMITIVE,
    crypto_scalarmult_curve25519_BYTES: ()=>crypto_scalarmult_curve25519_BYTES,
    crypto_scalarmult_curve25519_SCALARBYTES: ()=>crypto_scalarmult_curve25519_SCALARBYTES,
    crypto_scalarmult_ed25519_BYTES: ()=>crypto_scalarmult_ed25519_BYTES,
    crypto_scalarmult_ed25519_SCALARBYTES: ()=>crypto_scalarmult_ed25519_SCALARBYTES,
    crypto_scalarmult_ristretto255_BYTES: ()=>crypto_scalarmult_ristretto255_BYTES,
    crypto_scalarmult_ristretto255_SCALARBYTES: ()=>crypto_scalarmult_ristretto255_SCALARBYTES,
    crypto_secretbox_KEYBYTES: ()=>crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES: ()=>crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES: ()=>crypto_secretbox_MACBYTES,
    crypto_secretbox_PRIMITIVE: ()=>crypto_secretbox_PRIMITIVE,
    crypto_secretbox_MESSAGEBYTES_MAX: ()=>crypto_secretbox_MESSAGEBYTES_MAX,
    crypto_secretbox_ZEROBYTES: ()=>crypto_secretbox_ZEROBYTES,
    crypto_secretbox_BOXZEROBYTES: ()=>crypto_secretbox_BOXZEROBYTES,
    crypto_secretbox_xchacha20poly1305_KEYBYTES: ()=>crypto_secretbox_xchacha20poly1305_KEYBYTES,
    crypto_secretbox_xchacha20poly1305_NONCEBYTES: ()=>crypto_secretbox_xchacha20poly1305_NONCEBYTES,
    crypto_secretbox_xchacha20poly1305_MACBYTES: ()=>crypto_secretbox_xchacha20poly1305_MACBYTES,
    crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX: ()=>crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX,
    crypto_secretbox_xsalsa20poly1305_KEYBYTES: ()=>crypto_secretbox_xsalsa20poly1305_KEYBYTES,
    crypto_secretbox_xsalsa20poly1305_NONCEBYTES: ()=>crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
    crypto_secretbox_xsalsa20poly1305_MACBYTES: ()=>crypto_secretbox_xsalsa20poly1305_MACBYTES,
    crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX: ()=>crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX,
    crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES: ()=>crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,
    crypto_secretbox_xsalsa20poly1305_ZEROBYTES: ()=>crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
    crypto_secretstream_xchacha20poly1305_ABYTES: ()=>crypto_secretstream_xchacha20poly1305_ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES: ()=>crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_KEYBYTES: ()=>crypto_secretstream_xchacha20poly1305_KEYBYTES,
    crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX: ()=>crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX,
    crypto_secretstream_xchacha20poly1305_TAGBYTES: ()=>crypto_secretstream_xchacha20poly1305_TAGBYTES,
    crypto_shorthash_BYTES: ()=>crypto_shorthash_BYTES,
    crypto_shorthash_KEYBYTES: ()=>crypto_shorthash_KEYBYTES,
    crypto_shorthash_PRIMITIVE: ()=>crypto_shorthash_PRIMITIVE,
    crypto_shorthash_siphash24_BYTES: ()=>crypto_shorthash_siphash24_BYTES,
    crypto_shorthash_siphash24_KEYBYTES: ()=>crypto_shorthash_siphash24_KEYBYTES,
    crypto_shorthash_siphashx24_BYTES: ()=>crypto_shorthash_siphashx24_BYTES,
    crypto_shorthash_siphashx24_KEYBYTES: ()=>crypto_shorthash_siphashx24_KEYBYTES,
    crypto_sign_BYTES: ()=>crypto_sign_BYTES,
    crypto_sign_SEEDBYTES: ()=>crypto_sign_SEEDBYTES,
    crypto_sign_PUBLICKEYBYTES: ()=>crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES: ()=>crypto_sign_SECRETKEYBYTES,
    crypto_sign_MESSAGEBYTES_MAX: ()=>crypto_sign_MESSAGEBYTES_MAX,
    crypto_sign_PRIMITIVE: ()=>crypto_sign_PRIMITIVE,
    crypto_sign_ed25519_BYTES: ()=>crypto_sign_ed25519_BYTES,
    crypto_sign_ed25519_SEEDBYTES: ()=>crypto_sign_ed25519_SEEDBYTES,
    crypto_sign_ed25519_PUBLICKEYBYTES: ()=>crypto_sign_ed25519_PUBLICKEYBYTES,
    crypto_sign_ed25519_SECRETKEYBYTES: ()=>crypto_sign_ed25519_SECRETKEYBYTES,
    crypto_sign_ed25519_MESSAGEBYTES_MAX: ()=>crypto_sign_ed25519_MESSAGEBYTES_MAX,
    crypto_sign_edwards25519sha512batch_BYTES: ()=>crypto_sign_edwards25519sha512batch_BYTES,
    crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES: ()=>crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES,
    crypto_sign_edwards25519sha512batch_SECRETKEYBYTES: ()=>crypto_sign_edwards25519sha512batch_SECRETKEYBYTES,
    crypto_sign_edwards25519sha512batch_MESSAGEBYTES_MAX: ()=>crypto_sign_edwards25519sha512batch_MESSAGEBYTES_MAX,
    crypto_stream_KEYBYTES: ()=>crypto_stream_KEYBYTES,
    crypto_stream_NONCEBYTES: ()=>crypto_stream_NONCEBYTES,
    crypto_stream_MESSAGEBYTES_MAX: ()=>crypto_stream_MESSAGEBYTES_MAX,
    crypto_stream_PRIMITIVE: ()=>crypto_stream_PRIMITIVE,
    crypto_stream_chacha20_KEYBYTES: ()=>crypto_stream_chacha20_KEYBYTES,
    crypto_stream_chacha20_NONCEBYTES: ()=>crypto_stream_chacha20_NONCEBYTES,
    crypto_stream_chacha20_MESSAGEBYTES_MAX: ()=>crypto_stream_chacha20_MESSAGEBYTES_MAX,
    crypto_stream_chacha20_ietf_KEYBYTES: ()=>crypto_stream_chacha20_ietf_KEYBYTES,
    crypto_stream_chacha20_ietf_NONCEBYTES: ()=>crypto_stream_chacha20_ietf_NONCEBYTES,
    crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX: ()=>crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX,
    crypto_stream_chacha20_IETF_KEYBYTES: ()=>crypto_stream_chacha20_IETF_KEYBYTES,
    crypto_stream_chacha20_IETF_NONCEBYTES: ()=>crypto_stream_chacha20_IETF_NONCEBYTES,
    crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX: ()=>crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX,
    crypto_stream_salsa20_KEYBYTES: ()=>crypto_stream_salsa20_KEYBYTES,
    crypto_stream_salsa20_NONCEBYTES: ()=>crypto_stream_salsa20_NONCEBYTES,
    crypto_stream_salsa20_MESSAGEBYTES_MAX: ()=>crypto_stream_salsa20_MESSAGEBYTES_MAX,
    crypto_stream_salsa2012_KEYBYTES: ()=>crypto_stream_salsa2012_KEYBYTES,
    crypto_stream_salsa2012_NONCEBYTES: ()=>crypto_stream_salsa2012_NONCEBYTES,
    crypto_stream_salsa2012_MESSAGEBYTES_MAX: ()=>crypto_stream_salsa2012_MESSAGEBYTES_MAX,
    crypto_stream_salsa208_KEYBYTES: ()=>crypto_stream_salsa208_KEYBYTES,
    crypto_stream_salsa208_NONCEBYTES: ()=>crypto_stream_salsa208_NONCEBYTES,
    crypto_stream_salsa208_MESSAGEBYTES_MAX: ()=>crypto_stream_salsa208_MESSAGEBYTES_MAX,
    crypto_stream_xchacha20_KEYBYTES: ()=>crypto_stream_xchacha20_KEYBYTES,
    crypto_stream_xchacha20_NONCEBYTES: ()=>crypto_stream_xchacha20_NONCEBYTES,
    crypto_stream_xchacha20_MESSAGEBYTES_MAX: ()=>crypto_stream_xchacha20_MESSAGEBYTES_MAX,
    crypto_stream_xsalsa20_KEYBYTES: ()=>crypto_stream_xsalsa20_KEYBYTES,
    crypto_stream_xsalsa20_NONCEBYTES: ()=>crypto_stream_xsalsa20_NONCEBYTES,
    crypto_stream_xsalsa20_MESSAGEBYTES_MAX: ()=>crypto_stream_xsalsa20_MESSAGEBYTES_MAX,
    crypto_verify_16_BYTES: ()=>crypto_verify_16_BYTES,
    crypto_verify_32_BYTES: ()=>crypto_verify_32_BYTES,
    crypto_verify_64_BYTES: ()=>crypto_verify_64_BYTES,
    randombytes_BYTES_MAX: ()=>randombytes_BYTES_MAX,
    randombytes_SEEDBYTES: ()=>randombytes_SEEDBYTES
});
const SODIUM_SIZE_MAX = Number.MAX_SAFE_INTEGER;
const crypto_aead_aes256gcm_KEYBYTES = 32;
const crypto_aead_aes256gcm_NSECBYTES = 0;
const crypto_aead_aes256gcm_NPUBBYTES = 12;
const crypto_aead_aes256gcm_ABYTES = 16;
const crypto_aead_aes256gcm_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
const crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0;
const crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
const crypto_aead_chacha20poly1305_ietf_ABYTES = 16;
const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_aead_chacha20poly1305_KEYBYTES = 32;
const crypto_aead_chacha20poly1305_NSECBYTES = 0;
const crypto_aead_chacha20poly1305_NPUBBYTES = 8;
const crypto_aead_chacha20poly1305_ABYTES = 16;
const crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ABYTES;
const crypto_aead_chacha20poly1305_IETF_KEYBYTES = 32;
const crypto_aead_chacha20poly1305_IETF_NSECBYTES = 0;
const crypto_aead_chacha20poly1305_IETF_NPUBBYTES = 24;
const crypto_aead_chacha20poly1305_IETF_ABYTES = 26;
const crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_IETF_ABYTES;
const crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32;
const crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0;
const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24;
const crypto_aead_xchacha20poly1305_ietf_ABYTES = 16;
const crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = 4294967279;
const crypto_aead_xchacha20poly1305_IETF_KEYBYTES = 32;
const crypto_aead_xchacha20poly1305_IETF_NSECBYTES = 0;
const crypto_aead_xchacha20poly1305_IETF_NPUBBYTES = 24;
const crypto_aead_xchacha20poly1305_IETF_ABYTES = 16;
const crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX - crypto_aead_xchacha20poly1305_IETF_ABYTES;
const crypto_auth_BYTES = 32;
const crypto_auth_KEYBYTES = 32;
const crypto_auth_PRIMITIVE = "hmacsha512256";
const crypto_auth_hmacsha256_BYTES = 32;
const crypto_auth_hmacsha256_KEYBYTES = 32;
const crypto_auth_hmacsha512_BYTES = 64;
const crypto_auth_hmacsha512_KEYBYTES = 32;
const crypto_auth_hmacsha512256_BYTES = 32;
const crypto_auth_hmacsha512256_KEYBYTES = 32;
const crypto_box_SEEDBYTES = 32;
const crypto_box_PUBLICKEYBYTES = 32;
const crypto_box_SECRETKEYBYTES = 32;
const crypto_box_NONCEBYTES = 24;
const crypto_box_MACBYTES = 16;
const crypto_box_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_box_PRIMITIVE = "curve25519xsalsa20poly1305";
const crypto_box_BEFORENMBYTES = 32;
const crypto_box_SEALBYTES = 48;
const crypto_box_ZEROBYTES = 32;
const crypto_box_BOXZEROBYTES = 16;
const crypto_box_curve25519xchacha20poly1305_SEEDBYTES = 32;
const crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES = 32;
const crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES = 32;
const crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES = 32;
const crypto_box_curve25519xchacha20poly1305_NONCEBYTES = 24;
const crypto_box_curve25519xchacha20poly1305_MACBYTES = 16;
const crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_box_curve25519xchacha20poly1305_SEALBYTES = 48;
const crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = 32;
const crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32;
const crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
const crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = 32;
const crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = 24;
const crypto_box_curve25519xsalsa20poly1305_MACBYTES = 16;
const crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = 16;
const crypto_box_curve25519xsalsa20poly1305_ZEROBYTES = 32;
const crypto_core_ed25519_BYTES = 32;
const crypto_core_ed25519_UNIFORMBYTES = 32;
const crypto_core_ed25519_HASHBYTES = 64;
const crypto_core_ed25519_SCALARBYTES = 32;
const crypto_core_ed25519_NONREDUCEDSCALARBYTES = 64;
const crypto_core_hchacha20_OUTPUTBYTES = 32;
const crypto_core_hchacha20_INPUTBYTES = 16;
const crypto_core_hchacha20_KEYBYTES = 32;
const crypto_core_hchacha20_CONSTBYTES = 16;
const crypto_core_hsalsa20_OUTPUTBYTES = 32;
const crypto_core_hsalsa20_INPUTBYTES = 16;
const crypto_core_hsalsa20_KEYBYTES = 32;
const crypto_core_hsalsa20_CONSTBYTES = 16;
const crypto_core_ristretto255_BYTES = 32;
const crypto_core_ristretto255_HASHBYTES = 64;
const crypto_core_ristretto255_SCALARBYTES = 32;
const crypto_core_ristretto255_NONREDUCEDSCALARBYTES = 64;
const crypto_core_salsa20_OUTPUTBYTES = 64;
const crypto_core_salsa20_INPUTBYTES = 16;
const crypto_core_salsa20_KEYBYTES = 32;
const crypto_core_salsa20_CONSTBYTES = 16;
const crypto_core_salsa2012_OUTPUTBYTES = 64;
const crypto_core_salsa2012_INPUTBYTES = 16;
const crypto_core_salsa2012_KEYBYTES = 32;
const crypto_core_salsa2012_CONSTBYTES = 16;
const crypto_core_salsa208_OUTPUTBYTES = 64;
const crypto_core_salsa208_INPUTBYTES = 16;
const crypto_core_salsa208_KEYBYTES = 32;
const crypto_core_salsa208_CONSTBYTES = 16;
const crypto_generichash_BYTES_MIN = 16;
const crypto_generichash_BYTES_MAX = 64;
const crypto_generichash_BYTES = 32;
const crypto_generichash_KEYBYTES_MIN = 16;
const crypto_generichash_KEYBYTES_MAX = 64;
const crypto_generichash_KEYBYTES = 32;
const crypto_generichash_PRIMITIVE = "blake2b";
const crypto_generichash_blake2b_BYTES_MIN = 16;
const crypto_generichash_blake2b_BYTES_MAX = 64;
const crypto_generichash_blake2b_BYTES = 32;
const crypto_generichash_blake2b_KEYBYTES_MIN = 16;
const crypto_generichash_blake2b_KEYBYTES_MAX = 64;
const crypto_generichash_blake2b_KEYBYTES = 32;
const crypto_generichash_blake2b_SALTBYTES = 16;
const crypto_generichash_blake2b_PERSONALBYTES = 16;
const crypto_hash_BYTES = 64;
const crypto_hash_PRIMITIVE = "sha512";
const crypto_hash_sha256_BYTES = 32;
const crypto_hash_sha512_BYTES = 64;
const crypto_kdf_BYTES_MIN = 16;
const crypto_kdf_BYTES_MAX = 64;
const crypto_kdf_CONTEXTBYTES = 8;
const crypto_kdf_KEYBYTES = 32;
const crypto_kdf_PRIMITIVE = "blake2b";
const crypto_kdf_blake2b_BYTES_MIN = 16;
const crypto_kdf_blake2b_BYTES_MAX = 64;
const crypto_kdf_blake2b_CONTEXTBYTES = 8;
const crypto_kdf_blake2b_KEYBYTES = 32;
const crypto_kx_PUBLICKEYBYTES = 32;
const crypto_kx_SECRETKEYBYTES = 32;
const crypto_kx_SEEDBYTES = 32;
const crypto_kx_SESSIONKEYBYTES = 32;
const crypto_kx_PRIMITIVE = "x25519blake2b";
const crypto_onetimeauth_BYTES = 16;
const crypto_onetimeauth_KEYBYTES = 32;
const crypto_onetimeauth_PRIMITIVE = "poly1305";
const crypto_onetimeauth_poly1305_BYTES = 16;
const crypto_onetimeauth_poly1305_KEYBYTES = 32;
const crypto_pwhash_ALG_DEFAULT = 2;
const crypto_pwhash_BYTES_MIN = 16;
const crypto_pwhash_BYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_pwhash_PASSWD_MIN = 0;
const crypto_pwhash_PASSWD_MAX = 4294967295;
const crypto_pwhash_SALTBYTES = 16;
const crypto_pwhash_STRBYTES = 128;
const crypto_pwhash_STRPREFIX = "$argon2id$";
const crypto_pwhash_OPSLIMIT_MIN = 1;
const crypto_pwhash_OPSLIMIT_MAX = 4294967295;
const crypto_pwhash_MEMLIMIT_MIN = 8192;
const crypto_pwhash_MEMLIMIT_MAX = 4398046510080;
const crypto_pwhash_OPSLIMIT_INTERACTIVE = 2;
const crypto_pwhash_MEMLIMIT_INTERACTIVE = 67108864;
const crypto_pwhash_OPSLIMIT_MODERATE = 3;
const crypto_pwhash_MEMLIMIT_MODERATE = 268435456;
const crypto_pwhash_OPSLIMIT_SENSITIVE = 4;
const crypto_pwhash_MEMLIMIT_SENSITIVE = 1073741824;
const crypto_pwhash_PRIMITIVE = "argon2i";
const crypto_pwhash_argon2i_BYTES_MIN = 16;
const crypto_pwhash_argon2i_BYTES_MAX = 4294967295;
const crypto_pwhash_argon2i_PASSWD_MIN = 0;
const crypto_pwhash_argon2i_PASSWD_MAX = 4294967295;
const crypto_pwhash_argon2i_SALTBYTES = 16;
const crypto_pwhash_argon2i_STRBYTES = 128;
const crypto_pwhash_argon2i_STRPREFIX = "$argon2i$";
const crypto_pwhash_argon2i_OPSLIMIT_MIN = 3;
const crypto_pwhash_argon2i_OPSLIMIT_MAX = 4294967295;
const crypto_pwhash_argon2i_MEMLIMIT_MIN = 8192;
const crypto_pwhash_argon2i_MEMLIMIT_MAX = 4398046510080;
const crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE = 4;
const crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE = 33554432;
const crypto_pwhash_argon2i_OPSLIMIT_MODERATE = 6;
const crypto_pwhash_argon2i_MEMLIMIT_MODERATE = 134217728;
const crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE = 8;
const crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE = 536870912;
const crypto_pwhash_argon2id_BYTES_MIN = 16;
const crypto_pwhash_argon2id_BYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_pwhash_argon2id_PASSWD_MIN = 0;
const crypto_pwhash_argon2id_PASSWD_MAX = 4294967295;
const crypto_pwhash_argon2id_SALTBYTES = 16;
const crypto_pwhash_argon2id_STRBYTES = 128;
const crypto_pwhash_argon2id_STRPREFIX = "$argon2id$";
const crypto_pwhash_argon2id_OPSLIMIT_MIN = 1;
const crypto_pwhash_argon2id_OPSLIMIT_MAX = 4294967295;
const crypto_pwhash_argon2id_MEMLIMIT_MIN = 8192;
const crypto_pwhash_argon2id_MEMLIMIT_MAX = 4398046510080;
const crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE = 2;
const crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE = 67108864;
const crypto_pwhash_argon2id_OPSLIMIT_MODERATE = 3;
const crypto_pwhash_argon2id_MEMLIMIT_MODERATE = 268435456;
const crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE = 4;
const crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE = 1073741824;
const crypto_pwhash_scryptsalsa208sha256_BYTES_MIN = 16;
const crypto_pwhash_scryptsalsa208sha256_BYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN = 0;
const crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX = Number.MAX_SAFE_INTEGER;
const crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;
const crypto_pwhash_scryptsalsa208sha256_STRBYTES = 102;
const crypto_pwhash_scryptsalsa208sha256_STRPREFIX = "$7$";
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN = 32768;
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX = 4294967295;
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN = 16777216;
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX = 68719476736;
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = 524288;
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = 16777216;
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = 33554432;
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = 1073741824;
const crypto_scalarmult_BYTES = 32;
const crypto_scalarmult_SCALARBYTES = 32;
const crypto_scalarmult_PRIMITIVE = "curve25519";
const crypto_scalarmult_curve25519_BYTES = 32;
const crypto_scalarmult_curve25519_SCALARBYTES = 32;
const crypto_scalarmult_ed25519_BYTES = 32;
const crypto_scalarmult_ed25519_SCALARBYTES = 32;
const crypto_scalarmult_ristretto255_BYTES = 32;
const crypto_scalarmult_ristretto255_SCALARBYTES = 32;
const crypto_secretbox_KEYBYTES = 32;
const crypto_secretbox_NONCEBYTES = 24;
const crypto_secretbox_MACBYTES = 16;
const crypto_secretbox_PRIMITIVE = "xsalsa20poly1305";
const crypto_secretbox_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_secretbox_ZEROBYTES = 32;
const crypto_secretbox_BOXZEROBYTES = 16;
const crypto_secretbox_xchacha20poly1305_KEYBYTES = 32;
const crypto_secretbox_xchacha20poly1305_NONCEBYTES = 24;
const crypto_secretbox_xchacha20poly1305_MACBYTES = 16;
const crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
const crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;
const crypto_secretbox_xsalsa20poly1305_MACBYTES = 16;
const crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16;
const crypto_secretbox_xsalsa20poly1305_ZEROBYTES = 32;
const crypto_secretstream_xchacha20poly1305_ABYTES = 17;
const crypto_secretstream_xchacha20poly1305_HEADERBYTES = 24;
const crypto_secretstream_xchacha20poly1305_KEYBYTES = 32;
const crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX = SODIUM_SIZE_MAX;
const crypto_secretstream_xchacha20poly1305_TAGBYTES = 1;
const crypto_shorthash_BYTES = 8;
const crypto_shorthash_KEYBYTES = 16;
const crypto_shorthash_PRIMITIVE = "siphash24";
const crypto_shorthash_siphash24_BYTES = 8;
const crypto_shorthash_siphash24_KEYBYTES = 16;
const crypto_shorthash_siphashx24_BYTES = 16;
const crypto_shorthash_siphashx24_KEYBYTES = 16;
const crypto_sign_BYTES = 64;
const crypto_sign_SEEDBYTES = 32;
const crypto_sign_PUBLICKEYBYTES = 32;
const crypto_sign_SECRETKEYBYTES = 64;
const crypto_sign_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER - 64;
const crypto_sign_PRIMITIVE = "ed25519";
const crypto_sign_ed25519_BYTES = 64;
const crypto_sign_ed25519_SEEDBYTES = 32;
const crypto_sign_ed25519_PUBLICKEYBYTES = 32;
const crypto_sign_ed25519_SECRETKEYBYTES = 64;
const crypto_sign_ed25519_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER - 64;
const crypto_sign_edwards25519sha512batch_BYTES = 64;
const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES = 32;
const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES = 64;
const crypto_sign_edwards25519sha512batch_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER - 64;
const crypto_stream_KEYBYTES = 32;
const crypto_stream_NONCEBYTES = 24;
const crypto_stream_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_stream_PRIMITIVE = "xsalsa20";
const crypto_stream_chacha20_KEYBYTES = 32;
const crypto_stream_chacha20_NONCEBYTES = 8;
const crypto_stream_chacha20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_stream_chacha20_ietf_KEYBYTES = 32;
const crypto_stream_chacha20_ietf_NONCEBYTES = 12;
const crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_stream_chacha20_IETF_KEYBYTES = 32;
const crypto_stream_chacha20_IETF_NONCEBYTES = 12;
const crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_stream_salsa20_KEYBYTES = 32;
const crypto_stream_salsa20_NONCEBYTES = 8;
const crypto_stream_salsa20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_stream_salsa2012_KEYBYTES = 32;
const crypto_stream_salsa2012_NONCEBYTES = 8;
const crypto_stream_salsa2012_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_stream_salsa208_KEYBYTES = 32;
const crypto_stream_salsa208_NONCEBYTES = 8;
const crypto_stream_salsa208_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_stream_xchacha20_KEYBYTES = 32;
const crypto_stream_xchacha20_NONCEBYTES = 24;
const crypto_stream_xchacha20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_stream_xsalsa20_KEYBYTES = 32;
const crypto_stream_xsalsa20_NONCEBYTES = 24;
const crypto_stream_xsalsa20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
const crypto_verify_16_BYTES = 16;
const crypto_verify_32_BYTES = 32;
const crypto_verify_64_BYTES = 64;
const randombytes_BYTES_MAX = Number.MAX_SAFE_INTEGER;
const randombytes_SEEDBYTES = 32;
