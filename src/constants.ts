export const SODIUM_SIZE_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_aead_aes256gcm_KEYBYTES = 32;
export const crypto_aead_aes256gcm_NSECBYTES = 0;
export const crypto_aead_aes256gcm_NPUBBYTES = 12;
export const crypto_aead_aes256gcm_ABYTES = 16;
export const crypto_aead_aes256gcm_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
export const crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0;
export const crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
export const crypto_aead_chacha20poly1305_ietf_ABYTES = 16;
export const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_aead_chacha20poly1305_KEYBYTES = 32;
export const crypto_aead_chacha20poly1305_NSECBYTES = 0;
export const crypto_aead_chacha20poly1305_NPUBBYTES = 8;
export const crypto_aead_chacha20poly1305_ABYTES = 16;
export const crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX =
	SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ABYTES;
export const crypto_aead_chacha20poly1305_IETF_KEYBYTES = 32;
export const crypto_aead_chacha20poly1305_IETF_NSECBYTES = 0;
export const crypto_aead_chacha20poly1305_IETF_NPUBBYTES = 24;
export const crypto_aead_chacha20poly1305_IETF_ABYTES = 26;
export const crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX =
	SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_IETF_ABYTES;
export const crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32;
export const crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0;
export const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24;
export const crypto_aead_xchacha20poly1305_ietf_ABYTES = 16;
export const crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = 4294967279;
export const crypto_aead_xchacha20poly1305_IETF_KEYBYTES = 32;
export const crypto_aead_xchacha20poly1305_IETF_NSECBYTES = 0;
export const crypto_aead_xchacha20poly1305_IETF_NPUBBYTES = 24;
export const crypto_aead_xchacha20poly1305_IETF_ABYTES = 16;
export const crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX =
	SODIUM_SIZE_MAX - crypto_aead_xchacha20poly1305_IETF_ABYTES;
export const crypto_auth_BYTES = 32;
export const crypto_auth_KEYBYTES = 32;
export const crypto_auth_PRIMITIVE = "hmacsha512256";
export const crypto_auth_hmacsha256_BYTES = 32;
export const crypto_auth_hmacsha256_KEYBYTES = 32;
export const crypto_auth_hmacsha512_BYTES = 64;
export const crypto_auth_hmacsha512_KEYBYTES = 32;
export const crypto_auth_hmacsha512256_BYTES = 32;
export const crypto_auth_hmacsha512256_KEYBYTES = 32;
export const crypto_box_SEEDBYTES = 32;
export const crypto_box_PUBLICKEYBYTES = 32;
export const crypto_box_SECRETKEYBYTES = 32;
export const crypto_box_NONCEBYTES = 24;
export const crypto_box_MACBYTES = 16;
export const crypto_box_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_box_PRIMITIVE = "curve25519xsalsa20poly1305";
export const crypto_box_BEFORENMBYTES = 32;
export const crypto_box_SEALBYTES = 48;
export const crypto_box_ZEROBYTES = 32;
export const crypto_box_BOXZEROBYTES = 16;
export const crypto_box_curve25519xchacha20poly1305_SEEDBYTES = 32;
export const crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES = 32;
export const crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES = 32;
export const crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES = 32;
export const crypto_box_curve25519xchacha20poly1305_NONCEBYTES = 24;
export const crypto_box_curve25519xchacha20poly1305_MACBYTES = 16;
export const crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_box_curve25519xchacha20poly1305_SEALBYTES = 48;
export const crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = 32;
export const crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32;
export const crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
export const crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = 32;
export const crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = 24;
export const crypto_box_curve25519xsalsa20poly1305_MACBYTES = 16;
export const crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = 16;
export const crypto_box_curve25519xsalsa20poly1305_ZEROBYTES = 32;
export const crypto_core_ed25519_BYTES = 32;
export const crypto_core_ed25519_UNIFORMBYTES = 32;
export const crypto_core_ed25519_HASHBYTES = 64;
export const crypto_core_ed25519_SCALARBYTES = 32;
export const crypto_core_ed25519_NONREDUCEDSCALARBYTES = 64;
export const crypto_core_hchacha20_OUTPUTBYTES = 32;
export const crypto_core_hchacha20_INPUTBYTES = 16;
export const crypto_core_hchacha20_KEYBYTES = 32;
export const crypto_core_hchacha20_CONSTBYTES = 16;
export const crypto_core_hsalsa20_OUTPUTBYTES = 32;
export const crypto_core_hsalsa20_INPUTBYTES = 16;
export const crypto_core_hsalsa20_KEYBYTES = 32;
export const crypto_core_hsalsa20_CONSTBYTES = 16;
export const crypto_core_ristretto255_BYTES = 32;
export const crypto_core_ristretto255_HASHBYTES = 64;
export const crypto_core_ristretto255_SCALARBYTES = 32;
export const crypto_core_ristretto255_NONREDUCEDSCALARBYTES = 64;
export const crypto_core_salsa20_OUTPUTBYTES = 64;
export const crypto_core_salsa20_INPUTBYTES = 16;
export const crypto_core_salsa20_KEYBYTES = 32;
export const crypto_core_salsa20_CONSTBYTES = 16;
export const crypto_core_salsa2012_OUTPUTBYTES = 64;
export const crypto_core_salsa2012_INPUTBYTES = 16;
export const crypto_core_salsa2012_KEYBYTES = 32;
export const crypto_core_salsa2012_CONSTBYTES = 16;
export const crypto_core_salsa208_OUTPUTBYTES = 64;
export const crypto_core_salsa208_INPUTBYTES = 16;
export const crypto_core_salsa208_KEYBYTES = 32;
export const crypto_core_salsa208_CONSTBYTES = 16;
export const crypto_generichash_BYTES_MIN = 16;
export const crypto_generichash_BYTES_MAX = 64;
export const crypto_generichash_BYTES = 32;
export const crypto_generichash_KEYBYTES_MIN = 16;
export const crypto_generichash_KEYBYTES_MAX = 64;
export const crypto_generichash_KEYBYTES = 32;
export const crypto_generichash_PRIMITIVE = "blake2b";
export const crypto_generichash_blake2b_BYTES_MIN = 16;
export const crypto_generichash_blake2b_BYTES_MAX = 64;
export const crypto_generichash_blake2b_BYTES = 32;
export const crypto_generichash_blake2b_KEYBYTES_MIN = 16;
export const crypto_generichash_blake2b_KEYBYTES_MAX = 64;
export const crypto_generichash_blake2b_KEYBYTES = 32;
export const crypto_generichash_blake2b_SALTBYTES = 16;
export const crypto_generichash_blake2b_PERSONALBYTES = 16;
export const crypto_hash_BYTES = 64;
export const crypto_hash_PRIMITIVE = "sha512";
export const crypto_hash_sha256_BYTES = 32;
export const crypto_hash_sha512_BYTES = 64;
export const crypto_kdf_BYTES_MIN = 16;
export const crypto_kdf_BYTES_MAX = 64;
export const crypto_kdf_CONTEXTBYTES = 8;
export const crypto_kdf_KEYBYTES = 32;
export const crypto_kdf_PRIMITIVE = "blake2b";
export const crypto_kdf_blake2b_BYTES_MIN = 16;
export const crypto_kdf_blake2b_BYTES_MAX = 64;
export const crypto_kdf_blake2b_CONTEXTBYTES = 8;
export const crypto_kdf_blake2b_KEYBYTES = 32;
export const crypto_kx_PUBLICKEYBYTES = 32;
export const crypto_kx_SECRETKEYBYTES = 32;
export const crypto_kx_SEEDBYTES = 32;
export const crypto_kx_SESSIONKEYBYTES = 32;
export const crypto_kx_PRIMITIVE = "x25519blake2b";
export const crypto_onetimeauth_BYTES = 16;
export const crypto_onetimeauth_KEYBYTES = 32;
export const crypto_onetimeauth_PRIMITIVE = "poly1305";
export const crypto_onetimeauth_poly1305_BYTES = 16;
export const crypto_onetimeauth_poly1305_KEYBYTES = 32;
export const crypto_pwhash_ALG_DEFAULT = 2;
export const crypto_pwhash_BYTES_MIN = 16;
export const crypto_pwhash_BYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_pwhash_PASSWD_MIN = 0;
export const crypto_pwhash_PASSWD_MAX = 4294967295;
export const crypto_pwhash_SALTBYTES = 16;
export const crypto_pwhash_STRBYTES = 128;
export const crypto_pwhash_STRPREFIX = "$argon2id$";
export const crypto_pwhash_OPSLIMIT_MIN = 1;
export const crypto_pwhash_OPSLIMIT_MAX = 4294967295;
export const crypto_pwhash_MEMLIMIT_MIN = 8192;
export const crypto_pwhash_MEMLIMIT_MAX = 4398046510080;
export const crypto_pwhash_OPSLIMIT_INTERACTIVE = 2;
export const crypto_pwhash_MEMLIMIT_INTERACTIVE = 67108864;
export const crypto_pwhash_OPSLIMIT_MODERATE = 3;
export const crypto_pwhash_MEMLIMIT_MODERATE = 268435456;
export const crypto_pwhash_OPSLIMIT_SENSITIVE = 4;
export const crypto_pwhash_MEMLIMIT_SENSITIVE = 1073741824;
export const crypto_pwhash_PRIMITIVE = "argon2i";
export const crypto_pwhash_argon2i_BYTES_MIN = 16;
export const crypto_pwhash_argon2i_BYTES_MAX = 4294967295;
export const crypto_pwhash_argon2i_PASSWD_MIN = 0;
export const crypto_pwhash_argon2i_PASSWD_MAX = 4294967295;
export const crypto_pwhash_argon2i_SALTBYTES = 16;
export const crypto_pwhash_argon2i_STRBYTES = 128;
export const crypto_pwhash_argon2i_STRPREFIX = "$argon2i$";
export const crypto_pwhash_argon2i_OPSLIMIT_MIN = 3;
export const crypto_pwhash_argon2i_OPSLIMIT_MAX = 4294967295;
export const crypto_pwhash_argon2i_MEMLIMIT_MIN = 8192;
export const crypto_pwhash_argon2i_MEMLIMIT_MAX = 4398046510080;
export const crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE = 4;
export const crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE = 33554432;
export const crypto_pwhash_argon2i_OPSLIMIT_MODERATE = 6;
export const crypto_pwhash_argon2i_MEMLIMIT_MODERATE = 134217728;
export const crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE = 8;
export const crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE = 536870912;
export const crypto_pwhash_argon2id_BYTES_MIN = 16;
export const crypto_pwhash_argon2id_BYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_pwhash_argon2id_PASSWD_MIN = 0;
export const crypto_pwhash_argon2id_PASSWD_MAX = 4294967295;
export const crypto_pwhash_argon2id_SALTBYTES = 16;
export const crypto_pwhash_argon2id_STRBYTES = 128;
export const crypto_pwhash_argon2id_STRPREFIX = "$argon2id$";
export const crypto_pwhash_argon2id_OPSLIMIT_MIN = 1;
export const crypto_pwhash_argon2id_OPSLIMIT_MAX = 4294967295;
export const crypto_pwhash_argon2id_MEMLIMIT_MIN = 8192;
export const crypto_pwhash_argon2id_MEMLIMIT_MAX = 4398046510080;
export const crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE = 2;
export const crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE = 67108864;
export const crypto_pwhash_argon2id_OPSLIMIT_MODERATE = 3;
export const crypto_pwhash_argon2id_MEMLIMIT_MODERATE = 268435456;
export const crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE = 4;
export const crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE = 1073741824;
export const crypto_pwhash_scryptsalsa208sha256_BYTES_MIN = 16;
export const crypto_pwhash_scryptsalsa208sha256_BYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN = 0;
export const crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;
export const crypto_pwhash_scryptsalsa208sha256_STRBYTES = 102;
export const crypto_pwhash_scryptsalsa208sha256_STRPREFIX = "$7$";
export const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN = 32768;
export const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX = 4294967295;
export const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN = 16777216;
export const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX = 68719476736;
export const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = 524288;
export const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = 16777216;
export const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = 33554432;
export const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = 1073741824;
export const crypto_scalarmult_BYTES = 32;
export const crypto_scalarmult_SCALARBYTES = 32;
export const crypto_scalarmult_PRIMITIVE = "curve25519";
export const crypto_scalarmult_curve25519_BYTES = 32;
export const crypto_scalarmult_curve25519_SCALARBYTES = 32;
export const crypto_scalarmult_ed25519_BYTES = 32;
export const crypto_scalarmult_ed25519_SCALARBYTES = 32;
export const crypto_scalarmult_ristretto255_BYTES = 32;
export const crypto_scalarmult_ristretto255_SCALARBYTES = 32;
export const crypto_secretbox_KEYBYTES = 32;
export const crypto_secretbox_NONCEBYTES = 24;
export const crypto_secretbox_MACBYTES = 16;
export const crypto_secretbox_PRIMITIVE = "xsalsa20poly1305";
export const crypto_secretbox_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_secretbox_ZEROBYTES = 32;
export const crypto_secretbox_BOXZEROBYTES = 16;
export const crypto_secretbox_xchacha20poly1305_KEYBYTES = 32;
export const crypto_secretbox_xchacha20poly1305_NONCEBYTES = 24;
export const crypto_secretbox_xchacha20poly1305_MACBYTES = 16;
export const crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
export const crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;
export const crypto_secretbox_xsalsa20poly1305_MACBYTES = 16;
export const crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16;
export const crypto_secretbox_xsalsa20poly1305_ZEROBYTES = 32;
export const crypto_secretstream_xchacha20poly1305_ABYTES = 17;
export const crypto_secretstream_xchacha20poly1305_HEADERBYTES = 24;
export const crypto_secretstream_xchacha20poly1305_KEYBYTES = 32;
export const crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX =
	SODIUM_SIZE_MAX;
export const crypto_secretstream_xchacha20poly1305_TAGBYTES = 1;
export const crypto_shorthash_BYTES = 8;
export const crypto_shorthash_KEYBYTES = 16;
export const crypto_shorthash_PRIMITIVE = "siphash24";
export const crypto_shorthash_siphash24_BYTES = 8;
export const crypto_shorthash_siphash24_KEYBYTES = 16;
export const crypto_shorthash_siphashx24_BYTES = 16;
export const crypto_shorthash_siphashx24_KEYBYTES = 16;
export const crypto_sign_BYTES = 64;
export const crypto_sign_SEEDBYTES = 32;
export const crypto_sign_PUBLICKEYBYTES = 32;
export const crypto_sign_SECRETKEYBYTES = 64;
export const crypto_sign_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER - 64;
export const crypto_sign_PRIMITIVE = "ed25519";
export const crypto_sign_ed25519_BYTES = 64;
export const crypto_sign_ed25519_SEEDBYTES = 32;
export const crypto_sign_ed25519_PUBLICKEYBYTES = 32;
export const crypto_sign_ed25519_SECRETKEYBYTES = 64;
export const crypto_sign_ed25519_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER - 64;
export const crypto_sign_edwards25519sha512batch_BYTES = 64;
export const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES = 32;
export const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES = 64;
export const crypto_sign_edwards25519sha512batch_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER - 64;
export const crypto_stream_KEYBYTES = 32;
export const crypto_stream_NONCEBYTES = 24;
export const crypto_stream_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_stream_PRIMITIVE = "xsalsa20";
export const crypto_stream_chacha20_KEYBYTES = 32;
export const crypto_stream_chacha20_NONCEBYTES = 8;
export const crypto_stream_chacha20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_stream_chacha20_ietf_KEYBYTES = 32;
export const crypto_stream_chacha20_ietf_NONCEBYTES = 12;
export const crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_stream_chacha20_IETF_KEYBYTES = 32;
export const crypto_stream_chacha20_IETF_NONCEBYTES = 12;
export const crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_stream_salsa20_KEYBYTES = 32;
export const crypto_stream_salsa20_NONCEBYTES = 8;
export const crypto_stream_salsa20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_stream_salsa2012_KEYBYTES = 32;
export const crypto_stream_salsa2012_NONCEBYTES = 8;
export const crypto_stream_salsa2012_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_stream_salsa208_KEYBYTES = 32;
export const crypto_stream_salsa208_NONCEBYTES = 8;
export const crypto_stream_salsa208_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_stream_xchacha20_KEYBYTES = 32;
export const crypto_stream_xchacha20_NONCEBYTES = 24;
export const crypto_stream_xchacha20_MESSAGEBYTES_MAX =
	Number.MAX_SAFE_INTEGER;
export const crypto_stream_xsalsa20_KEYBYTES = 32;
export const crypto_stream_xsalsa20_NONCEBYTES = 24;
export const crypto_stream_xsalsa20_MESSAGEBYTES_MAX = Number.MAX_SAFE_INTEGER;
export const crypto_verify_16_BYTES = 16;
export const crypto_verify_32_BYTES = 32;
export const crypto_verify_64_BYTES = 64;
export const randombytes_BYTES_MAX = Number.MAX_SAFE_INTEGER;
export const randombytes_SEEDBYTES = 32;
