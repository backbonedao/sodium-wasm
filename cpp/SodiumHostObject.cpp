#include "SodiumHostObject.h"
#include "JSI Utils/Uint8Array.h"
#include <jsi/jsi.h>
#include "sodium.h"

namespace screamingvoid {

using namespace facebook::jsi;
using namespace std;

SodiumHostObject::SodiumHostObject() {
	if (sodium_init() < 0) {
		throw runtime_error("Failed to initialize sodium");
	}
}

vector<PropNameID> SodiumHostObject::getPropertyNames(Runtime& runtime) {
	vector<PropNameID> result;

	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_encrypt"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_decrypt"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_encrypt_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_decrypt_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_encrypt"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_decrypt"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_encrypt_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_decrypt_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_encrypt"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_decrypt"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_encrypt_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_decrypt_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_auth"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_auth_verify"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_auth_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_box_keypair"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_box_seed_keypair"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_box_easy"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_box_open_easy"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_box_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_box_open_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_is_valid_point"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_random"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_from_uniform"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_add"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_sub"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_random"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_reduce"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_invert"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_negate"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_complement"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_add"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_sub"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_mul"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_generichash_STATEBYTES"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_generichash"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_generichash_init"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_generichash_update"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_generichash_final"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_generichash_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha256_STATEBYTES"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha256"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha256_init"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha256_update"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha256_final"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha512_STATEBYTES"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha512"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha512_init"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha512_update"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_hash_sha512_final"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_kdf_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_kdf_derive_from_key"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_kx_keypair"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_kx_seed_keypair"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_kx_client_session_keys"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_kx_server_session_keys"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_onetimeauth_STATEBYTES"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_onetimeauth"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_onetimeauth_verify"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_onetimeauth_init"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_onetimeauth_update"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_onetimeauth_final"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_onetimeauth_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_ALG_ARGON2I13"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_ALG_ARGON2ID13"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_str"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_str_verify"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_str_needs_rehash"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_scryptsalsa208sha256"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_scryptsalsa208sha256_str"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_scryptsalsa208sha256_str_verify"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_pwhash_scryptsalsa208sha256_str_needs_rehash"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_scalarmult_base"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_scalarmult"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_scalarmult_ed25519"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_scalarmult_ed25519_base"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_scalarmult_ed25519_noclamp"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_scalarmult_ed25519_base_noclamp"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretbox_easy"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretbox_open_easy"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretbox_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretbox_open_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretbox_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_TAG_MESSAGE"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_TAG_PUSH"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_TAG_REKEY"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_TAG_FINAL"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_STATEBYTES"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_init_push"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_push"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_init_pull"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_pull"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_rekey"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_shorthash_keygen"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_shorthash"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_shorthash_siphashx24"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_STATEBYTES"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_keypair"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_seed_keypair"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_open"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_verify_detached"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_ed25519_sk_to_pk"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_ed25519_pk_to_curve25519"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_sign_ed25519_sk_to_curve25519"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_xor"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_chacha20"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_chacha20_xor"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_chacha20_xor_ic"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_chacha20_ietf"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_chacha20_ietf_xor"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_chacha20_ietf_xor_ic"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_xchacha20"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_xchacha20_xor"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_xchacha20_xor_ic"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_salsa20"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_salsa20_xor"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_stream_salsa20_xor_ic"));
	result.push_back(PropNameID::forUtf8(runtime, "randombytes_random"));
	result.push_back(PropNameID::forUtf8(runtime, "randombytes_uniform"));
	result.push_back(PropNameID::forUtf8(runtime, "randombytes_buf"));
	result.push_back(PropNameID::forUtf8(runtime, "randombytes_buf_deterministic"));
	result.push_back(PropNameID::forUtf8(runtime, "sodium_memcmp"));
	result.push_back(PropNameID::forUtf8(runtime, "sodium_increment"));
	result.push_back(PropNameID::forUtf8(runtime, "sodium_add"));
	result.push_back(PropNameID::forUtf8(runtime, "sodium_sub"));
	result.push_back(PropNameID::forUtf8(runtime, "sodium_compare"));
	result.push_back(PropNameID::forUtf8(runtime, "sodium_is_zero"));
	result.push_back(PropNameID::forUtf8(runtime, "sodium_pad"));
	result.push_back(PropNameID::forUtf8(runtime, "sodium_unpad"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_box_seal"));
	result.push_back(PropNameID::forUtf8(runtime, "crypto_box_seal_open"));

	return result;
}

Value SodiumHostObject::get(Runtime& runtime, const PropNameID& propNameId) {
	auto propName = propNameId.utf8(runtime);

	if (propName == "crypto_aead_chacha20poly1305_encrypt") {
		auto aead_chacha20poly1305_encrypt = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto npub = Uint8Array(runtime, arguments[4]);
			auto k = Uint8Array(runtime, arguments[5]);
			unsigned long  long int clen_p;
			if (arguments[2].isNull()) {
				crypto_aead_chacha20poly1305_encrypt(c.toArray(runtime), &clen_p, m.toArray(runtime),
													 m.byteLength(runtime), nullptr, 0, nullptr,
													 npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[2]);
				crypto_aead_chacha20poly1305_encrypt(c.toArray(runtime), &clen_p, m.toArray(runtime),
													 m.byteLength(runtime), ad.toArray(runtime), ad.byteLength(runtime),
													 nullptr, npub.toArray(runtime), k.toArray(runtime));
			}
			return Value((int) clen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_encrypt"), 6, aead_chacha20poly1305_encrypt);
	}
	if (propName == "crypto_aead_chacha20poly1305_decrypt") {
		auto aead_chacha20poly1305_decrypt = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[2]);
			auto npub = Uint8Array(runtime, arguments[4]);
			auto k = Uint8Array(runtime, arguments[5]);
			unsigned long long int mlen_p;
			int ret;
			if (arguments[3].isNull()) {
				ret = crypto_aead_chacha20poly1305_decrypt(m.toArray(runtime), &mlen_p, nullptr,
													 c.toArray(runtime), c.byteLength(runtime),
													 nullptr, 0,
													 npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[3]);
				ret = crypto_aead_chacha20poly1305_decrypt(m.toArray(runtime), &mlen_p, nullptr,
														   c.toArray(runtime), c.byteLength(runtime),
														   ad.toArray(runtime), ad.byteLength(runtime),
														   npub.toArray(runtime), k.toArray(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid mac");
			}
			return Value((int) mlen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_decrypt"), 6, aead_chacha20poly1305_decrypt);
	}
	if (propName == "crypto_aead_chacha20poly1305_encrypt_detached") {
		auto aead_chacha20poly1305_encrypt_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto mac = Uint8Array(runtime, arguments[1]);
			auto m = Uint8Array(runtime, arguments[2]);
			auto npub = Uint8Array(runtime, arguments[5]);
			auto k = Uint8Array(runtime, arguments[6]);
			unsigned long long int maclen_p;
			if (arguments[3].isNull()) {
				crypto_aead_chacha20poly1305_encrypt_detached(c.toArray(runtime), mac.toArray(runtime),
															  &maclen_p, m.toArray(runtime), m.byteLength(runtime),
															  nullptr, 0, nullptr,
															  npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[3]);
				crypto_aead_chacha20poly1305_encrypt_detached(c.toArray(runtime), mac.toArray(runtime),
															  &maclen_p, m.toArray(runtime), m.byteLength(runtime),
															  ad.toArray(runtime), ad.byteLength(runtime),
															  nullptr, npub.toArray(runtime), k.toArray(runtime));
			}
			return Value((int) maclen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_encrypt_detached"), 7, aead_chacha20poly1305_encrypt_detached);
	}
	if (propName == "crypto_aead_chacha20poly1305_decrypt_detached") {
		auto aead_chacha20poly1305_decrypt_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[2]);
			auto mac = Uint8Array(runtime, arguments[3]);
			auto npub = Uint8Array(runtime, arguments[5]);
			auto k = Uint8Array(runtime, arguments[6]);
			int ret;
			if (arguments[3].isNull()) {
				ret = crypto_aead_chacha20poly1305_decrypt_detached(m.toArray(runtime), nullptr,
																	c.toArray(runtime), c.byteLength(runtime),
																	mac.toArray(runtime), nullptr, 0,
																	npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[3]);
				ret = crypto_aead_chacha20poly1305_decrypt_detached(m.toArray(runtime), nullptr,
																	c.toArray(runtime), c.byteLength(runtime),
																	mac.toArray(runtime), ad.toArray(runtime),
																	ad.byteLength(runtime), npub.toArray(runtime),
																	k.toArray(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid mac");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_decrypt_detached"), 7, aead_chacha20poly1305_decrypt_detached);
	}
	if (propName == "crypto_aead_chacha20poly1305_keygen") {
		auto aead_chacha20poly1305_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_aead_chacha20poly1305_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_keygen"), 1, aead_chacha20poly1305_keygen);
	}
	if (propName == "crypto_aead_chacha20poly1305_ietf_encrypt") {
		auto aead_chacha20poly1305_ietf_encrypt = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto npub = Uint8Array(runtime, arguments[4]);
			auto k = Uint8Array(runtime, arguments[5]);
			unsigned long long int clen_p;
			if (arguments[2].isNull()) {
				crypto_aead_chacha20poly1305_ietf_encrypt(c.toArray(runtime), &clen_p,
														  m.toArray(runtime), m.byteLength(runtime),
														  nullptr, 0, nullptr,
														  npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[2]);
				crypto_aead_chacha20poly1305_ietf_encrypt(c.toArray(runtime), &clen_p,
														  m.toArray(runtime), m.byteLength(runtime),
														  ad.toArray(runtime), ad.byteLength(runtime),
														  nullptr, npub.toArray(runtime), k.toArray(runtime));
			}
			return Value((int) clen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_encrypt"), 6, aead_chacha20poly1305_ietf_encrypt);
	}
	if (propName == "crypto_aead_chacha20poly1305_ietf_decrypt") {
		auto aead_chacha20poly1305_ietf_decrypt = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[2]);
			auto npub = Uint8Array(runtime, arguments[4]);
			auto k = Uint8Array(runtime, arguments[5]);
			unsigned long long int mlen_p;
			int ret;
			if (arguments[3].isNull()) {
				ret = crypto_aead_chacha20poly1305_ietf_decrypt(m.toArray(runtime), &mlen_p,
				                                                nullptr, c.toArray(runtime), c.byteLength(runtime),
				                                                nullptr, 0, npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[3]);
				ret = crypto_aead_chacha20poly1305_ietf_decrypt(m.toArray(runtime), &mlen_p, nullptr,
																c.toArray(runtime), c.byteLength(runtime),
																ad.toArray(runtime), ad.byteLength(runtime),
																npub.toArray(runtime), k.toArray(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid mac");
			}
			return Value((int) mlen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_decrypt"), 6, aead_chacha20poly1305_ietf_decrypt);
	}
	if (propName == "crypto_aead_chacha20poly1305_ietf_encrypt_detached") {
		auto aead_chacha20poly1305_ietf_encrypt_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto mac = Uint8Array(runtime, arguments[1]);
			auto m = Uint8Array(runtime, arguments[2]);
			auto npub = Uint8Array(runtime, arguments[5]);
			auto k = Uint8Array(runtime, arguments[6]);
			unsigned long long int maclen_p;
			if (arguments[3].isNull()) {
				crypto_aead_chacha20poly1305_ietf_encrypt_detached(c.toArray(runtime), mac.toArray(runtime), &maclen_p,
																   m.toArray(runtime), m.byteLength(runtime),
																   nullptr, 0, nullptr,
																   npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[3]);
				crypto_aead_chacha20poly1305_ietf_encrypt_detached(c.toArray(runtime), mac.toArray(runtime), &maclen_p,
																   m.toArray(runtime), m.byteLength(runtime),
																   ad.toArray(runtime), ad.byteLength(runtime),
																   nullptr, npub.toArray(runtime), k.toArray(runtime));
			}
			return Value((int) maclen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_encrypt_detached"), 7, aead_chacha20poly1305_ietf_encrypt_detached);
	}
	if (propName == "crypto_aead_chacha20poly1305_ietf_decrypt_detached") {
		auto aead_chacha20poly1305_ietf_decrypt_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[2]);
			auto mac = Uint8Array(runtime, arguments[3]);
			auto npub = Uint8Array(runtime, arguments[5]);
			auto k = Uint8Array(runtime, arguments[6]);
			int ret;
			if (arguments[4].isNull()) {
				ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(m.toArray(runtime), nullptr,
																		 c.toArray(runtime), c.byteLength(runtime),
																		 mac.toArray(runtime),
																		 nullptr, 0,
																		 npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[4]);
				ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(m.toArray(runtime), nullptr,
																		 c.toArray(runtime), c.byteLength(runtime),
																		 mac.toArray(runtime), ad.toArray(runtime), ad.byteLength(runtime),
																		 npub.toArray(runtime), k.toArray(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid mac");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime,"crypto_aead_chacha20poly1305_ietf_decrypt_detached"), 7, aead_chacha20poly1305_ietf_decrypt_detached);
	}
	if (propName == "crypto_aead_chacha20poly1305_ietf_keygen") {
		auto aead_chacha20poly1305_ietf_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_aead_chacha20poly1305_ietf_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_chacha20poly1305_ietf_keygen"), 1, aead_chacha20poly1305_ietf_keygen);
	}
	if (propName == "crypto_aead_xchacha20poly1305_ietf_encrypt") {
		auto aead_xchacha20poly1305_ietf_encrypt = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto npub = Uint8Array(runtime, arguments[4]);
			auto k = Uint8Array(runtime, arguments[5]);
			unsigned long long int clen_p;
			if (arguments[2].isNull()) {
				crypto_aead_xchacha20poly1305_ietf_encrypt(c.toArray(runtime), &clen_p,
														   m.toArray(runtime), m.byteLength(runtime),
														   nullptr, 0, nullptr,
														   npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[2]);
				crypto_aead_xchacha20poly1305_ietf_encrypt(c.toArray(runtime), &clen_p,
														   m.toArray(runtime), m.byteLength(runtime),
														   ad.toArray(runtime), ad.byteLength(runtime),
														   nullptr, npub.toArray(runtime), k.toArray(runtime));
			}
			return Value((int) clen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_encrypt"), 6, aead_xchacha20poly1305_ietf_encrypt);
	}
	if (propName == "crypto_aead_xchacha20poly1305_ietf_decrypt") {
		auto aead_xchacha20poly1305_ietf_decrypt = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[2]);
			auto npub = Uint8Array(runtime, arguments[4]);
			auto k = Uint8Array(runtime, arguments[5]);
			unsigned long long int mlen_p;
			int ret;
			if (m.byteLength(runtime) < c.byteLength(runtime) - crypto_aead_xchacha20poly1305_ietf_ABYTES) {
				throw JSError(runtime, "m length must be at least c length - crypto_aead_xchacha20poly1305_ietf_ABYTES");
			}
			if (arguments[3].isNull()) {
				ret = crypto_aead_xchacha20poly1305_ietf_decrypt(m.toArray(runtime), &mlen_p,
				                                                 nullptr, c.toArray(runtime), c.byteLength(runtime),
				                                                 nullptr, 0, npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[3]);
				ret = crypto_aead_xchacha20poly1305_ietf_decrypt(m.toArray(runtime), &mlen_p,
				                                                 nullptr, c.toArray(runtime), c.byteLength(runtime),
				                                                 ad.toArray(runtime), ad.byteLength(runtime),
				                                                 npub.toArray(runtime), k.toArray(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid mac");
			}
			return Value((int) mlen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_decrypt"), 6, aead_xchacha20poly1305_ietf_decrypt);
	}
	if (propName == "crypto_aead_xchacha20poly1305_ietf_encrypt_detached") {
		auto aead_xchacha20poly1305_ietf_encrypt_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto mac = Uint8Array(runtime, arguments[1]);
			auto m = Uint8Array(runtime, arguments[2]);
			auto npub = Uint8Array(runtime, arguments[5]);
			auto k = Uint8Array(runtime, arguments[6]);
			unsigned long long int maclen_p;
			if (arguments[3].isNull()) {
				crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c.toArray(runtime), mac.toArray(runtime), &maclen_p,
																	m.toArray(runtime), m.byteLength(runtime),
																	nullptr, 0, nullptr,
																	npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[3]);
				crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c.toArray(runtime), mac.toArray(runtime), &maclen_p,
																	m.toArray(runtime), m.byteLength(runtime),
																	ad.toArray(runtime), ad.byteLength(runtime),
																	nullptr, npub.toArray(runtime), k.toArray(runtime));
			}
			return Value((int) maclen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_encrypt_detached"), 7, aead_xchacha20poly1305_ietf_encrypt_detached);
	}
	if (propName == "crypto_aead_xchacha20poly1305_ietf_decrypt_detached") {
		auto aead_xchacha20poly1305_ietf_decrypt_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[2]);
			auto mac = Uint8Array(runtime, arguments[3]);
			auto npub = Uint8Array(runtime, arguments[5]);
			auto k = Uint8Array(runtime, arguments[6]);
			int ret;
			if (arguments[4].isNull()) {
				ret = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m.toArray(runtime),
				                                                          nullptr,
				                                                          c.toArray(runtime), c.byteLength(runtime),
				                                                          mac.toArray(runtime),
				                                                          nullptr, 0,
				                                                          npub.toArray(runtime), k.toArray(runtime));
			} else {
				auto ad = Uint8Array(runtime, arguments[4]);
				ret = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m.toArray(runtime),
				                                                          nullptr,
				                                                          c.toArray(runtime), c.byteLength(runtime),
				                                                          mac.toArray(runtime), ad.toArray(runtime), ad.byteLength(runtime),
				                                                          npub.toArray(runtime), k.toArray(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid mac");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_decrypt_detached"), 7, aead_xchacha20poly1305_ietf_decrypt_detached);
	}
	if (propName == "crypto_aead_xchacha20poly1305_ietf_keygen") {
		auto aead_xchacha20poly1305_ietf_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_aead_xchacha20poly1305_ietf_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_aead_xchacha20poly1305_ietf_keygen"), 1, aead_xchacha20poly1305_ietf_keygen);
	}
	if (propName == "crypto_auth") {
		auto auth = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_auth(out.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_auth"), 3, auth);
	}
	if (propName == "crypto_auth_verify") {
		auto auth_verify = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto h = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			auto  k = Uint8Array(runtime, arguments[2]);
			int ret = crypto_auth_verify(h.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime), k.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_auth_verify"), 3, auth_verify);
	}
	if (propName == "crypto_auth_keygen") {
		auto auth_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_auth_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_auth_keygen"), 1, auth_keygen);
	}
	if (propName == "crypto_box_keypair") {
		auto box_keypair = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto pk = Uint8Array(runtime, arguments[0]);
			auto sk = Uint8Array(runtime, arguments[1]);
			int ret = crypto_box_keypair(pk.toArray(runtime), sk.toArray(runtime));
			return Value(ret);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_box_keypair"), 2, box_keypair);
	}
	if (propName == "crypto_box_seed_keypair") {
		auto box_seed_keypair = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto pk = Uint8Array(runtime, arguments[0]);
			auto sk = Uint8Array(runtime, arguments[1]);
			auto seed = Uint8Array(runtime, arguments[2]);
			int ret = crypto_box_seed_keypair(pk.toArray(runtime), sk.toArray(runtime), seed.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_box_seed_keypair"), 3, box_seed_keypair);
	}
	if (propName == "crypto_box_easy") {
		auto box_easy = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto pk = Uint8Array(runtime, arguments[3]);
			auto sk = Uint8Array(runtime, arguments[4]);
			int ret = crypto_box_easy(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), pk.toArray(runtime), sk.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_box_easy"), 5, box_easy);
	}
	if (propName == "crypto_box_open_easy") {
		auto box_open_easy = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto pk = Uint8Array(runtime, arguments[3]);
			auto sk = Uint8Array(runtime, arguments[4]);
			int ret = crypto_box_open_easy(m.toArray(runtime), c.toArray(runtime), c.byteLength(runtime), n.toArray(runtime), pk.toArray(runtime), sk.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_box_open_easy"), 5, box_open_easy);
	}
	if (propName == "crypto_box_detached") {
		auto box_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto mac = Uint8Array(runtime, arguments[1]);
			auto m = Uint8Array(runtime, arguments[2]);
			auto n = Uint8Array(runtime, arguments[3]);
			auto pk = Uint8Array(runtime, arguments[4]);
			auto sk = Uint8Array(runtime, arguments[5]);
			int ret = crypto_box_detached(c.toArray(runtime), mac.toArray(runtime),
										  m.toArray(runtime), m.byteLength(runtime),
										  n.toArray(runtime),
										  pk.toArray(runtime), sk.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_box_detached"), 6, box_detached);
	}
	if (propName == "crypto_box_open_detached") {
		auto box_open_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[1]);
			auto mac = Uint8Array(runtime, arguments[2]);
			auto n = Uint8Array(runtime, arguments[3]);
			auto pk = Uint8Array(runtime, arguments[4]);
			auto sk = Uint8Array(runtime, arguments[5]);
			int ret = crypto_box_open_detached(m.toArray(runtime), c.toArray(runtime),
											   mac.toArray(runtime), c.byteLength(runtime),
											   n.toArray(runtime), pk.toArray(runtime), sk.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_box_open_detached"), 6, box_open_detached);
	}
	if (propName == "crypto_core_ed25519_is_valid_point") {
		auto core_ed25519_is_valid_point = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto p = Uint8Array(runtime, arguments[0]);
			int ret = crypto_core_ed25519_is_valid_point(p.toArray(runtime));
			return Value((bool) ret);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_is_valid_point"), 1, core_ed25519_is_valid_point);
	}
	if (propName == "crypto_core_ed25519_random") {
		auto core_ed25519_random = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto p = Uint8Array(runtime, arguments[0]);
			crypto_core_ed25519_random(p.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_random"), 1, core_ed25519_random);
	}
	if (propName == "crypto_core_ed25519_from_uniform") {
		auto core_ed25519_from_uniform = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto p = Uint8Array(runtime, arguments[0]);
			auto r = Uint8Array(runtime, arguments[1]);
			int ret = crypto_core_ed25519_from_uniform(p.toArray(runtime), r.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_from_uniform"), 2, core_ed25519_from_uniform);
	}
	if (propName == "crypto_core_ed25519_add") {
		auto core_ed25519_add = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto r = Uint8Array(runtime, arguments[0]);
			auto p = Uint8Array(runtime, arguments[1]);
			auto q = Uint8Array(runtime, arguments[2]);
			int ret = crypto_core_ed25519_add(r.toArray(runtime), p.toArray(runtime), q.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Not a valid curve point");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_add"), 3, core_ed25519_add);
	}
	if (propName == "crypto_core_ed25519_sub") {
		auto core_ed25519_sub = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto r = Uint8Array(runtime, arguments[0]);
			auto p = Uint8Array(runtime, arguments[1]);
			auto q = Uint8Array(runtime, arguments[2]);
			int ret = crypto_core_ed25519_sub(r.toArray(runtime), p.toArray(runtime), q.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Not a valid curve point");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_sub"), 3, core_ed25519_sub);
	}
	if (propName == "crypto_core_ed25519_scalar_random") {
		auto core_ed25519_scalar_random = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto r = Uint8Array(runtime, arguments[0]);
			crypto_core_ed25519_scalar_random(r.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_random"), 1, core_ed25519_scalar_random);
	}
	if (propName == "crypto_core_ed25519_scalar_reduce") {
		auto core_ed25519_scalar_reduce = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto r = Uint8Array(runtime, arguments[0]);
			auto s = Uint8Array(runtime, arguments[1]);
			crypto_core_ed25519_scalar_reduce(r.toArray(runtime), s.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_reduce"), 2, core_ed25519_scalar_reduce);
	}
	if (propName == "crypto_core_ed25519_scalar_invert") {
		auto core_ed25519_scalar_invert = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto recip = Uint8Array(runtime, arguments[0]);
			auto  s = Uint8Array(runtime, arguments[1]);
			int ret = crypto_core_ed25519_scalar_invert(recip.toArray(runtime), s.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_invert"), 2, core_ed25519_scalar_invert);
	}
	if (propName == "crypto_core_ed25519_scalar_negate") {
		auto core_ed25519_scalar_negate = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto neg = Uint8Array(runtime, arguments[0]);
			auto s = Uint8Array(runtime, arguments[1]);
			crypto_core_ed25519_scalar_negate(neg.toArray(runtime), s.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_negate"), 2, core_ed25519_scalar_negate);
	}
	if (propName == "crypto_core_ed25519_scalar_complement") {
		auto core_ed25519_scalar_complement = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto comp = Uint8Array(runtime, arguments[0]);
			auto s = Uint8Array(runtime, arguments[1]);
			crypto_core_ed25519_scalar_complement(comp.toArray(runtime), s.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_complement"), 2, core_ed25519_scalar_complement);
	}
	if (propName == "crypto_core_ed25519_scalar_add") {
		auto core_ed25519_scalar_add = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto z = Uint8Array(runtime, arguments[0]);
			auto x = Uint8Array(runtime, arguments[1]);
			auto y = Uint8Array(runtime, arguments[2]);
			crypto_core_ed25519_scalar_add(z.toArray(runtime), x.toArray(runtime), y.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_add"), 3, core_ed25519_scalar_add);
	}
	if (propName == "crypto_core_ed25519_scalar_sub") {
		auto core_ed25519_scalar_sub = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto z = Uint8Array(runtime, arguments[0]);
			auto x = Uint8Array(runtime, arguments[1]);
			auto y = Uint8Array(runtime, arguments[2]);
			crypto_core_ed25519_scalar_sub(z.toArray(runtime), x.toArray(runtime), y.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_sub"), 3, core_ed25519_scalar_sub);
	}
	if (propName == "crypto_core_ed25519_scalar_mul") {
		auto core_ed25519_scalar_mul = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto z = Uint8Array(runtime, arguments[0]);
			auto x = Uint8Array(runtime, arguments[1]);
			auto y = Uint8Array(runtime, arguments[2]);
			crypto_core_ed25519_scalar_mul(z.toArray(runtime), x.toArray(runtime), y.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_core_ed25519_scalar_mul"), 3, core_ed25519_scalar_mul);
	}
	if (propName == "crypto_generichash_STATEBYTES") {
		return Value((int) crypto_generichash_statebytes());
	}
	if (propName == "crypto_generichash") {
		auto generichash = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			int ret;
			if (arguments[2].isNull() || arguments[2].isUndefined()) {
				ret = crypto_generichash(out.toArray(runtime), out.byteLength(runtime),
										 inp.toArray(runtime), inp.byteLength(runtime),
				                         nullptr, 0);
			} else {
				auto key = Uint8Array(runtime, arguments[2]);
				ret = crypto_generichash(out.toArray(runtime), out.byteLength(runtime),
										 inp.toArray(runtime), inp.byteLength(runtime),
										 key.toArray(runtime), key.byteLength(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_generichash"), 3, generichash);
	}
	if (propName == "crypto_generichash_init") {
		auto generichash_init = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			int outlen = arguments[2].getNumber();
			if (arguments[1].isNull() || arguments[1].isUndefined()) {
				crypto_generichash_init((crypto_generichash_state*) state.toArray(runtime), nullptr, 0, outlen);
			} else {
				auto key = Uint8Array(runtime, arguments[1]);
				crypto_generichash_init((crypto_generichash_state*) state.toArray(runtime), key.toArray(runtime), key.byteLength(runtime), outlen);
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_generichash_init"), 3, generichash_init);
	}
	if (propName == "crypto_generichash_update") {
		auto generichash_update = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			crypto_generichash_update((crypto_generichash_state*) state.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_generichash_update"), 2, generichash_update);
	}
	if (propName == "crypto_generichash_final") {
		auto generichash_final = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto out = Uint8Array(runtime, arguments[1]);
			crypto_generichash_final((crypto_generichash_state*) state.toArray(runtime), out.toArray(runtime), out.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_generichash_final"), 2, generichash_final);
	}
	if (propName == "crypto_generichash_keygen") {
		auto generichash_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_generichash_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_generichash_keygen"), 1, generichash_keygen);
	}
	if (propName == "crypto_hash") {
		auto hash = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			crypto_hash(out.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash"), 2, hash);
	}
	if (propName == "crypto_hash_sha256_STATEBYTES") {
		return Value((int) crypto_hash_sha256_statebytes());
	}
	if (propName == "crypto_hash_sha256") {
		auto hash_sha256 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			crypto_hash_sha256(out.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash_sha256"), 2, hash_sha256);
	}
	if (propName == "crypto_hash_sha256_init") {
		auto hash_sha256_init = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			crypto_hash_sha256_init((crypto_hash_sha256_state*) state.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash_sha256_init"), 1, hash_sha256_init);
	}
	if (propName == "crypto_hash_sha256_update") {
		auto hash_sha256_update = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			crypto_hash_sha256_update((crypto_hash_sha256_state*) state.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash_sha256_update"), 2, hash_sha256_update);
	}
	if (propName == "crypto_hash_sha256_final") {
		auto hash_sha256_final = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto out = Uint8Array(runtime, arguments[1]);
			crypto_hash_sha256_final((crypto_hash_sha256_state*) state.toArray(runtime), out.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash_sha256_final"), 2, hash_sha256_final);
	}
	if (propName == "crypto_hash_sha512_STATEBYTES") {
		return Value((int) crypto_hash_sha512_statebytes());
	}
	if (propName == "crypto_hash_sha512") {
		auto hash_sha512 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			crypto_hash_sha512(out.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash_sha512"), 2, hash_sha512);
	}
	if (propName == "crypto_hash_sha512_init") {
		auto hash_sha512_init = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			crypto_hash_sha512_init((crypto_hash_sha512_state*) state.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash_sha512_init"), 1, hash_sha512_init);
	}
	if (propName == "crypto_hash_sha512_update") {
		auto hash_sha512_update = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			crypto_hash_sha512_update((crypto_hash_sha512_state*) state.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash_sha512_update"), 2, hash_sha512_update);
	}
	if (propName == "crypto_hash_sha512_final") {
		auto hash_sha512_final = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto out = Uint8Array(runtime, arguments[1]);
			crypto_hash_sha512_final((crypto_hash_sha512_state*) state.toArray(runtime), out.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_hash_sha512_final"), 2, hash_sha512_final);
	}
	if (propName == "crypto_kdf_keygen") {
		auto kdf_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto key = Uint8Array(runtime, arguments[0]);
			crypto_kdf_keygen(key.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_kdf_keygen"), 1, kdf_keygen);
	}
	if (propName == "crypto_kdf_derive_from_key") {
		auto kdf_derive_from_key = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto subkey = Uint8Array(runtime, arguments[0]);
			unsigned long long int subkey_id = arguments[1].getNumber();
			auto ctx = Uint8Array(runtime, arguments[2]);
			auto key = Uint8Array(runtime, arguments[3]);
			crypto_kdf_derive_from_key(subkey.toArray(runtime), subkey.byteLength(runtime), subkey_id, (char *) ctx.toArray(runtime), key.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_kdf_derive_from_key"), 4, kdf_derive_from_key);
	}
	if (propName == "crypto_kx_keypair") {
		auto kx_keypair = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto pk = Uint8Array(runtime, arguments[0]);
			auto sk = Uint8Array(runtime, arguments[1]);
			crypto_kx_keypair(pk.toArray(runtime), sk.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_kx_keypair"), 2, kx_keypair);
	}
	if (propName == "crypto_kx_seed_keypair") {
		auto kx_seed_keypair = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto pk = Uint8Array(runtime, arguments[0]);
			auto sk = Uint8Array(runtime, arguments[1]);
			auto seed = Uint8Array(runtime, arguments[2]);
			crypto_kx_seed_keypair(pk.toArray(runtime), sk.toArray(runtime), seed.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_kx_seed_keypair"), 3, kx_seed_keypair);
	}
	if (propName == "crypto_kx_client_session_keys") {
		auto kx_client_session_keys = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto client_pk = Uint8Array(runtime, arguments[2]);
			auto client_sk = Uint8Array(runtime, arguments[3]);
			auto server_pk = Uint8Array(runtime, arguments[4]);
			int ret;
			if (arguments[0].isNull() && arguments[1].isNull()) {
				throw JSError(runtime, "Both rx and tx can't be null");
			}
			if (arguments[0].isNull()) {
				auto tx = Uint8Array(runtime, arguments[1]);
				ret = crypto_kx_client_session_keys(nullptr, tx.toArray(runtime), client_pk.toArray(runtime), client_sk.toArray(runtime), server_pk.toArray(runtime));
			} else if (arguments[1].isNull()) {
				auto rx = Uint8Array(runtime, arguments[0]);
				ret = crypto_kx_client_session_keys(rx.toArray(runtime), nullptr, client_pk.toArray(runtime), client_sk.toArray(runtime), server_pk.toArray(runtime));
			} else {
				auto rx = Uint8Array(runtime, arguments[0]);
				auto tx = Uint8Array(runtime, arguments[1]);
				ret = crypto_kx_client_session_keys(rx.toArray(runtime), tx.toArray(runtime), client_pk.toArray(runtime), client_sk.toArray(runtime), server_pk.toArray(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_kx_client_session_keys"), 5, kx_client_session_keys);
	}
	if (propName == "crypto_kx_server_session_keys") {
		auto kx_server_session_keys = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto server_pk = Uint8Array(runtime, arguments[2]);
			auto server_sk = Uint8Array(runtime, arguments[3]);
			auto client_pk = Uint8Array(runtime, arguments[4]);
			int ret;
			if (arguments[0].isNull() && arguments[1].isNull()) {
				throw JSError(runtime, "Both rx and tx can't be null");
			}
			if (arguments[0].isNull()) {
				auto tx = Uint8Array(runtime, arguments[1]);
				ret = crypto_kx_server_session_keys(nullptr, tx.toArray(runtime), server_pk.toArray(runtime), server_sk.toArray(runtime), client_pk.toArray(runtime));
			} else if (arguments[1].isNull()) {
				auto rx = Uint8Array(runtime, arguments[0]);
				ret = crypto_kx_server_session_keys(rx.toArray(runtime), nullptr, server_pk.toArray(runtime), server_sk.toArray(runtime), client_pk.toArray(runtime));
			} else {
				auto rx = Uint8Array(runtime, arguments[0]);
				auto tx = Uint8Array(runtime, arguments[1]);
				ret = crypto_kx_server_session_keys(rx.toArray(runtime), tx.toArray(runtime), server_pk.toArray(runtime), server_sk.toArray(runtime), client_pk.toArray(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_kx_server_session_keys"), 5, kx_server_session_keys);
	}
	if (propName == "crypto_onetimeauth_STATEBYTES") {
		return Value((int) crypto_onetimeauth_statebytes());
	}
	if (propName == "crypto_onetimeauth") {
		auto onetimeauth = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_onetimeauth(out.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_onetimeauth"), 3, onetimeauth);
	}
	if (propName == "crypto_onetimeauth_verify") {
		auto onetimeauth_verify = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto h = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			int ret = crypto_onetimeauth_verify(h.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime), k.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_onetimeauth_verify"), 3, onetimeauth_verify);
	}
	if (propName == "crypto_onetimeauth_init") {
		auto onetimeauth_init = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto key = Uint8Array(runtime, arguments[1]);
			crypto_onetimeauth_init((crypto_onetimeauth_state*) state.toArray(runtime), key.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_onetimeauth_init"), 2, onetimeauth_init);
	}
	if (propName == "crypto_onetimeauth_update") {
		auto onetimeauth_update = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			crypto_onetimeauth_update((crypto_onetimeauth_state*) state.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_onetimeauth_update"), 2, onetimeauth_update);
	}
	if (propName == "crypto_onetimeauth_final") {
		auto onetimeauth_final = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto out = Uint8Array(runtime, arguments[1]);
			crypto_onetimeauth_final((crypto_onetimeauth_state*) state.toArray(runtime), out.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_onetimeauth_final"), 2, onetimeauth_final);
	}
	if (propName == "crypto_onetimeauth_keygen") {
		auto onetimeauth_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_onetimeauth_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_onetimeauth_keygen"), 1, onetimeauth_keygen);
	}
	if (propName == "crypto_pwhash_ALG_ARGON2I13") {
		return Value((int) crypto_pwhash_ALG_ARGON2I13);
	}
	if (propName == "crypto_pwhash_ALG_ARGON2ID13") {
		return Value((int) crypto_pwhash_ALG_ARGON2ID13);
	}
	if (propName == "crypto_pwhash") {
		auto pwhash = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto passwd = Uint8Array(runtime, arguments[1]);
			auto salt = Uint8Array(runtime, arguments[2]);
			uint64_t ops = arguments[3].getNumber();
			int mem = arguments[4].getNumber();
			int alg = arguments[5].getNumber();
			int ret = crypto_pwhash(out.toArray(runtime), out.byteLength(runtime), (char *) passwd.toArray(runtime), passwd.byteLength(runtime), salt.toArray(runtime), ops, mem, alg);
			if (ret < 0) {
				throw JSError(runtime, "Out of memory");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_pwhash"), 6, pwhash);
	}
	if (propName == "crypto_pwhash_str") {
		auto pwhash_str = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto passwd = Uint8Array(runtime, arguments[1]);
			uint64_t ops = arguments[2].getNumber();
			int mem = arguments[3].getNumber();
			int ret = crypto_pwhash_str((char *) out.toArray(runtime), (char *) passwd.toArray(runtime), passwd.byteLength(runtime), ops, mem);
			if (ret < 0) {
				throw JSError(runtime, "Out of memory");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_pwhash_str"), 4, pwhash_str);
	}
	if (propName == "crypto_pwhash_str_verify") {
		auto pwhash_str_verify = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto str = Uint8Array(runtime, arguments[0]);
			auto passwd = Uint8Array(runtime, arguments[1]);
			int ret = crypto_pwhash_str_verify((char*) str.toArray(runtime), (char *) passwd.toArray(runtime), passwd.byteLength(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_pwhash_str_verify"), 2, pwhash_str_verify);
	}
	if (propName == "crypto_pwhash_str_needs_rehash") {
		auto pwhash_str_needs_rehash = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto str = Uint8Array(runtime, arguments[0]);
			uint64_t ops = arguments[1].getNumber();
			int mem = arguments[2].getNumber();
			int ret = crypto_pwhash_str_needs_rehash((char *) str.toArray(runtime), ops, mem);
			return Value((bool) ret);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_pwhash_str_needs_rehash"), 3, pwhash_str_needs_rehash);
	}
	if (propName == "crypto_pwhash_scryptsalsa208sha256") {
		auto pwhash_scryptsalsa208sha256 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto passwd = Uint8Array(runtime, arguments[1]);
			auto salt = Uint8Array(runtime, arguments[2]);
			uint64_t ops = arguments[3].getNumber();
			int mem = arguments[4].getNumber();
			int ret = crypto_pwhash_scryptsalsa208sha256(out.toArray(runtime), out.byteLength(runtime), (char *) passwd.toArray(runtime), passwd.byteLength(runtime), salt.toArray(runtime), ops, mem);
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_pwhash_scryptsalsa208sha256"), 5, pwhash_scryptsalsa208sha256);
	}
	if (propName == "crypto_pwhash_scryptsalsa208sha256_str") {
		auto pwhash_scryptsalsa208sha256_str = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto passwd = Uint8Array(runtime, arguments[1]);
			uint64_t ops = arguments[2].getNumber();
			int mem = arguments[3].getNumber();
			int ret = crypto_pwhash_scryptsalsa208sha256_str((char *) out.toArray(runtime), (char *) passwd.toArray(runtime), passwd.byteLength(runtime), ops, mem);
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_pwhash_scryptsalsa208sha256_str"), 4, pwhash_scryptsalsa208sha256_str);
	}
	if (propName == "crypto_pwhash_scryptsalsa208sha256_str_verify") {
		auto pwhash_scryptsalsa208sha256_str_verify = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto str = Uint8Array(runtime, arguments[0]);
			auto passwd = Uint8Array(runtime, arguments[1]);
			int ret = crypto_pwhash_scryptsalsa208sha256_str_verify((char *) str.toArray(runtime), (char *) passwd.toArray(runtime), passwd.byteLength(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_pwhash_scryptsalsa208sha256_str_verify"), 2, pwhash_scryptsalsa208sha256_str_verify);
	}
	if (propName == "crypto_pwhash_scryptsalsa208sha256_str_needs_rehash") {
		auto pwhash_scryptsalsa208sha256_str_needs_rehash = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto str = Uint8Array(runtime, arguments[0]);
			uint64_t ops = arguments[1].getNumber();
			int mem = arguments[2].getNumber();
			int ret = crypto_pwhash_scryptsalsa208sha256_str_needs_rehash((char *) str.toArray(runtime), ops, mem);
			return Value((bool) ret);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_pwhash_scryptsalsa208sha256_str_needs_rehash"), 3, pwhash_scryptsalsa208sha256_str_needs_rehash);
	}
	if (propName == "crypto_scalarmult_base") {
		auto scalarmult_base = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto q = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			crypto_scalarmult_base(q.toArray(runtime), n.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_scalarmult_base"), 2, scalarmult_base);
	}
	if (propName == "crypto_scalarmult") {
		auto scalarmult = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto q = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			auto p = Uint8Array(runtime, arguments[2]);
			int ret = crypto_scalarmult(q.toArray(runtime), n.toArray(runtime), p.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_scalarmult"), 3, scalarmult);
	}
	if (propName == "crypto_scalarmult_ed25519") {
		auto scalarmult_ed25519 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto q = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			auto p = Uint8Array(runtime, arguments[2]);
			int ret = crypto_scalarmult_ed25519(q.toArray(runtime), n.toArray(runtime), p.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_scalarmult_ed25519"), 3, scalarmult_ed25519);
	}
	if (propName == "crypto_scalarmult_ed25519_base") {
		auto scalarmult_ed25519_base = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto q = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			crypto_scalarmult_ed25519_base(q.toArray(runtime), n.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_scalarmult_ed25519_base"), 2, scalarmult_ed25519_base);
	}
	if (propName == "crypto_scalarmult_ed25519_noclamp") {
		auto scalarmult_ed25519_noclamp = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto q = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			auto p = Uint8Array(runtime, arguments[2]);
			int ret = crypto_scalarmult_ed25519_noclamp(q.toArray(runtime), n.toArray(runtime), p.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_scalarmult_ed25519_noclamp"), 3, scalarmult_ed25519_noclamp);
	}
	if (propName == "crypto_scalarmult_ed25519_base_noclamp") {
		auto scalarmult_ed25519_base_noclamp = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto q = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			crypto_scalarmult_ed25519_base_noclamp(q.toArray(runtime), n.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_scalarmult_ed25519_base_noclamp"), 2, scalarmult_ed25519_base_noclamp);
	}
	if (propName == "crypto_secretbox_easy") {
		auto secretbox_easy = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto k = Uint8Array(runtime, arguments[3]);
			if (c.byteLength(runtime) < m.byteLength(runtime) + crypto_secretbox_MACBYTES) {
				throw JSError(runtime, "c length must be at least m length + crypto_secretbox_MACBYTES");
			}
			crypto_secretbox_easy(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretbox_easy"), 4, secretbox_easy);
	}
	if (propName == "crypto_secretbox_open_easy") {
		auto secretbox_open_easy = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto k = Uint8Array(runtime, arguments[3]);
			int ret = crypto_secretbox_open_easy(m.toArray(runtime), c.toArray(runtime), c.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretbox_open_easy"), 4, secretbox_open_easy);
	}
	if (propName == "crypto_secretbox_detached") {
		auto secretbox_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto mac = Uint8Array(runtime, arguments[1]);
			auto m = Uint8Array(runtime, arguments[2]);
			auto n = Uint8Array(runtime, arguments[3]);
			auto k = Uint8Array(runtime, arguments[4]);
			crypto_secretbox_detached(c.toArray(runtime), mac.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretbox_detached"), 5, secretbox_detached);
	}
	if (propName == "crypto_secretbox_open_detached") {
		auto secretbox_open_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[1]);
			auto mac = Uint8Array(runtime, arguments[2]);
			auto n = Uint8Array(runtime, arguments[3]);
			auto k = Uint8Array(runtime, arguments[4]);
			int ret = crypto_secretbox_open_detached(m.toArray(runtime), c.toArray(runtime), mac.toArray(runtime), c.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretbox_open_detached"), 5, secretbox_open_detached);
	}
	if (propName == "crypto_secretbox_keygen") {
		auto secretbox_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_secretbox_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretbox_keygen"), 1, secretbox_keygen);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_TAG_MESSAGE") {
		auto buf = Uint8Array(runtime, 1);
		auto arr = buf.toArray(runtime);
		arr[0] = crypto_secretstream_xchacha20poly1305_tag_message();
		return Value(runtime, buf);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_TAG_PUSH") {
		auto buf = Uint8Array(runtime, 1);
		auto arr = buf.toArray(runtime);
		arr[0] = crypto_secretstream_xchacha20poly1305_tag_push();
		return Value(runtime, buf);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_TAG_REKEY") {
		auto buf = Uint8Array(runtime, 1);
		auto arr = buf.toArray(runtime);
		arr[0] = crypto_secretstream_xchacha20poly1305_tag_rekey();
		return Value(runtime, buf);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_TAG_FINAL") {
		auto buf = Uint8Array(runtime, 1);
		auto arr = buf.toArray(runtime);
		arr[0] = crypto_secretstream_xchacha20poly1305_tag_final();
		return Value(runtime, buf);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_keygen") {
		auto secretstream_xchacha20poly1305_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_secretstream_xchacha20poly1305_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_keygen"), 1, secretstream_xchacha20poly1305_keygen);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_STATEBYTES") {
		return Value((int) crypto_secretstream_xchacha20poly1305_statebytes());
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_init_push") {
		auto secretstream_xchacha20poly1305_init_push = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto header = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_secretstream_xchacha20poly1305_init_push((crypto_secretstream_xchacha20poly1305_state*) state.toArray(runtime), header.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_init_push"), 3, secretstream_xchacha20poly1305_init_push);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_push") {
		auto secretstream_xchacha20poly1305_push = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[1]);
			auto m = Uint8Array(runtime, arguments[2]);
			auto tag = Uint8Array(runtime, arguments[4]);
			unsigned long long int clen_p;
			if (arguments[3].isNull()) {
				crypto_secretstream_xchacha20poly1305_push((crypto_secretstream_xchacha20poly1305_state*) state.toArray(runtime),
														   c.toArray(runtime), &clen_p,
														   m.toArray(runtime), m.byteLength(runtime),
														   nullptr, 0, tag.toArray(runtime)[0]);
			} else {
				auto ad = Uint8Array(runtime, arguments[3]);
				crypto_secretstream_xchacha20poly1305_push((crypto_secretstream_xchacha20poly1305_state*) state.toArray(runtime),
														   c.toArray(runtime), &clen_p,
														   m.toArray(runtime), m.byteLength(runtime),
														   ad.toArray(runtime), ad.byteLength(runtime),
														   tag.toArray(runtime)[0]);
			}
			return Value((int) clen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_push"), 5, secretstream_xchacha20poly1305_push);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_init_pull") {
		auto secretstream_xchacha20poly1305_init_pull = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto header = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_secretstream_xchacha20poly1305_init_pull((crypto_secretstream_xchacha20poly1305_state*) state.toArray(runtime), header.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_init_pull"), 3, secretstream_xchacha20poly1305_init_pull);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_pull") {
		auto secretstream_xchacha20poly1305_pull = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto tag = Uint8Array(runtime, arguments[2]);
			auto c = Uint8Array(runtime, arguments[3]);
			unsigned long long int mlen_p;
			int ret;
			if (arguments[4].isNull()) {
				ret = crypto_secretstream_xchacha20poly1305_pull((crypto_secretstream_xchacha20poly1305_state*) state.toArray(runtime),
																 m.toArray(runtime), &mlen_p, tag.toArray(runtime),
																 c.toArray(runtime), c.byteLength(runtime),
																 nullptr, 0);
			} else {
				auto ad = Uint8Array(runtime, arguments[4]);
				ret = crypto_secretstream_xchacha20poly1305_pull((crypto_secretstream_xchacha20poly1305_state*) state.toArray(runtime),
																 m.toArray(runtime), &mlen_p, tag.toArray(runtime),
																 c.toArray(runtime), c.byteLength(runtime),
																 ad.toArray(runtime), ad.byteLength(runtime));
			}
			if (ret < 0) {
				throw JSError(runtime, "Invalid cipher");
			}
			return Value((int) mlen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_pull"), 5, secretstream_xchacha20poly1305_pull);
	}
	if (propName == "crypto_secretstream_xchacha20poly1305_rekey") {
		auto secretstream_xchacha20poly1305_rekey = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto state = Uint8Array(runtime, arguments[0]);
			crypto_secretstream_xchacha20poly1305_rekey((crypto_secretstream_xchacha20poly1305_state*) state.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_secretstream_xchacha20poly1305_rekey"), 1, secretstream_xchacha20poly1305_rekey);
	}
	if (propName == "crypto_shorthash_keygen") {
		auto shorthash_keygen = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto k = Uint8Array(runtime, arguments[0]);
			crypto_shorthash_keygen(k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_shorthash_keygen"), 1, shorthash_keygen);
	}
	if (propName == "crypto_shorthash") {
		auto shorthash = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_shorthash(out.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_shorthash"), 3, shorthash);
	}
	if (propName == "crypto_shorthash_siphashx24") {
		auto shorthash_siphashx24 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto out = Uint8Array(runtime, arguments[0]);
			auto inp = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_shorthash_siphashx24(out.toArray(runtime), inp.toArray(runtime), inp.byteLength(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_shorthash_siphashx24"), 3, shorthash_siphashx24);
	}
	if (propName == "crypto_sign_STATEBYTES") {
		return Value((int) crypto_sign_statebytes());
	}
	if (propName == "crypto_sign_keypair") {
		auto sign_keypair = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto pk = Uint8Array(runtime, arguments[0]);
			auto sk = Uint8Array(runtime, arguments[1]);
			crypto_sign_keypair(pk.toArray(runtime), sk.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign_keypair"), 2, sign_keypair);
	}
	if (propName == "crypto_sign_seed_keypair") {
		auto sign_seed_keypair = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto pk = Uint8Array(runtime, arguments[0]);
			auto sk = Uint8Array(runtime, arguments[1]);
			auto seed = Uint8Array(runtime, arguments[2]);
			crypto_sign_seed_keypair(pk.toArray(runtime), sk.toArray(runtime), seed.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign_seed_keypair"), 3, sign_seed_keypair);
	}
	if (propName == "crypto_sign") {
		auto sign = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto sm = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto sk = Uint8Array(runtime, arguments[2]);
			unsigned long long int smlen_p;
			crypto_sign(sm.toArray(runtime), &smlen_p, m.toArray(runtime), m.byteLength(runtime), sk.toArray(runtime));
			return Value((int) smlen_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign"), 3, sign);
	}
	if (propName == "crypto_sign_open") {
		auto sign_open = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto sm = Uint8Array(runtime, arguments[1]);
			auto pk = Uint8Array(runtime, arguments[2]);
			int ret = crypto_sign_open(m.toArray(runtime), nullptr, sm.toArray(runtime), sm.byteLength(runtime), pk.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign_open"), 3, sign_open);
	}
	if (propName == "crypto_sign_detached") {
		auto sign_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto sig = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto sk = Uint8Array(runtime, arguments[2]);
			crypto_sign_detached(sig.toArray(runtime), nullptr, m.toArray(runtime), m.byteLength(runtime), sk.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign_detached"), 3, sign_detached);
	}
	if (propName == "crypto_sign_verify_detached") {
		auto sign_verify_detached = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto sig = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto pk = Uint8Array(runtime, arguments[2]);
			int ret = crypto_sign_verify_detached(sig.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), pk.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign_verify_detached"), 3, sign_verify_detached);
	}
	if (propName == "crypto_sign_ed25519_sk_to_pk") {
		auto sign_ed25519_sk_to_pk = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto pk = Uint8Array(runtime, arguments[0]);
			auto sk = Uint8Array(runtime, arguments[1]);
			crypto_sign_ed25519_sk_to_pk(pk.toArray(runtime), sk.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign_ed25519_sk_to_pk"), 2, sign_ed25519_sk_to_pk);
	}
	if (propName == "crypto_sign_ed25519_pk_to_curve25519") {
		auto sign_ed25519_pk_to_curve25519 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto x25519_pk = Uint8Array(runtime, arguments[0]);
			auto ed25519_pk = Uint8Array(runtime, arguments[1]);
			int ret = crypto_sign_ed25519_pk_to_curve25519(x25519_pk.toArray(runtime), ed25519_pk.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Invalid public key");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign_ed25519_pk_to_curve25519"), 2, sign_ed25519_pk_to_curve25519);
	}
	if (propName == "crypto_sign_ed25519_sk_to_curve25519") {
		auto sign_ed25519_sk_to_curve25519 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto x25519_sk = Uint8Array(runtime, arguments[0]);
			auto ed25519_sk = Uint8Array(runtime, arguments[1]);
			int ret = crypto_sign_ed25519_sk_to_curve25519(x25519_sk.toArray(runtime), ed25519_sk.toArray(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Invalid secret key");
			}
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_sign_ed25519_sk_to_curve25519"), 2, sign_ed25519_sk_to_curve25519);
	}
	if (propName == "crypto_stream") {
		auto stream = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_stream(c.toArray(runtime), c.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream"), 3, stream);
	}
	if (propName == "crypto_stream_xor") {
		auto stream_xor = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto k = Uint8Array(runtime, arguments[3]);
			crypto_stream_xor(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_xor"), 4, stream_xor);
	}
	if (propName == "crypto_stream_chacha20") {
		auto stream_chacha20 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_stream_chacha20(c.toArray(runtime), c.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_chacha20"), 3, stream_chacha20);
	}
	if (propName == "crypto_stream_chacha20_xor") {
		auto stream_chacha20_xor = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto k = Uint8Array(runtime, arguments[3]);
			crypto_stream_chacha20_xor(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_chacha20_xor"), 4, stream_chacha20_xor);
	}
	if (propName == "crypto_stream_chacha20_xor_ic") {
		auto stream_chacha20_xor_ic = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			int ic = arguments[3].getNumber();
			auto k = Uint8Array(runtime, arguments[4]);
			crypto_stream_chacha20_xor_ic(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), ic, k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_chacha20_xor_ic"), 5, stream_chacha20_xor_ic);
	}
	if (propName == "crypto_stream_chacha20_ietf") {
		auto stream_chacha20_ietf = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_stream_chacha20_ietf(c.toArray(runtime), c.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_chacha20_ietf"), 3, stream_chacha20_ietf);
	}
	if (propName == "crypto_stream_chacha20_ietf_xor") {
		auto stream_chacha20_ietf_xor = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto k = Uint8Array(runtime, arguments[3]);
			crypto_stream_chacha20_ietf_xor(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_chacha20_ietf_xor"), 4, stream_chacha20_ietf_xor);
	}
	if (propName == "crypto_stream_chacha20_ietf_xor_ic") {
		auto stream_chacha20_ietf_xor_ic = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			uint32_t ic = arguments[3].getNumber();
			auto k = Uint8Array(runtime, arguments[4]);
			crypto_stream_chacha20_ietf_xor_ic(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), ic, k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_chacha20_ietf_xor_ic"), 5, stream_chacha20_ietf_xor_ic);
	}
	if (propName == "crypto_stream_xchacha20") {
		auto stream_xchacha20 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_stream_xchacha20(c.toArray(runtime), c.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_xchacha20"), 3, stream_xchacha20);
	}
	if (propName == "crypto_stream_xchacha20_xor") {
		auto stream_xchacha20_xor = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto k = Uint8Array(runtime, arguments[3]);
			crypto_stream_xchacha20_xor(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_xchacha20_xor"), 4, stream_xchacha20_xor);
	}
	if (propName == "crypto_stream_xchacha20_xor_ic") {
		auto stream_xchacha20_xor_ic = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			int ic = arguments[3].getNumber();
			auto k = Uint8Array(runtime, arguments[4]);
			crypto_stream_xchacha20_xor_ic(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), ic, k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_xchacha20_xor_ic"), 5, stream_xchacha20_xor_ic);
	}
	if (propName == "crypto_stream_salsa20") {
		auto stream_salsa20 = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto n = Uint8Array(runtime, arguments[1]);
			auto k = Uint8Array(runtime, arguments[2]);
			crypto_stream_salsa20(c.toArray(runtime), c.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_salsa20"), 3, stream_salsa20);
	}
	if (propName == "crypto_stream_salsa20_xor") {
		auto stream_salsa20_xor = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			auto k = Uint8Array(runtime, arguments[3]);
			crypto_stream_salsa20_xor(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_salsa20_xor"), 4, stream_salsa20_xor);
	}
	if (propName == "crypto_stream_salsa20_xor_ic") {
		auto stream_salsa20_xor_ic = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto n = Uint8Array(runtime, arguments[2]);
			int ic = arguments[3].getNumber();
			auto k = Uint8Array(runtime, arguments[4]);
			crypto_stream_salsa20_xor_ic(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), n.toArray(runtime), ic, k.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_stream_salsa20_xor_ic"), 5, stream_salsa20_xor_ic);
	}
	if (propName == "randombytes_random") {
		auto random = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			return Value((int) randombytes_random());
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "randombytes_random"), 0, random);
	}
	if (propName == "randombytes_uniform") {
		auto uniform = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			int upper_bound = arguments[0].getNumber();
			return Value((int) randombytes_uniform(upper_bound));
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "randombytes_uniform"), 1, uniform);
	}
	if (propName == "randombytes_buf") {
		auto buf = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto buf = Uint8Array(runtime, arguments[0]);
			randombytes_buf(buf.toArray(runtime), buf.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "randombytes_buf"), 1, buf);
	}
	if (propName == "randombytes_buf_deterministic") {
		auto buf_deterministic = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto buf = Uint8Array(runtime, arguments[0]);
			auto seed = Uint8Array(runtime, arguments[1]);
			randombytes_buf_deterministic(buf.toArray(runtime), buf.byteLength(runtime), seed.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "randombytes_buf_deterministic"), 2, buf_deterministic);
	}
	if (propName == "sodium_memcmp") {
		auto sodiummemcmp = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto b1 = Uint8Array(runtime, arguments[0]);
			auto b2 = Uint8Array(runtime, arguments[1]);
			if (b1.byteLength(runtime) != b2.byteLength(runtime)) {
				throw JSError(runtime, "Arguments must be of equal length");
			}
			int ret = sodium_memcmp(b1.toArray(runtime), b2.toArray(runtime), b1.byteLength(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "sodium_memcmp"), 2, sodiummemcmp);
	}
	if (propName == "sodium_increment") {
		auto increment = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto n = Uint8Array(runtime, arguments[0]);
			sodium_increment(n.toArray(runtime), n.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "sodium_increment"), 1, increment);
	}
	if (propName == "sodium_add") {
		auto add = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto a = Uint8Array(runtime, arguments[0]);
			auto b = Uint8Array(runtime, arguments[1]);
			sodium_add(a.toArray(runtime), b.toArray(runtime), a.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "sodium_add"), 2, add);
	}
	if (propName == "sodium_sub") {
		auto sub = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto a = Uint8Array(runtime, arguments[0]);
			auto b = Uint8Array(runtime, arguments[1]);
			sodium_sub(a.toArray(runtime), b.toArray(runtime), a.byteLength(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "sodium_sub"), 2, sub);
	}
	if (propName == "sodium_compare") {
		auto compare = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto b1 = Uint8Array(runtime, arguments[0]);
			auto b2 = Uint8Array(runtime, arguments[1]);
			int ret = sodium_compare(b1.toArray(runtime), b2.toArray(runtime), b1.byteLength(runtime));
			return Value(ret);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "sodium_compare"), 2, compare);
	}
	if (propName == "sodium_is_zero") {
		auto is_zero = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto n = Uint8Array(runtime, arguments[0]);
			int ret = sodium_is_zero(n.toArray(runtime), n.byteLength(runtime));
			return Value((bool) ret);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "sodium_is_zero"), 1, is_zero);
	}
	if (propName == "sodium_pad") {
		auto pad = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto buf = Uint8Array(runtime, arguments[0]);
			int unpadded_len = arguments[1].getNumber();
			int blocksize = arguments[2].getNumber();
			if (unpadded_len > buf.byteLength(runtime)) {
				throw JSError(runtime, "unpadded length cannot exceed buffer length");
			}
			if (blocksize > buf.byteLength(runtime)) {
				throw JSError(runtime, "block size cannot exceed buffer length");
			}
			if (blocksize < 1) {
				throw JSError(runtime, "block size must be at least 1 byte");
			}
			if (buf.byteLength(runtime) < unpadded_len + (blocksize - (unpadded_len % blocksize))) {
				throw JSError(runtime, "buf not long enough");
			}
			size_t padded_len_p;
			int ret = sodium_pad(&padded_len_p, buf.toArray(runtime), unpadded_len, blocksize, buf.byteLength(runtime));
			if (ret < 0) {
				throw JSError(runtime, "Invalid data");
			}
			return Value((int) padded_len_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "sodium_pad"), 3, pad);
	}
	if (propName == "sodium_unpad") {
		auto unpad = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto buf = Uint8Array(runtime, arguments[0]);
			int padded_len = arguments[1].getNumber();
			int blocksize = arguments[2].getNumber();
			if (padded_len > buf.byteLength(runtime)) {
				throw JSError(runtime, "padded length cannot exceed buffer length");
			}
			if (blocksize > buf.byteLength(runtime)) {
				throw JSError(runtime, "block size cannot exceed buffer length");
			}
			if (blocksize < 1) {
				throw JSError(runtime, "block size must be at least 1 byte");
			}
			size_t unpadded_len_p;
			sodium_unpad(&unpadded_len_p, buf.toArray(runtime), padded_len, blocksize);
			return Value((int) unpadded_len_p);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "sodium_unpad"), 3, unpad);
	}
	if (propName == "crypto_box_seal") {
		auto box_seal = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto c = Uint8Array(runtime, arguments[0]);
			auto m = Uint8Array(runtime, arguments[1]);
			auto pk = Uint8Array(runtime, arguments[2]);
			crypto_box_seal(c.toArray(runtime), m.toArray(runtime), m.byteLength(runtime), pk.toArray(runtime));
			return Value::undefined();
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_box_seal"), 3, box_seal);
	}
	if (propName == "crypto_box_seal_open") {
		auto box_seal_open = [](Runtime& runtime, const Value&, const Value* arguments, size_t) -> Value {
			auto m = Uint8Array(runtime, arguments[0]);
			auto c = Uint8Array(runtime, arguments[1]);
			auto pk = Uint8Array(runtime, arguments[2]);
			auto sk = Uint8Array(runtime, arguments[3]);
			int ret = crypto_box_seal_open(m.toArray(runtime), c.toArray(runtime), c.byteLength(runtime), pk.toArray(runtime), sk.toArray(runtime));
			return Value(ret == 0);
		};
		return Function::createFromHostFunction(runtime, PropNameID::forUtf8(runtime, "crypto_box_seal_open"), 4, box_seal_open);
	}

	return Value::undefined();
}

} // namespace screamingvoid
