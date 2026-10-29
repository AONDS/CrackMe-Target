#include "crypto.h"
#include "protect.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdexcept>
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

namespace crypto
{
	VERIFY_NOT_INLINE Bytes fromHex(const std::string& value)
	{
		VERIFY_VM_BEGIN;
		if ((value.size() & 1U) != 0U) throw std::runtime_error("Hex格式错误");
		Bytes result(value.size() / 2);
		for (size_t i = 0; i < result.size(); ++i)
		{
            const auto nibble = [](unsigned char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int high = nibble(static_cast<unsigned char>(value[i * 2]));
            const int low = nibble(static_cast<unsigned char>(value[i * 2 + 1]));
			if (high < 0 || high > 15 || low < 0 || low > 15) throw std::runtime_error("Hex格式错误");
			result[i] = static_cast<unsigned char>((high << 4) | low);
		}
		VERIFY_VM_END;
		return result;
	}
	VERIFY_NOT_INLINE std::string toHex(const Bytes& value)
	{
		VERIFY_VM_BEGIN;
		static const char alphabet[] = "0123456789abcdef";
		std::string result(value.size() * 2, '0');
		for (size_t i = 0; i < value.size(); ++i)
		{
			result[i * 2] = alphabet[value[i] >> 4];
			result[i * 2 + 1] = alphabet[value[i] & 0x0f];
		}
		VERIFY_VM_END;
		return result;
	}

	VERIFY_NOT_INLINE Bytes randomBytes(size_t size)
	{
		VERIFY_VM_BEGIN;
		Bytes result(size);
		if (RAND_bytes(result.data(), static_cast<int>(result.size())) != 1) throw std::runtime_error("安全随机数生成失败");
		VERIFY_VM_END;
		return result;
	}

	VERIFY_NOT_INLINE Bytes x25519Public(const Bytes& privateKey)
	{
		VERIFY_VM_BEGIN;
		if (privateKey.size() != 32) throw std::runtime_error("X25519私钥长度错误");
		EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey.data(), privateKey.size());
		if (!key) throw std::runtime_error("X25519密钥初始化失败");
		Bytes result(32);
		size_t length = result.size();
		int ok = EVP_PKEY_get_raw_public_key(key, result.data(), &length);
		EVP_PKEY_free(key);
		if (ok != 1 || length != 32) throw std::runtime_error("X25519公钥生成失败");
		VERIFY_VM_END;
		return result;
	}
	VERIFY_NOT_INLINE Bytes x25519(const Bytes& privateKey, const Bytes& publicKey)
	{
		VERIFY_VM_BEGIN;
		if (privateKey.size() != 32 || publicKey.size() != 32) throw std::runtime_error("X25519密钥长度错误");
		EVP_PKEY* local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey.data(), privateKey.size());
		EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, publicKey.data(), publicKey.size());
		EVP_PKEY_CTX* ctx = local ? EVP_PKEY_CTX_new(local, nullptr) : nullptr;
		Bytes result(32);
		size_t length = result.size();
		int ok = ctx && peer && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peer) == 1 && EVP_PKEY_derive(ctx, result.data(), &length) == 1;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(peer);
		EVP_PKEY_free(local);
		if (!ok || length != 32) throw std::runtime_error("X25519密钥协商失败");
		unsigned char nonZero = 0;
		for (unsigned char value : result) nonZero |= value;
		if (nonZero == 0) throw std::runtime_error("X25519共享密钥无效");
		VERIFY_VM_END;
		return result;
	}

	VERIFY_NOT_INLINE Bytes hkdf(const Bytes& input, const std::string& salt, const std::string& info)
	{
		VERIFY_VM_BEGIN;
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
		Bytes result(32);
		size_t length = result.size();
		int ok = ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) == 1 && EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 && EVP_PKEY_CTX_set1_hkdf_key(ctx, input.data(), input.size()) == 1;
		if (ok && !salt.empty()) ok = EVP_PKEY_CTX_set1_hkdf_salt(ctx, reinterpret_cast<const unsigned char*>(salt.data()), salt.size()) == 1;
		if (ok) ok = EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char*>(info.data()), info.size()) == 1;
		if (ok) ok = EVP_PKEY_derive(ctx, result.data(), &length) == 1;
		EVP_PKEY_CTX_free(ctx);
		if (!ok || length != 32) throw std::runtime_error("HKDF派生失败");
		VERIFY_VM_END;
		return result;
	}

	VERIFY_NOT_INLINE std::string encryptText(const std::string& plaintext, const Bytes& key)
	{
		VERIFY_VM_BEGIN;
		if (key.size() != 32) throw std::runtime_error("ChaCha20密钥长度错误");
		Bytes nonce = randomBytes(12);
		Bytes ciphertext(plaintext.size() + 16);
		Bytes tag(16);
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		int length = 0;
		int total = 0;
		int ok = ctx && EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr) == 1 && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 && EVP_EncryptUpdate(ctx, ciphertext.data(), &length, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) == 1;
		total = length;
		if (ok) ok = EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &length) == 1;
		total += length;
		if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag.size(), tag.data()) == 1;
		EVP_CIPHER_CTX_free(ctx);
		if (!ok) throw std::runtime_error("ChaCha20-Poly1305加密失败");
		ciphertext.resize(total);
		Bytes result;
		result.reserve(nonce.size() + ciphertext.size() + tag.size());
		result.insert(result.end(), nonce.begin(), nonce.end());
		result.insert(result.end(), ciphertext.begin(), ciphertext.end());
		result.insert(result.end(), tag.begin(), tag.end());
		VERIFY_VM_END;
		return toHex(result);
	}
	VERIFY_NOT_INLINE std::string decryptText(const std::string& encryptedHex, const Bytes& key)
	{
		VERIFY_VM_BEGIN;
		Bytes input = fromHex(encryptedHex);
		if (key.size() != 32 || input.size() < 28) throw std::runtime_error("DHV2密文格式错误");
		const size_t cipherLength = input.size() - 12 - 16;
		Bytes plaintext(cipherLength + 16);
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		int length = 0;
		int total = 0;
		int ok = ctx && EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), input.data()) == 1 && EVP_DecryptUpdate(ctx, plaintext.data(), &length, input.data() + 12, cipherLength) == 1;
		total = length;
		if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, input.data() + 12 + cipherLength) == 1;
		if (ok) ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &length) == 1;
		total += length;
		EVP_CIPHER_CTX_free(ctx);
		if (!ok) throw std::runtime_error("DHV2密文认证失败");
		VERIFY_VM_END;
		return std::string(reinterpret_cast<char*>(plaintext.data()), total);
	}

	VERIFY_NOT_INLINE bool verifyEd25519(const std::string& message, const std::string& signatureHex, const std::string& publicKeyHex)
	{
		VERIFY_VM_BEGIN;
		Bytes signature = fromHex(signatureHex);
		Bytes publicKey = fromHex(publicKeyHex);
		if (signature.size() != 64 || publicKey.size() != 32) return false;
		EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey.data(), publicKey.size());
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		int ok = key && ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 && EVP_DigestVerify(ctx, signature.data(), signature.size(), reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1;
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(key);
		VERIFY_VM_END;
		return ok == 1;
	}
}