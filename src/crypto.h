#ifndef VERIFY_CRYPTO
#define VERIFY_CRYPTO
#include <string>
#include <vector>

namespace crypto
{
	constexpr const char* INIT_INFO = "k9Xp2mWqR7vLnJ4cYbA8dFe3H";
	constexpr const char* SESSION_INFO = "T5uZsG6wN1xKfQ9jMrC0hBv4P";
	constexpr const char* TRANSPORT_SALT = "aR3nV8kLpW5mX2qYjF7d";
	constexpr const char* TRANSPORT_INFO = "xQ4vN9bK2wRj";

	using Bytes = std::vector<unsigned char>;

	Bytes fromHex(const std::string& value);
	std::string toHex(const Bytes& value);

	Bytes randomBytes(size_t size);

	Bytes x25519Public(const Bytes& privateKey);
	Bytes x25519(const Bytes& privateKey, const Bytes& publicKey);

	Bytes hkdf(const Bytes& input, const std::string& salt, const std::string& info);

	std::string encryptText(const std::string& plaintext, const Bytes& key);
	std::string decryptText(const std::string& encryptedHex, const Bytes& key);

	bool verifyEd25519(const std::string& message, const std::string& signatureHex, const std::string& publicKeyHex);
}
#endif