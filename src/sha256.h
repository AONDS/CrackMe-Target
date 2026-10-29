#pragma once
#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

class Sha256
{
	static constexpr uint32_t H0[] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	static constexpr uint32_t K[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	static constexpr uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
	static constexpr uint32_t shr(uint32_t x, uint32_t n) { return x >> n; }
	static constexpr uint32_t Ch(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
	static constexpr uint32_t Maj(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
	static constexpr uint32_t Sigma0(uint32_t a) { return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22); }
	static constexpr uint32_t Sigma1(uint32_t e) { return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25); }
	static constexpr uint32_t sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }
	static constexpr uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }

public:
	static std::vector<unsigned char> en(const void* data, const size_t size)
	{
		auto udata = reinterpret_cast<const unsigned char*>(data);
		if (!udata || size == 0) return {};
		std::vector<unsigned char> padded(udata, udata + size);
		padded.push_back(0x80);

		while ((padded.size() % 64) != 56) padded.push_back(0x00);

		uint64_t bit_len = static_cast<uint64_t>(size) * 8;
		for (int i = 7; i >= 0; --i) padded.push_back(static_cast<unsigned char>((bit_len >> (i * 8)) & 0xFF));

		uint32_t state[8];
		std::memcpy(state, H0, sizeof(H0));

		for (size_t p = 0; p < padded.size(); p += 64)
		{
			const unsigned char* block = &padded[p];
			uint32_t W[64];

			for (int i = 0; i < 16; ++i) W[i] = (static_cast<uint32_t>(block[i * 4]) << 24) | (static_cast<uint32_t>(block[i * 4 + 1]) << 16) | (static_cast<uint32_t>(block[i * 4 + 2]) << 8) | (static_cast<uint32_t>(block[i * 4 + 3]));

			for (int t = 16; t < 64; ++t) W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];

			uint32_t a = state[0];
			uint32_t b = state[1];
			uint32_t c = state[2];
			uint32_t d = state[3];
			uint32_t e = state[4];
			uint32_t f = state[5];
			uint32_t g = state[6];
			uint32_t h = state[7];

			for (int t = 0; t < 64; ++t)
			{
				uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
				uint32_t T2 = Sigma0(a) + Maj(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}

			state[0] += a;
			state[1] += b;
			state[2] += c;
			state[3] += d;
			state[4] += e;
			state[5] += f;
			state[6] += g;
			state[7] += h;
		}

		std::vector<unsigned char> digest(32);
		for (int i = 0; i < 8; ++i)
		{
			digest[i * 4] = static_cast<unsigned char>((state[i] >> 24) & 0xFF);
			digest[i * 4 + 1] = static_cast<unsigned char>((state[i] >> 16) & 0xFF);
			digest[i * 4 + 2] = static_cast<unsigned char>((state[i] >> 8) & 0xFF);
			digest[i * 4 + 3] = static_cast<unsigned char>(state[i] & 0xFF);
		}
		return digest;
	}
	static std::vector<unsigned char> en(const std::vector<unsigned char>& data) { return en(data.data(), data.size()); }
	static std::vector<unsigned char> en(const std::string& data) { return en(data.data(), data.size()); }

	static std::string en_hex(const void* data, const size_t size)
	{
		auto sha = en(data, size);
		std::ostringstream oss;
		for (unsigned char b : sha) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
		return oss.str();
	}
	static std::string en_hex(const std::vector<unsigned char>& data) { return en_hex(data.data(), data.size()); }
	static std::string en_hex(const std::string& data) { return en_hex(data.data(), data.size()); }
};
#endif