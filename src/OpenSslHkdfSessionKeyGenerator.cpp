#include "OpenSslHkdfSessionKeyGenerator.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
std::vector<std::uint8_t> makeInfo(std::span<const std::uint8_t> context, std::uint32_t sessionId) {
    const char prefix[] = "SessionKeyGenerator-v1";
    std::vector<std::uint8_t> info;
    info.reserve(sizeof(prefix) - 1 + sizeof(sessionId) + context.size());

    info.insert(info.end(), prefix, prefix + sizeof(prefix) - 1);
    info.push_back(static_cast<std::uint8_t>((sessionId >> 24U) & 0xFFU));
    info.push_back(static_cast<std::uint8_t>((sessionId >> 16U) & 0xFFU));
    info.push_back(static_cast<std::uint8_t>((sessionId >> 8U) & 0xFFU));
    info.push_back(static_cast<std::uint8_t>(sessionId & 0xFFU));
    info.insert(info.end(), context.begin(), context.end());

    return info;
}
} // namespace

OpenSslHkdfSessionKeyGenerator::OpenSslHkdfSessionKeyGenerator() {
    // PoC only: hardcoded master key.
    m_masterKey = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
        0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81,
        0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09
    };

    if (RAND_bytes(m_salt.data(), static_cast<int>(m_salt.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed while generating HKDF salt");
    }
}

void OpenSslHkdfSessionKeyGenerator::setMasterKey(std::span<const std::uint8_t> masterKey) {
    if (masterKey.size() != m_masterKey.size()) {
        throw std::invalid_argument("masterKey must be exactly 32 bytes");
    }
    std::memcpy(m_masterKey.data(), masterKey.data(), m_masterKey.size());
}

std::vector<std::uint8_t> OpenSslHkdfSessionKeyGenerator::deriveSessionKey(
    std::span<const std::uint8_t> context,
    std::uint32_t sessionId,
    std::size_t outputLength) const {

    if (outputLength == 0U || outputLength > 64U) {
        throw std::invalid_argument("outputLength must be in range [1, 64]");
    }

    const auto info = makeInfo(context, sessionId);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }

    std::vector<std::uint8_t> out(outputLength);
    size_t outLen = outputLength;

    const auto fail = [&](const std::string& msg) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error(msg);
    };

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fail("EVP_PKEY_derive_init failed");
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        fail("EVP_PKEY_CTX_set_hkdf_md failed");
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, m_salt.data(), static_cast<int>(m_salt.size())) <= 0) {
        fail("EVP_PKEY_CTX_set1_hkdf_salt failed");
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, m_masterKey.data(), static_cast<int>(m_masterKey.size())) <= 0) {
        fail("EVP_PKEY_CTX_set1_hkdf_key failed");
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), static_cast<int>(info.size())) <= 0) {
        fail("EVP_PKEY_CTX_add1_hkdf_info failed");
    }
    if (EVP_PKEY_derive(ctx, out.data(), &outLen) <= 0) {
        fail("EVP_PKEY_derive failed");
    }

    EVP_PKEY_CTX_free(ctx);
    out.resize(outLen);
    return out;
}

std::vector<std::uint8_t> OpenSslHkdfSessionKeyGenerator::computeHmacSha256(
    std::span<const std::uint8_t> data,
    std::span<const std::uint8_t> key) const {

    if (key.empty()) {
        throw std::invalid_argument("key must not be empty");
    }
    if (key.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("key size exceeds OpenSSL HMAC input limit");
    }

    std::vector<std::uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digestLength = 0U;

    const unsigned char* mac = HMAC(
        EVP_sha256(),
        key.data(),
        static_cast<int>(key.size()),
        data.data(),
        data.size(),
        digest.data(),
        &digestLength);

    if (mac == nullptr) {
        throw std::runtime_error("HMAC computation failed");
    }

    digest.resize(digestLength);
    return digest;
}

std::vector<std::uint8_t> OpenSslHkdfSessionKeyGenerator::generateRandomBytes(std::size_t length) const {
    if (length == 0U) {
        throw std::invalid_argument("length must be greater than 0");
    }
    if (length > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("length exceeds OpenSSL RAND input limit");
    }

    std::vector<std::uint8_t> bytes(length);
    if (RAND_priv_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_priv_bytes failed while generating random bytes");
    }

    return bytes;
}
