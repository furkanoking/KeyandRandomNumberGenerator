#ifndef OPENSSLHKDFSESSIONKEYGENERATOR_H
#define OPENSSLHKDFSESSIONKEYGENERATOR_H

#include "ISessionKeyGenerator.h"

#include <array>

class OpenSslHkdfSessionKeyGenerator final : public ISessionKeyGenerator {
public:
    OpenSslHkdfSessionKeyGenerator();

    void setMasterKey(std::span<const std::uint8_t> masterKey) override;

    std::vector<std::uint8_t> deriveSessionKey(
        std::span<const std::uint8_t> context,
        std::uint32_t sessionId,
        std::size_t outputLength) const override;

    std::vector<std::uint8_t> computeHmacSha256(
        std::span<const std::uint8_t> data,
        std::span<const std::uint8_t> key) const override;

private:
    std::array<std::uint8_t, 32> m_masterKey{};
    std::array<std::uint8_t, 16> m_salt{};
};

#endif
