#ifndef ISESSIONKEYGENERATOR_H
#define ISESSIONKEYGENERATOR_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

class ISessionKeyGenerator {
public:
    virtual ~ISessionKeyGenerator() = default;

    virtual void setMasterKey(std::span<const std::uint8_t> masterKey) = 0;

    virtual std::vector<std::uint8_t> deriveSessionKey(
        std::span<const std::uint8_t> context,
        std::uint32_t sessionId,
        std::size_t outputLength) const = 0;

    virtual std::vector<std::uint8_t> computeHmacSha256(
        std::span<const std::uint8_t> data,
        std::span<const std::uint8_t> key) const = 0;

    virtual std::vector<std::uint8_t> generateRandomBytes(std::size_t length) const = 0;
};
#endif
