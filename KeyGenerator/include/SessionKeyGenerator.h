#ifndef SESSIONKEYGENERATOR_H
#define SESSIONKEYGENERATOR_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

class ISessionKeyGenerator;

class SessionKeyGenerator {
public:
    SessionKeyGenerator();
    ~SessionKeyGenerator();

    SessionKeyGenerator(const SessionKeyGenerator&) = delete;
    SessionKeyGenerator& operator=(const SessionKeyGenerator&) = delete;
    SessionKeyGenerator(SessionKeyGenerator&&) noexcept;
    SessionKeyGenerator& operator=(SessionKeyGenerator&&) noexcept;

    void setMasterKey(std::span<const std::uint8_t> masterKey);

    std::vector<std::uint8_t> deriveSessionKey(
        std::span<const std::uint8_t> context,
        std::uint32_t sessionId,
        std::size_t outputLength = 32) const;

    std::vector<std::uint8_t> computeHmacSha256(
        std::span<const std::uint8_t> data,
        std::span<const std::uint8_t> key) const;

    void setSessionKeyGenerator(std::unique_ptr<ISessionKeyGenerator> impl);

private:
    std::unique_ptr<ISessionKeyGenerator> m_impl;
};

#endif
