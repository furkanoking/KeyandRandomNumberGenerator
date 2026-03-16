#include "SessionKeyGenerator.h"

#include "ISessionKeyGenerator.h"
#include "OpenSslHkdfSessionKeyGenerator.h"

SessionKeyGenerator::SessionKeyGenerator()
    : m_impl(std::make_unique<OpenSslHkdfSessionKeyGenerator>()) {}

SessionKeyGenerator::~SessionKeyGenerator() = default;

SessionKeyGenerator::SessionKeyGenerator(SessionKeyGenerator&&) noexcept = default;
SessionKeyGenerator& SessionKeyGenerator::operator=(SessionKeyGenerator&&) noexcept = default;

void SessionKeyGenerator::setMasterKey(std::span<const std::uint8_t> masterKey) {
    m_impl->setMasterKey(masterKey);
}

std::vector<std::uint8_t> SessionKeyGenerator::deriveSessionKey(
    std::span<const std::uint8_t> context,
    std::uint32_t sessionId,
    std::size_t outputLength) const {

    return m_impl->deriveSessionKey(context, sessionId, outputLength);
}

std::vector<std::uint8_t> SessionKeyGenerator::computeHmacSha256(
    std::span<const std::uint8_t> data,
    std::span<const std::uint8_t> key) const {

    return m_impl->computeHmacSha256(data, key);
}

void SessionKeyGenerator::setSessionKeyGenerator(std::unique_ptr<ISessionKeyGenerator> impl) {
    m_impl = std::move(impl);
}
