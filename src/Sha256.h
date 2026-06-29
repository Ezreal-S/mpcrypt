#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace mpcrypt
{
    /**
     * 32字节SHA256结果
     */
    using Sha256Hash = std::array<uint8_t, 32>;

    /**
     * 计算SHA256
     * 输入任意二进制数据
     */
    Sha256Hash Sha256(
        const void* data,
        size_t size);

    /**
     * 计算字符串SHA256（UTF-8）
     */
    Sha256Hash Sha256(
        const std::string& text);

    /**
     * 转HEX（调试用）
     */
    std::string Sha256ToHex(
        const Sha256Hash& hash);
}