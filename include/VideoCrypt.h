#pragma once

#include <cstdint>

namespace mpcrypt {

    enum class ErrorCode : int {
    kSuccess = 0,               // 成功
    kInvalidParameter = -1,     // 参数无效
    kInputFileOpenFailed = -2,  // 无法打开输入文件
    kRandomFailed = -3,         // 随机数生成失败（加密阶段）
    kOutputFileOpenFailed = -4, // 无法打开输出文件
    kReadWriteFailed = -5,      // 读取或写入错误
    kFooterInvalid = -6,        // Footer 格式错误（非加密文件或损坏）
    kFileSizeInvalid = -7,      // 文件大小异常
    kSeekFailed = -8,           // 文件定位失败（解密时跳过开头填充）
    kWrongPassword = -9,        // 密码错误（解密时）
};

/**
 * @brief 进度回调函数类型
 * @param processed  当前已处理的视频数据字节数（原始文件内容，不含填充）
 * @param total      视频数据总字节数（原始文件大小）
 * @param user_data  用户自定义指针
 */
using ProgressCallback = void (*)(uint64_t processed, uint64_t total, void* user_data);

/**
 * @brief 加密一个 MP4 视频文件（无进度回调，兼容旧版）
 */
ErrorCode  encrypt_video(const char* inputPath, const char* password,
                  const char* outputPath = nullptr);

/**
 * @brief 解密一个加密视频文件（无进度回调，兼容旧版）
 */
ErrorCode  decrypt_video(const char* inputPath, const char* password,
                  const char* outputPath = nullptr);

/**
 * @brief 加密一个 MP4 视频文件（带进度回调）
 * 
 * 文件结构： [开头随机填充] + [加密的前4MB] + [原文件4MB之后] + [尾部随机填充] + [Footer] + [4字节长度]
 * 
 * @param inputPath   原始 MP4 文件路径（UTF-8）
 * @param password    用户密码（UTF-8）
 * @param outputPath  输出路径，若为 nullptr 或空则自动生成
 * @param callback    进度回调，可为 nullptr 表示不需要进度
 * @param user_data   回调中的用户数据指针
 * @return 0 成功，负数错误码
 */
ErrorCode  encrypt_video_ex(const char* inputPath, const char* password,
                     const char* outputPath,
                     ProgressCallback callback, void* user_data);

/**
 * @brief 解密一个加密视频文件（带进度回调）
 * 
 * @param inputPath   加密文件路径
 * @param password    用户密码
 * @param outputPath  输出路径，若为 nullptr 或空则自动生成
 * @param callback    进度回调，可为 nullptr
 * @param user_data   用户数据指针
 * @return 0 成功，负数错误码
 */
ErrorCode  decrypt_video_ex(const char* inputPath, const char* password,
                     const char* outputPath,
                     ProgressCallback callback, void* user_data);

} // namespace mpcrypt