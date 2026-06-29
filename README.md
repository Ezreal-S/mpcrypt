# 🔐 mpcrypt —— MP4 视频加密库

一个**高性能、跨平台**的 C++ 加密库，专门用于保护 MP4 视频文件。
仅加密文件头部，破坏播放器解析，同时支持文件名加密、随机填充、密码校验，并提供了恢复原文件名的解密能力。

## ✨ 主要特性

* **头部加密**：仅加密文件前 4 MB，性能极高，足以阻止播放器与 ffmpeg 正常解码。
* **前后随机填充**：加密文件首尾加入随机大小（可配置）的随机字节，隐藏真实文件大小。
* **密码保护**：用户自定义字符串密码，通过 SHA-256 + 随机盐派生 AES-256 密钥。
* **文件名加密与恢复**：原始文件名（含中文/Unicode）被加密后以十六进制形式作为加密文件名；解密时从文件内部恢复原文件名，即使加密文件被重命名也不影响恢复。
* **防篡改校验**：Footer 中保存原文件名的 SHA-256，用于验证密码正确性。
* **跨平台 UTF-8 路径**：完美支持 Windows、Linux、macOS、Android 等平台含特殊字符的文件路径。
* **进度回调**：可选的进度通知接口，便于集成到 GUI 进度条。
* **纯静态库，零外部依赖（除标准库和操作系统 API）**：基于 tinyaes 和 picosha2，已内置在源码中。
* **现代 CMake 构建**：支持 `find_package` 安装与集成，兼容 Qt、Android NDK 等环境。

## 📦 文件加密结构

```text
[开头随机填充]
+
[加密的前4MB]
+
[原文件4MB之后]
+
[尾部随机填充]
+
[Footer]
+
[4字节Footer长度]
```

### Footer 包含

* 魔数（Magic）
* 版本号（Version）
* 加密后的文件名
* 文件名 SHA-256
* 密钥派生 Salt
* AES IV
* 前后填充大小
* 其他元数据

解密时自动跳过填充、解密头部、恢复原始文件，并校验密码。

## 🛠️ 构建与安装

### 要求

* CMake ≥ 3.20
* C++20 编译器（GCC 11+、Clang 14+、MSVC 2022+）
* Windows / Linux / macOS / Android

### 编译

```bash
git clone https://github.com/yourname/mpcrypt.git
cd mpcrypt

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### 安装

Linux / macOS：

```bash
cmake --install build --prefix /usr/local
```

Windows：

```bash
cmake --install build --prefix C:/libs/mpcrypt
```

安装后目录结构类似：

```text
include/
└── mpcrypt/
    └── VideoCrypt.h

lib/
├── libmpcrypt.a
└── cmake/
    └── mpcrypt/
        ├── mpcryptConfig.cmake
        ├── mpcryptConfigVersion.cmake
        └── mpcryptTargets.cmake
```

## 🔗 在 CMake 项目中使用

```cmake
find_package(mpcrypt REQUIRED)

target_link_libraries(
    your_app
    PRIVATE
    mpcrypt::mpcrypt
)
```

## 🚀 快速开始

### 基础加密解密

```cpp
#include <mpcrypt/VideoCrypt.h>
#include <cstdio>

int main() {
    // 加密视频（自动在同目录生成十六进制加密文件）
    auto ret = mpcrypt::encrypt_video(
        "C:/videos/我的视频.mp4",
        "my_password"
    );

    if (ret != mpcrypt::ErrorCode::kSuccess) {
        printf(
            "加密失败，错误码: %d\n",
            static_cast<int>(ret)
        );
        return -1;
    }

    // 解密（自动恢复原始文件名）
    ret = mpcrypt::decrypt_video(
        "C:/videos/3A4FBC...",
        "my_password"
    );

    if (ret != mpcrypt::ErrorCode::kSuccess) {
        printf(
            "解密失败，错误码: %d\n",
            static_cast<int>(ret)
        );
        return -1;
    }

    return 0;
}
```

### 带进度回调

```cpp
#include <cstdio>

void on_progress(
    uint64_t processed,
    uint64_t total,
    void*
) {
    double pct =
        total > 0
            ? processed * 100.0 / total
            : 0.0;

    printf("\r进度: %.1f%%", pct);
    fflush(stdout);
}

int main() {
    mpcrypt::encrypt_video_ex(
        "input.mp4",
        "pwd",
        nullptr,
        on_progress,
        nullptr
    );

    return 0;
}
```

## 📚 API 概览

详细定义见：

```cpp
#include <mpcrypt/VideoCrypt.h>
```

### 加密接口

```cpp
ErrorCode encrypt_video(
    const std::filesystem::path& input,
    const std::string& password,
    const std::filesystem::path* output = nullptr
);
```

### 解密接口

```cpp
ErrorCode decrypt_video(
    const std::filesystem::path& input,
    const std::string& password,
    const std::filesystem::path* output = nullptr
);
```

### 带进度回调

```cpp
ErrorCode encrypt_video_ex(
    const std::filesystem::path& input,
    const std::string& password,
    const std::filesystem::path* output,
    ProgressCallback cb,
    void* user
);

ErrorCode decrypt_video_ex(
    const std::filesystem::path& input,
    const std::string& password,
    const std::filesystem::path* output,
    ProgressCallback cb,
    void* user
);
```

## ⚠️ 错误码

| 枚举                    | 值  | 说明        |
| --------------------- | -- | --------- |
| kSuccess              | 0  | 成功        |
| kInvalidParameter     | -1 | 参数错误      |
| kInputFileOpenFailed  | -2 | 输入文件打开失败  |
| kRandomFailed         | -3 | 随机数生成失败   |
| kOutputFileOpenFailed | -4 | 输出文件打开失败  |
| kReadWriteFailed      | -5 | 文件读写失败    |
| kFooterInvalid        | -6 | Footer 损坏 |
| kFileSizeInvalid      | -7 | 文件大小异常    |
| kSeekFailed           | -8 | 文件定位失败    |
| kWrongPassword        | -9 | 密码错误      |

## ⚙️ 可配置参数

位于：

```cpp
src/VideoCrypt.cpp
```

可根据需求修改：

```cpp
HEAD_ENCRYPT_SIZE
```

默认：

```cpp
4 * 1024 * 1024
```

表示加密前 4MB。

---

随机填充范围：

```cpp
PADDING_MIN
PADDING_MAX
```

默认：

```cpp
16MB ~ 64MB
```

---

进度回调节流：

```cpp
total / 100
```

自动限制回调次数，最大约 200 次。

## 🧪 测试

构建测试目标：

```bash
cmake --build build --target mpcrypt_test
```

运行：

```bash
./build/mpcrypt_test
```

## 📄 License

本项目采用 [MIT License](LICENSE)。

内置第三方组件：

- [tiny-AES-c](https://github.com/kokke/tiny-AES-c)（MIT License）
- [PicoSHA2](https://github.com/okdshin/PicoSHA2)（MIT Compatible）

欢迎提交 Issue 和 Pull Request，希望这个库能够帮助你安全地保护视频文件。
