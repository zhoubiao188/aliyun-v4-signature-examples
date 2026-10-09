# C++ · 手写 OSS PutObject V4 签名（OSS4-HMAC-SHA256，CMake + OpenSSL）

配套文章：《阿里云 V4 签名实战（第3篇）· C++：手写 OSS PutObject V4 签名》（文章链接见仓库根 README 导航表）
与本仓库 `python-oss-putobject-v4/` 是同一套签名的 C++ 实现，共用同一组官方文档测试向量。

## 功能

- header-only 签名器 `include/oss_v4_signer.hpp`（C++17，仅依赖 OpenSSL Crypto）
- `src/main.cpp`：libcurl 发起 PutObject 上传
- `--dry-run` 打印签名全过程：CanonicalRequest / StringToSign / SigningKey / Signature / Authorization
- `test/test_signature.cpp`：官方文档示例离线自测（无需网络、无需真实 AK），接入 CTest

## 快速开始

```bash
# 依赖安装
#   macOS:   brew install cmake openssl
#   Ubuntu:  sudo apt install cmake g++ libssl-dev libcurl4-openssl-dev

cmake -B build -DCMAKE_BUILD_TYPE=Release
# macOS 如提示找不到 OpenSSL，追加：
#   cmake -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
cmake --build build

# 1) 先跑官方文档示例自测（推荐）
ctest --test-dir build --output-on-failure
# 或直接运行：./build/v4_selftest

# 2) 配置环境变量（推荐 RAM 子账号 AK，最小权限）
export ALIBABA_CLOUD_ACCESS_KEY_ID=<你的AccessKeyId>
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<你的AccessKeySecret>
export OSS_BUCKET=<你的Bucket名>          # 默认 your-bucket-name
export OSS_REGION=cn-hangzhou             # 可选，默认 cn-hangzhou

# 3) 查看签名过程，不发送请求
./build/oss_putobject_v4 --dry-run

# 4) 真实上传 hello-v4-signature-cpp.txt
./build/oss_putobject_v4
```

预期输出：`HTTP 200` 与 `ETag`，登录 OSS 控制台可看到对象 `hello-v4-signature-cpp.txt`。

## 目录结构

```
cpp-oss-putobject-v4/
├── CMakeLists.txt
├── include/oss_v4_signer.hpp   # header-only 签名器（可复用到你的项目）
├── src/main.cpp                # PutObject 主流程（libcurl）
└── test/test_signature.cpp     # 官方示例向量自测（CTest）
```

## 签名流程四步图

```
① CanonicalRequest  = Method \n URI \n Query \n Headers(std::map字典序,每行以\n结尾) \n AdditionalHeaders \n UNSIGNED-PAYLOAD
② StringToSign      = "OSS4-HMAC-SHA256" \n <x-oss-date> \n <日期>/<地域>/oss/aliyun_v4_request \n SHA256hex(①)
③ SigningKey        = HMAC链: ("aliyun_v4"+SK, 日期) → (·, 地域) → (·, "oss") → (·, "aliyun_v4_request")
④ Authorization     = OSS4-HMAC-SHA256 Credential=AK/<scope>,Signature=hex(HMAC(③, ②))
```

## C++ 实现要点

- 规范化头用 `std::map<std::string, std::string>`（自动按 key 字典序，与签名规范一致）；
- HMAC 派生密钥链的中间值是**二进制摘要**，统一用 `std::string`（二进制安全）传递，切勿经 `c_str()` 截断；
- `x-oss-date` 用 `gmtime_r + strftime("%Y%m%dT%H%M%SZ")` 生成 UTC 时间，误用 `localtime` 是高频 403 原因；
- URI 编码自行实现（仅 `A-Za-z0-9-._~` 不编码，空格 `%20`，路径保留 `/`），不依赖 libcurl 的 `curl_easy_escape`（其转义集与 OSS 规范不同）。

## 常见错误排查

| 现象 | 原因与排查 |
| --- | --- |
| 403 SignatureDoesNotMatch | 待签串与请求实际内容不一致：检查头小写排序、值 trim、`content-type` 是否漏签、`x-oss-date` 与请求头是否一致 |
| 403 RequestTimeTooSkewed | 本机时钟偏差过大，或误用本地时间代替 UTC |
| cmake 找不到 OpenSSL | macOS 加 `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl)` |
| 链接错误 undefined HMAC/EVP | 未链接 OpenSSL::Crypto，或 Linux 漏装 libssl-dev |
| AccessDenied | RAM 子账号缺少 `oss:PutObject` 权限 |

## 安全约定

本工程不会提交任何真实密钥；AK/SK 只从环境变量读取。若 AK 泄露请立即在控制台禁用并轮换。
