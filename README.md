# 阿里云 V4 签名实战示例集（Aliyun V4 Signature Examples）

本仓库是阿里云开发者社区专栏**「阿里云 V4 签名实战」系列文章**的配套完整工程代码，每篇文章对应一个**可直接导入编辑器运行的独立项目**：安装依赖 → 替换自己的 AK/SK（推荐环境变量）→ 运行即可。

## 系列文章导航

| 篇目 | 语言 | 主题 | 工程目录 | 文章链接 |
| --- | --- | --- | --- | --- |
| 1 | Python | 手写 OSS PutObject V4 签名（OSS4-HMAC-SHA256）已发布 | [python-oss-putobject-v4/](python-oss-putobject-v4/) | https://developer.aliyun.com/article/1768774 |
| 2 | Java | 手写 OpenAPI V4 签名（ACS3-HMAC-SHA256）调用 ECS | `java-openapi-acs3/` | 待发布后补充 |
| 3 | C++ | 手写 OSS PutObject V4 签名（CMake + OpenSSL） | [cpp-oss-putobject-v4/](cpp-oss-putobject-v4/) | 待发布后补充 |

## 覆盖的两种 V4 签名协议

1. **OSS V4 签名（OSS4-HMAC-SHA256）**：用于 OSS 原生 API（PutObject / GetObject / 预签名 URL 等）。派生密钥为 HMAC 链：
   `kDate = HMAC("aliyun_v4" + SK, date)` → `kRegion = HMAC(kDate, region)` → `kService = HMAC(kRegion, "oss")` → `kSigning = HMAC(kService, "aliyun_v4_request")`
2. **OpenAPI V3 签名（ACS3-HMAC-SHA256）**：用于阿里云全系 OpenAPI（ECS / CDN / VOD 等云产品 API）。签名密钥直接使用 AccessKeySecret 做一次 HMAC-SHA256，比 AWS SigV4 更简洁。

## 安全约定（重要）

- **本仓库永远不会提交任何真实 AccessKey / Secret**，所有示例统一从环境变量读取：
  - `ALIBABA_CLOUD_ACCESS_KEY_ID`
  - `ALIBABA_CLOUD_ACCESS_KEY_SECRET`
- 建议使用 RAM 子账号 AK，并只授予所需的最小权限。
- 若你不慎泄露 AK，请立即在控制台禁用并轮换。

## 目录结构

每个子目录都是一个独立工程，自带依赖清单与 README：

- `python-*`：`requirements.txt`（`pip install -r requirements.txt`）
- `java-*`：Maven `pom.xml`（`mvn compile exec:java`）
- `cpp-*`：`CMakeLists.txt`（依赖 OpenSSL，`cmake -B build && cmake --build build`）

## License

MIT
