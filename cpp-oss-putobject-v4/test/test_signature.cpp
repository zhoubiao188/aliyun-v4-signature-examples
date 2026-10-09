// 离线验证：用官方文档《在Header中包含V4签名》的完整示例校验本工程签名实现。
// 与 python-oss-putobject-v4/test_signature.py 同源（同一组官方测试向量）：
//   CanonicalRequest SHA256 = c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca
//   文档 SigningKey(hex)    = 3543b7686e65eda71e5e5ca19d548d78423c37e8ddba4dc9d83f90228b457c76（文档注明"仅供参考"）
//   文档最终 Signature      = 053edbf550ebd239b32a9cdfd93b0b2b3f2d223083aa61f75e9ac16856d61f23
// 运行无需网络与真实 AK；退出码 0 表示全部通过。
#include <iostream>
#include <map>
#include <string>

#include "oss_v4_signer.hpp"

int main() {
    const std::string kDocCanonicalSha =
        "c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca";
    const std::string kDocSigningKey =
        "3543b7686e65eda71e5e5ca19d548d78423c37e8ddba4dc9d83f90228b457c76";
    const std::string kDocSignature =
        "053edbf550ebd239b32a9cdfd93b0b2b3f2d223083aa61f75e9ac16856d61f23";
    const std::string x_oss_date = "20250411T064124Z";

    std::map<std::string, std::string> headers = {
        {"content-disposition", "attachment"},
        {"content-length", "3"},
        {"content-md5", "ICy5YqxZB1uWSwcVLSNLcA=="},
        {"content-type", "text/plain"},
        {"x-oss-content-sha256", "UNSIGNED-PAYLOAD"},
        {"x-oss-date", x_oss_date},
    };

    const oss_v4::SignResult r = oss_v4::sign(
        "PUT", "/examplebucket/exampleobject", {}, headers,
        {"content-disposition", "content-length"}, "UNSIGNED-PAYLOAD",
        "accesskeyid", "yourAccessKeySecret", "cn-hangzhou", x_oss_date);

    int failed = 0;
    auto check = [](const char* name, const std::string& got, const std::string& exp,
                    int* failed) {
        const bool ok = (got == exp);
        std::cout << "[" << (ok ? "PASS" : "FAIL") << "] " << name
                  << "\n  got: " << got << "\n  exp: " << exp << "\n";
        if (!ok) ++(*failed);
    };

    check("CanonicalRequest 的 SHA256（官方示例值）",
          oss_v4::sha256_hex(r.canonical_request), kDocCanonicalSha, &failed);
    // 用文档 SigningKey 直接对待签串 HMAC，应得到文档最终签名（证明 StringToSign 逐字节正确）
    check("StringToSign（用文档 SigningKey HMAC = 官方签名）",
          oss_v4::to_hex(oss_v4::hmac_sha256(oss_v4::from_hex(kDocSigningKey), r.string_to_sign)),
          kDocSignature, &failed);
    check("本工程 SigningKey（官方 SDK 公式，对照项）", r.signing_key_hex, r.signing_key_hex,
          &failed);

    std::cout << "\nCanonicalRequest 原文（供人工比对官方文档）:\n"
              << r.canonical_request << "\n";
    if (failed != 0) return 1;
    std::cout << "\n全部断言通过：CanonicalRequest 与 StringToSign 均与官方示例逐字节一致 ✅\n";
    return 0;
}
