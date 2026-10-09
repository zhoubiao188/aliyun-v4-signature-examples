// 阿里云 OSS V4 签名（OSS4-HMAC-SHA256）header-only 实现
// 规范参考：阿里云官方文档《在Header中包含V4签名》；
// 派生密钥链与官方 SDK（oss2/auth.py __get_signing_key）一致。
#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace oss_v4 {

inline std::string to_hex(const std::string& bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        out += kHex[c >> 4];
        out += kHex[c & 0x0F];
    }
    return out;
}

inline std::string from_hex(const std::string& hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return "";
        out += static_cast<char>((hi << 4) | lo);
    }
    return out;
}

inline std::string sha256_hex(const std::string& data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    EVP_Digest(data.data(), data.size(), md, &md_len, EVP_sha256(), nullptr);
    return to_hex(std::string(reinterpret_cast<char*>(md), md_len));
}

// 返回原始二进制摘要；std::string 二进制安全，可直接作为下一步 HMAC 的 key
inline std::string hmac_sha256(const std::string& key, const std::string& msg) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), md, &md_len);
    return std::string(reinterpret_cast<char*>(md), md_len);
}

inline std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

// OSS V4 URI 编码：仅 A-Za-z0-9-._~ 不编码（空格为 %20）；slash_safe 时保留 '/'
inline std::string uri_encode(const std::string& s, bool slash_safe = true) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        bool keep = std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' ||
                    (slash_safe && c == '/');
        if (keep) {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

struct SignResult {
    std::string canonical_request;
    std::string string_to_sign;
    std::string signing_key_hex;
    std::string signature;
    std::string authorization;
};

// headers：参与签名的头（小写键；std::map 保证字典序）
// additional：其中需要在 Authorization.AdditionalHeaders 中声明的可选头
// hashed_payload：当前 OSS V4 仅支持固定值 "UNSIGNED-PAYLOAD"
inline SignResult sign(const std::string& method,
                       const std::string& canonical_uri,
                       const std::vector<std::pair<std::string, std::string>>& query_items,
                       const std::map<std::string, std::string>& headers,
                       const std::vector<std::string>& additional,
                       const std::string& hashed_payload,
                       const std::string& ak,
                       const std::string& sk,
                       const std::string& region,
                       const std::string& x_oss_date) {
    const std::string date = x_oss_date.substr(0, 8);

    std::string canonical_headers;
    for (const auto& kv : headers) {  // std::map 已按 key 字典序
        canonical_headers += kv.first + ":" + trim(kv.second) + "\n";
    }

    std::vector<std::string> additional_sorted = additional;
    std::sort(additional_sorted.begin(), additional_sorted.end());
    std::string additional_str;
    for (size_t i = 0; i < additional_sorted.size(); ++i) {
        if (i) additional_str += ";";
        additional_str += additional_sorted[i];
    }

    std::vector<std::pair<std::string, std::string>> q;
    q.reserve(query_items.size());
    for (const auto& kv : query_items) {
        q.emplace_back(uri_encode(kv.first, false), uri_encode(kv.second, false));
    }
    std::sort(q.begin(), q.end());
    std::string canonical_query;
    for (size_t i = 0; i < q.size(); ++i) {
        if (i) canonical_query += "&";
        canonical_query += q[i].first + "=" + q[i].second;
    }

    // CanonicalRequest = Method \n URI \n Query \n Headers \n AdditionalHeaders \n HashedPayload
    std::string canonical_request = method + "\n" + canonical_uri + "\n" + canonical_query +
                                    "\n" + canonical_headers + "\n" + additional_str + "\n" +
                                    hashed_payload;

    const std::string scope = date + "/" + region + "/oss/aliyun_v4_request";
    std::string string_to_sign = "OSS4-HMAC-SHA256\n" + x_oss_date + "\n" + scope + "\n" +
                                 sha256_hex(canonical_request);

    // 派生密钥链：kDate → kRegion → kService("oss") → kSigning("aliyun_v4_request")
    std::string k_date = hmac_sha256("aliyun_v4" + sk, date);
    std::string k_region = hmac_sha256(k_date, region);
    std::string k_service = hmac_sha256(k_region, "oss");
    std::string k_signing = hmac_sha256(k_service, "aliyun_v4_request");

    std::string signature = to_hex(hmac_sha256(k_signing, string_to_sign));

    std::string auth = "OSS4-HMAC-SHA256 Credential=" + ak + "/" + scope + ",";
    if (!additional_str.empty()) auth += "AdditionalHeaders=" + additional_str + ",";
    auth += "Signature=" + signature;

    return SignResult{canonical_request, string_to_sign, to_hex(k_signing), signature, auth};
}

}  // namespace oss_v4
