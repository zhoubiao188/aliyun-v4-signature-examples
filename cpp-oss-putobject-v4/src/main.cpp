// 手写实现阿里云 OSS V4 签名（OSS4-HMAC-SHA256）并执行 PutObject 上传。
// 用法：
//   export ALIBABA_CLOUD_ACCESS_KEY_ID=<你的AccessKeyId>
//   export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<你的AccessKeySecret>
//   export OSS_BUCKET=<你的Bucket名>
//   ./oss_putobject_v4            # 真实上传
//   ./oss_putobject_v4 --dry-run  # 只打印签名过程，不发送请求
#include <curl/curl.h>

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <map>
#include <string>

#include "oss_v4_signer.hpp"

namespace {

size_t OnBody(char* ptr, size_t size, size_t nmemb, void* userdata) {
    static_cast<std::string*>(userdata)->append(ptr, size * nmemb);
    return size * nmemb;
}

size_t OnHeader(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* etag = static_cast<std::string*>(userdata);
    std::string line(ptr, size * nmemb);
    if (line.rfind("ETag:", 0) == 0 || line.rfind("etag:", 0) == 0) {
        *etag = line.substr(line.find(':') + 1);
    }
    return size * nmemb;
}

}  // namespace

int main(int argc, char** argv) {
    const bool dry_run = argc > 1 && std::string(argv[1]) == "--dry-run";

    const char* ak = std::getenv("ALIBABA_CLOUD_ACCESS_KEY_ID");
    const char* sk = std::getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
    if (!ak || !sk || !*ak || !*sk) {
        std::cerr << "请先设置环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET\n";
        return 1;
    }
    const std::string region = std::getenv("OSS_REGION") ? std::getenv("OSS_REGION") : "cn-hangzhou";
    const std::string bucket = std::getenv("OSS_BUCKET") ? std::getenv("OSS_BUCKET") : "your-bucket-name";
    const std::string object_key = "hello-v4-signature-cpp.txt";
    const std::string body = "Hello OSS V4 Signature from C++!\n";
    const std::string content_type = "text/plain; charset=utf-8";

    // 签名时间必须 UTC（注意用 gmtime_r，不是 localtime）
    std::time_t now = std::time(nullptr);
    std::tm tm_utc{};
    gmtime_r(&now, &tm_utc);
    char x_oss_date[32];
    std::strftime(x_oss_date, sizeof(x_oss_date), "%Y%m%dT%H%M%SZ", &tm_utc);

    // 参与签名的头：x-oss-content-sha256 必须存在；content-type 存在即参与
    std::map<std::string, std::string> headers = {
        {"content-type", content_type},
        {"x-oss-content-sha256", "UNSIGNED-PAYLOAD"},
        {"x-oss-date", x_oss_date},
    };

    const std::string host = bucket + ".oss-" + region + ".aliyuncs.com";
    const std::string encoded_key = oss_v4::uri_encode(object_key);
    const std::string url = "https://" + host + "/" + encoded_key;

    const oss_v4::SignResult r = oss_v4::sign(
        "PUT", "/" + encoded_key, {}, headers, {}, "UNSIGNED-PAYLOAD",
        ak, sk, region, x_oss_date);

    std::cout
        << "============================================================\n"
        << "CanonicalRequest（规范化请求）:\n" << r.canonical_request << "\n"
        << "============================================================\n"
        << "StringToSign（待签名字符串）:\n" << r.string_to_sign << "\n"
        << "============================================================\n"
        << "SigningKey(hex): " << r.signing_key_hex << "\n"
        << "Signature(hex):  " << r.signature << "\n"
        << "Authorization:   " << r.authorization << "\n"
        << "============================================================\n";

    if (dry_run) {
        std::cout << "[dry-run] PUT " << url << "\n";
        return 0;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "curl init failed\n";
        return 1;
    }

    std::string resp_body;
    std::string etag;
    curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, ("Authorization: " + r.authorization).c_str());
    hdrs = curl_slist_append(hdrs, ("content-type: " + content_type).c_str());
    hdrs = curl_slist_append(hdrs, "x-oss-content-sha256: UNSIGNED-PAYLOAD");
    hdrs = curl_slist_append(hdrs, ("x-oss-date: " + std::string(x_oss_date)).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, OnBody);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, OnHeader);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &etag);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        std::cerr << "curl error: " << curl_easy_strerror(rc) << "\n";
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
        return 1;
    }

    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    std::cout << "PUT " << url << "\nHTTP " << status << "\nETag: " << etag << "\n";
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (status == 200) {
        std::cout << "上传成功 ✅\n";
        return 0;
    }
    std::cout << "响应体: " << resp_body << "\n";
    return 1;
}
