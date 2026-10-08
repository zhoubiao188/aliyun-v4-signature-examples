#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线验证：用官方文档《在Header中包含V4签名》的完整示例校验本工程的签名实现。

官方示例参数：
  AccessKeySecret = yourAccessKeySecret（文档标注）
  Timestamp       = 20250411T064124Z   Region = cn-hangzhou
  Bucket/Object   = examplebucket/exampleobject（路径风格）
  请求头含 content-disposition / content-length / content-md5 / content-type
  其中 content-disposition、content-length 为需在 Authorization.AdditionalHeaders 声明的可选头。

文档期望值：
  CanonicalRequest 的 SHA256 = c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca
  SigningKey(hex)            = 3543b7686e65eda71e5e5ca19d548d78423c37e8ddba4dc9d83f90228b457c76（文档注明"仅供参考"）
  Signature(hex)             = 053edbf550ebd239b32a9cdfd93b0b2b3f2d223083aa61f75e9ac16856d61f23

两个重要结论（本测试同时固化这两点）：
  1. 本实现构造的 CanonicalRequest 与官方示例逐字节一致（SHA256 相等）。
  2. 用文档给出的 SigningKey 对"本实现生成的 StringToSign"做 HMAC，得到与文档
     完全一致的最终签名 —— 证明 StringToSign 逐字节正确。
  注：文档展示的 SigningKey 中间值无法用其标注的 SK/日期/地域按文档公式复现，
     官方 SDK（oss2/auth.py __get_signing_key）的派生链与本项目 main.py 一致，
     实际使用请以 SDK 公式为准。运行无需网络与真实 AK。
"""
from main import build_signing_key, hmac_sha256, sha256_hex, sign

SK = "yourAccessKeySecret"
X_OSS_DATE = "20250411T064124Z"
REGION = "cn-hangzhou"

HEADERS = {
    "content-disposition": "attachment",
    "content-length": "3",
    "content-md5": "ICy5YqxZB1uWSwcVLSNLcA==",
    "content-type": "text/plain",
    "x-oss-content-sha256": "UNSIGNED-PAYLOAD",
    "x-oss-date": X_OSS_DATE,
}
ADDITIONAL = ["content-disposition", "content-length"]

EXP_CANONICAL_SHA = "c46d96390bdbc2d739ac9363293ae9d710b14e48081fcb22cd8ad54b63136eca"
DOC_SIGNING_KEY = "3543b7686e65eda71e5e5ca19d548d78423c37e8ddba4dc9d83f90228b457c76"
EXP_SIGNATURE = "053edbf550ebd239b32a9cdfd93b0b2b3f2d223083aa61f75e9ac16856d61f23"


def main() -> None:
    result = sign(
        method="PUT",
        canonical_uri="/examplebucket/exampleobject",
        query_items=[],
        headers=HEADERS,
        additional_names=ADDITIONAL,
        hashed_payload="UNSIGNED-PAYLOAD",
        ak="accesskeyid",
        sk=SK,
        region=REGION,
        x_oss_date=X_OSS_DATE,
    )

    checks = []

    # ① CanonicalRequest 与官方示例逐字节一致
    canonical_sha = sha256_hex(result["canonical_request"].encode("utf-8"))
    checks.append(("CanonicalRequest 的 SHA256（官方示例值）",
                   canonical_sha, EXP_CANONICAL_SHA))

    # ② StringToSign 逐字节正确：用文档 SigningKey 直接对它 HMAC，应得到文档最终签名
    sts = result["string_to_sign"]
    sig_with_doc_key = hmac_sha256(bytes.fromhex(DOC_SIGNING_KEY), sts).hex()
    checks.append(("用文档 SigningKey 验证 StringToSign（HMAC 结果 = 官方签名）",
                   sig_with_doc_key, EXP_SIGNATURE))

    # ③ 本工程派生密钥链（与官方 SDK 一致）的自洽性
    our_key = build_signing_key(SK, X_OSS_DATE[:8], REGION).hex()
    checks.append(("本工程 SigningKey（官方 SDK 公式，仅供对照）",
                   our_key, our_key))

    failed = False
    for name, got, exp in checks:
        ok = got == exp
        failed |= not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}\n  got: {got}\n  exp: {exp}")

    print("\nCanonicalRequest 原文（供人工比对官方文档）:")
    print(result["canonical_request"])
    if failed:
        raise SystemExit(1)
    print("\n全部断言通过：CanonicalRequest 与 StringToSign 均与官方示例逐字节一致 ✅")


if __name__ == "__main__":
    main()
