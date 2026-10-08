#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""手写实现阿里云 OSS V4 签名（OSS4-HMAC-SHA256）并执行 PutObject 上传。

用法：
    export ALIBABA_CLOUD_ACCESS_KEY_ID=<你的AccessKeyId>
    export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<你的AccessKeySecret>
    export OSS_BUCKET=<你的Bucket名>
    python3 main.py            # 真实上传
    python3 main.py --dry-run  # 只打印签名过程与最终请求，不发送

仅依赖 Python 标准库 + requests，不使用任何阿里云 SDK。
签名规范参考：阿里云官方文档《在Header中包含V4签名》
"""
import argparse
import datetime as dt
import hashlib
import hmac
import os
import urllib.parse

import requests

REGION = os.environ.get("OSS_REGION", "cn-hangzhou")
BUCKET = os.environ.get("OSS_BUCKET", "your-bucket-name")
OBJECT_KEY = os.environ.get("OSS_OBJECT_KEY", "hello-v4-signature.txt")
BODY = "Hello OSS V4 Signature (OSS4-HMAC-SHA256)!\n".encode("utf-8")
CONTENT_TYPE = "text/plain; charset=utf-8"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def uri_encode(s: str, slash_safe: bool = True) -> str:
    """OSS V4 的 URI 编码：仅 A-Za-z0-9-._~ 不编码（空格编码为 %20）。

    slash_safe=True 用于对象键路径（保留 /），False 用于查询参数。
    """
    safe = "-._~" + ("/" if slash_safe else "")
    return urllib.parse.quote(s, safe=safe)


def build_signing_key(secret: str, date: str, region: str) -> bytes:
    """V4 派生密钥（HMAC 链）：
    kDate = HMAC("aliyun_v4"+SK, 日期) → kRegion = HMAC(kDate, 地域)
    → kService = HMAC(kRegion, "oss") → kSigning = HMAC(kService, "aliyun_v4_request")
    """
    k_date = hmac_sha256(("aliyun_v4" + secret).encode("utf-8"), date)
    k_region = hmac_sha256(k_date, region)
    k_service = hmac_sha256(k_region, "oss")
    return hmac_sha256(k_service, "aliyun_v4_request")


def build_canonical_request(method, canonical_uri, query_items, headers,
                            additional_names, hashed_payload):
    """CanonicalRequest = Method\\nURI\\nQuery\\nHeaders\\nAdditionalHeaders\\nHashedPayload

    headers 只传"参与签名"的头（小写键）；additional_names 是其中需要
    在 Authorization.AdditionalHeaders 中声明的可选头（其余为自动参与）。
    """
    names = sorted(headers)
    canonical_headers = "".join(f"{n}:{str(headers[n]).strip()}\n" for n in names)
    additional_headers = ";".join(sorted(additional_names or []))
    q = sorted((uri_encode(k, False), uri_encode(str(v), False)) for k, v in query_items)
    canonical_query = "&".join(f"{k}={v}" for k, v in q)
    canonical_request = "\n".join(
        [method, canonical_uri, canonical_query,
         canonical_headers, additional_headers, hashed_payload]
    )
    return canonical_request, additional_headers


def sign(method, canonical_uri, query_items, headers, additional_names,
         hashed_payload, ak, sk, region, x_oss_date):
    """返回签名结果与全部中间值（便于 --dry-run 对照官方文档排查）。"""
    date = x_oss_date[:8]  # x_oss_date 形如 20250411T064124Z
    canonical_request, additional_field = build_canonical_request(
        method, canonical_uri, query_items, headers, additional_names, hashed_payload)

    scope = f"{date}/{region}/oss/aliyun_v4_request"
    string_to_sign = "\n".join(
        ["OSS4-HMAC-SHA256", x_oss_date, scope, sha256_hex(canonical_request.encode("utf-8"))]
    )
    signing_key = build_signing_key(sk, date, region)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"),
                         hashlib.sha256).hexdigest()

    auth = f"OSS4-HMAC-SHA256 Credential={ak}/{scope},"
    if additional_field:
        auth += f"AdditionalHeaders={additional_field},"
    auth += f"Signature={signature}"

    return {
        "canonical_request": canonical_request,
        "string_to_sign": string_to_sign,
        "signing_key_hex": signing_key.hex(),
        "signature": signature,
        "authorization": auth,
        "scope": scope,
    }


def main():
    parser = argparse.ArgumentParser(description="手写 OSS V4 签名 PutObject")
    parser.add_argument("--dry-run", action="store_true", help="只打印签名过程，不发送请求")
    args = parser.parse_args()

    ak = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
    sk = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")
    if not ak or not sk:
        raise SystemExit("请先设置环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET")

    now = dt.datetime.now(dt.timezone.utc)
    x_oss_date = now.strftime("%Y%m%dT%H%M%SZ")

    # 参与签名的请求头：x-oss-content-sha256 必须存在；content-type 存在则自动参与。
    # 当前 V4 只支持 x-oss-content-sha256: UNSIGNED-PAYLOAD（不做真实负载哈希）。
    headers = {
        "content-type": CONTENT_TYPE,
        "x-oss-content-sha256": "UNSIGNED-PAYLOAD",
        "x-oss-date": x_oss_date,
    }
    host = f"{BUCKET}.oss-{REGION}.aliyuncs.com"
    url = f"https://{host}/{uri_encode(OBJECT_KEY)}"

    result = sign("PUT", "/" + uri_encode(OBJECT_KEY), [], headers, None,
                  "UNSIGNED-PAYLOAD", ak, sk, REGION, x_oss_date)

    print("=" * 60)
    print("CanonicalRequest（规范化请求）:")
    print(result["canonical_request"])
    print("=" * 60)
    print("StringToSign（待签名字符串）:")
    print(result["string_to_sign"])
    print("=" * 60)
    print("SigningKey(hex):", result["signing_key_hex"])
    print("Signature(hex):", result["signature"])
    print("Authorization:", result["authorization"])
    print("=" * 60)

    if args.dry_run:
        print(f"[dry-run] PUT {url}")
        return

    resp = requests.put(
        url,
        data=BODY,
        headers={
            "Authorization": result["authorization"],
            "content-type": CONTENT_TYPE,
            "x-oss-content-sha256": "UNSIGNED-PAYLOAD",
            "x-oss-date": x_oss_date,
        },
        timeout=30,
    )
    print(f"PUT {url}")
    print(f"HTTP {resp.status_code}")
    print("ETag:", resp.headers.get("ETag", "-"))
    resp.raise_for_status()
    print("上传成功 ✅")


if __name__ == "__main__":
    main()
