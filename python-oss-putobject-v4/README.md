# Python · 手写 OSS PutObject V4 签名（OSS4-HMAC-SHA256）

配套文章：《阿里云 V4 签名实战（第1篇）· Python：手写 OSS PutObject V4 签名》（文章链接见仓库根 README 导航表）

## 功能

- **纯手写**实现阿里云 OSS V4 签名（不依赖任何阿里云 SDK，仅标准库 + requests），完成 PutObject 上传
- `--dry-run` 打印签名全过程：CanonicalRequest / StringToSign / SigningKey / Signature / Authorization，可逐行对照官方文档
- `test_signature.py` 使用**官方文档示例**离线验证实现正确性（无需网络、无需真实 AK）

## 快速开始

```bash
pip install -r requirements.txt

# 配置环境变量（推荐使用 RAM 子账号 AK，授予该 Bucket 的最小权限）
export ALIBABA_CLOUD_ACCESS_KEY_ID=<你的AccessKeyId>
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<你的AccessKeySecret>
export OSS_BUCKET=<你的Bucket名>        # 默认 your-bucket-name
export OSS_REGION=cn-hangzhou           # 可选，默认 cn-hangzhou

# 1) 先离线验证签名实现与官方文档一致（推荐先跑这个）
python3 test_signature.py

# 2) 查看签名过程，不发送请求
python3 main.py --dry-run

# 3) 真实上传 hello-v4-signature.txt
python3 main.py
```

预期输出：`HTTP 200` 与 `ETag`，登录 OSS 控制台可看到对象 `hello-v4-signature.txt`。

## 目录结构

```
python-oss-putobject-v4/
├── main.py             # 签名实现 + PutObject 主流程
├── test_signature.py   # 官方文档示例离线验证（单测）
└── requirements.txt    # 依赖：requests
```

## 签名流程四步图

```
① CanonicalRequest  = Method \n URI \n Query \n Headers(小写排序) \n AdditionalHeaders \n UNSIGNED-PAYLOAD
② StringToSign      = "OSS4-HMAC-SHA256" \n <x-oss-date> \n <日期>/<地域>/oss/aliyun_v4_request \n SHA256hex(①)
③ SigningKey        = HMAC链: ("aliyun_v4"+SK, 日期) → (·, 地域) → (·, "oss") → (·, "aliyun_v4_request")
④ Authorization     = OSS4-HMAC-SHA256 Credential=AK/<scope>,Signature=hex(HMAC(③, ②))
```

## 常见错误排查

| 现象 | 原因与排查 |
| --- | --- |
| 403 SignatureDoesNotMatch | 待签串构造与请求实际内容不一致：检查头名是否小写并排序、值是否 trim、`content-type` 等"存在即参与"的头是否漏签、`x-oss-date` 是否与请求头一致 |
| 403 InvalidAccessKeyId | AK 错误、或使用了其他账号/被禁用的 AK |
| 403 RequestTimeTooSkewed | `x-oss-date` 与服务器时间偏差过大，检查本机时钟 |
| 404 NoSuchBucket / NoSuchKey | Bucket 名或对象键错误；注意虚拟主机风格 URL 为 `bucket.oss-region.aliyuncs.com/key` |
| AccessDenied | RAM 子账号缺少 `oss:PutObject` 权限 |

## 安全约定

本工程不会提交任何真实密钥；AK/SK 只从环境变量读取。若 AK 泄露请立即在控制台禁用并轮换。
