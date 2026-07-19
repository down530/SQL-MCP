#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
认证token生成模块
提供RSA密钥对生成和访问令牌创建功能
支持密钥对持久化，确保跨重启Token不变
"""

import os
from fastmcp.server.auth import BearerAuthProvider
from fastmcp.server.auth.providers.bearer import RSAKeyPair

# 密钥文件路径（保存在项目根目录）
KEY_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".keys")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")


def load_or_generate_key_pair() -> RSAKeyPair:
    """加载已有的密钥对，如果不存在则生成新的并保存"""
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        print("[OK] Loading existing RSA key pair from .keys/")
        with open(PRIVATE_KEY_PATH, "r") as f:
            private_key = f.read()
        with open(PUBLIC_KEY_PATH, "r") as f:
            public_key = f.read()
        from pydantic import SecretStr
        return RSAKeyPair(private_key=SecretStr(private_key), public_key=public_key)
    else:
        print("[OK] Generating new RSA key pair...")
        key_pair = RSAKeyPair.generate()
        os.makedirs(KEY_DIR, exist_ok=True)
        with open(PRIVATE_KEY_PATH, "w") as f:
            f.write(key_pair.private_key.get_secret_value())
        with open(PUBLIC_KEY_PATH, "w") as f:
            f.write(key_pair.public_key)
        print(f"[OK] Key pair saved to {KEY_DIR}/")
        return key_pair


def create_auth_components():
    """
    创建认证组件
    使用持久化的密钥对，Token有效期设为10年

    Returns:
        BearerAuthProvider
    """
    # 加载或生成RSA密钥对
    key_pair = load_or_generate_key_pair()

    # 创建访问令牌（有效期10年 = 315360000秒）
    TEN_YEARS = 315360000
    access_token = key_pair.create_token(
        subject="58bf32d9-ef25-484f-bb7d-bfc683e5b3eb",
        issuer="https://fastmcp.example.com",
        audience="data-analysis-mcp",
        scopes=["data:read_tables", "data:read_table_data"],
        expires_in_seconds=TEN_YEARS,
    )

    print(f'Authorization=Bearer {access_token}')

    # 创建认证提供者
    auth = BearerAuthProvider(
        public_key=key_pair.public_key,
        audience="data-analysis-mcp",
    )

    return auth
