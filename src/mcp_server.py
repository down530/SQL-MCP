#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP数据查询服务器
基于FastMCP框架，提供安全的数据库查询服务
"""

import os
from typing import Dict, Any
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token, AccessToken
from dotenv import load_dotenv
# 导入现有模块
from database import DatabaseManager
# 导入新的认证模块
from auth_token import create_auth_components

# 加载环境变量
load_dotenv()

# 全局数据库管理器实例
db_manager = None

# 创建认证组件
auth = create_auth_components()

mcp = FastMCP(name="data-analysis-mcp", auth=auth)

def initialize_services():
    """初始化服务"""
    global db_manager

    if db_manager is None:
        db_manager = DatabaseManager()
        if not db_manager.connect():
            raise Exception("数据库连接失败")


def get_validated_access_token() -> AccessToken:
    """获取并验证访问令牌"""
    try:
        access_token = get_access_token()
        if access_token is None:
            # 本地开发模式：如果未提供令牌，返回默认权限令牌
            from fastmcp.server.dependencies import AccessToken as AT
            print("[WARN] No access token provided, using default permissions for local development")
            return AT(
                client_id="local-dev",
                scopes=["data:read_tables", "data:read_table_data"],
                audience="data-analysis-mcp",
                issuer="local",
                subject="local-dev",
                expiration=None,
            )
        return access_token
    except Exception as e:
        raise ToolError(f"权限验证失败: {str(e)}")


def check_permissions(access_token: AccessToken, required_scopes: list) -> None:
    """检查权限"""
    if not access_token.scopes:
        raise ToolError("用户没有任何权限")

    missing_scopes = [scope for scope in required_scopes if scope not in access_token.scopes]
    if missing_scopes:
        raise ToolError(f"权限不足：需要以下权限: {', '.join(missing_scopes)}")

# 移除convert_numpy函数，不再需要

@mcp.tool
async def get_database_tables(ctx: Context) -> Dict[str, Any]:
    """
    获取数据库中所有表的列表
    需要 'data:read' 权限
    """
    access_token = get_validated_access_token()
    check_permissions(access_token, ["data:read_tables"])

    try:
        initialize_services()
        tables = db_manager.get_all_tables()

        return {
            "user_id": access_token.client_id,
            "tables": tables,
            "total_tables": len(tables),
            "message": f"成功获取 {len(tables)} 个表"
        }
    except Exception as e:
        raise ToolError(f"获取表列表失败: {str(e)}")


@mcp.tool
async def get_table_structure(ctx: Context, table_name: str) -> Dict[str, Any]:
    """
    获取指定表的结构信息
    需要 'data:read' 权限

    Args:
        table_name: 表名
    """
    access_token = get_validated_access_token()
    check_permissions(access_token, ["data:read_tables"])

    try:
        initialize_services()
        table_info = db_manager.get_table_info(table_name)

        if not table_info:
            raise ToolError(f"表 '{table_name}' 不存在或无法访问")

        # 直接返回字典数据，无需转换
        result = {
            "user_id": access_token.client_id,
            "table_name": table_name,
            "total_rows": int(table_info.get('total_rows', 0))
        }
        if 'structure' in table_info and table_info['structure'] is not None:
            result["structure"] = table_info['structure']
        if 'sample_data' in table_info and table_info['sample_data'] is not None:
            result["sample_data"] = table_info['sample_data']
        return result

    except Exception as e:
        raise ToolError(f"获取表结构失败: {str(e)}")


@mcp.tool
async def execute_sql_query(ctx: Context, sql_query: str, limit: int = 100) -> Dict[str, Any]:
    """
    执行SQL查询
    需要 'data:read' 权限，查询需要 'data:read_table_data' 权限

    Args:
        sql_query: SQL查询语句
        limit: 返回结果的最大行数，默认100
    """
    access_token = get_validated_access_token()
    check_permissions(access_token, ["data:read_table_data"])

    # 检查是否为敏感查询（包含特定关键词）
    sensitive_keywords = ['password', 'secret', 'token', 'private', 'confidential']
    is_sensitive = any(keyword in sql_query.lower() for keyword in sensitive_keywords)

    if is_sensitive:
        check_permissions(access_token, ["data:read_table_data"])

    # 安全检查：禁止危险操作
    dangerous_keywords = ['drop', 'delete', 'update', 'insert', 'alter', 'create', 'truncate']
    if any(keyword in sql_query.lower() for keyword in dangerous_keywords):
        raise ToolError("安全限制：不允许执行修改数据的操作")

    try:
        initialize_services()

        # 添加LIMIT限制
        if 'limit' not in sql_query.lower():
            sql_query = f"{sql_query.rstrip(';')} LIMIT {limit}"

        result_data = db_manager.execute_query(sql_query)

        if result_data is None:
            raise ToolError("查询执行失败")

        # 获取列名（如果有数据的话）
        columns = list(result_data[0].keys()) if result_data else []

        return {
            "user_id": access_token.client_id,
            "query": sql_query,
            "row_count": len(result_data),
            "columns": columns,
            "data": result_data,
            "message": f"查询成功，返回 {len(result_data)} 行数据"
        }

    except Exception as e:
        raise ToolError(f"查询执行失败: {str(e)}")


@mcp.tool
async def get_user_permissions(ctx: Context) -> dict:
    """
    获取当前用户的权限信息
    无需特殊权限，但需要有效的访问令牌
    """
    try:
        print(ctx)
        access_token: AccessToken = get_access_token()
        print(f'access_token: {access_token}')
        # 如果没有访问令牌，返回默认信息
        if access_token is None:
            return {
                "user_id": "anonymous",
                "scopes": [],
                "permissions": {
                    "can_read_tables": False,
                    "can_read_table_data": False
                },
                "message": "未认证用户，无权限"
            }

        return {
            "user_id": access_token.client_id or "unknown",
            "scopes": access_token.scopes or [],
            "permissions": {
                "can_read_tables": "data:read_tables" in (access_token.scopes or []),
                "can_read_table_data": "data:read_table_data" in (access_token.scopes or []),
            },
            "message": "权限信息获取成功"
        }
    except Exception as e:
        # 如果获取权限时出错，返回错误信息但不抛出异常
        return {
            "user_id": "error",
            "scopes": [],
            "permissions": {
                "can_read_tables": False,
                "can_read_table_data": False
            },
            "message": f"权限检查出错: {str(e)}"
        }


# 添加一个不需要权限的健康检查工具
@mcp.tool
async def health_check(ctx: Context) -> Dict[str, Any]:
    """
    健康检查
    无需任何权限
    """
    try:
        initialize_services()
        return {
            "status": "healthy",
            "database_connected": db_manager is not None,
            "message": "服务运行正常"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database_connected": False,
            "message": f"服务异常: {str(e)}"
        }


if __name__ == "__main__":
    # 从环境变量获取配置
    host = os.getenv('MCP_HOST', '127.0.0.1')
    port = int(os.getenv('MCP_PORT', 8000))

    print(f"Starting MCP Data Query Server...")
    print(f"Address: http://{host}:{port}")
    print(f"Available Tools:")
    print(f"   - health_check")
    print(f"   - get_user_permissions")
    print(f"   - get_database_tables")
    print(f"   - get_table_structure")
    print(f"   - execute_sql_query")
    print(f"   - generate_sql_from_question")
    print(f"   - analyze_query_result")
    mcp.run(transport="streamable-http", host=host, port=port)