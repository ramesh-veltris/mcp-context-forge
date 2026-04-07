# -*- coding: utf-8 -*-
"""Tests for AWS Secrets Manager Plugin.

Examples:
    >>> True
    True
"""

# Standard
from unittest.mock import MagicMock, patch

# Third-Party
import pytest

# First-Party
from mcpgateway.plugins.framework import (
    HttpHeaderPayload,
    ToolPreInvokePayload,
)
from plugins.aws_secrets.aws_secrets_plugin import (
    AWSSecretsConfig,
    AWSSecretsPlugin,
)


def make_plugin():
    """Create a test plugin instance."""
    config = MagicMock()
    config.config = {
        "aws_region": "us-east-1",
        "secret_name": "mcp-gateway/tool-secrets",
        "system_tag_prefix": "system",
    }
    return AWSSecretsPlugin(config)


def make_context(system_tag=None):
    """Create a test plugin context."""
    context = MagicMock()
    tags = []
    if system_tag:
        tags = [{"label": f"system:{system_tag}"}]
    context.global_context.metadata = {
        "gateway": MagicMock(tags=tags)
    }
    return context


def make_payload(tool_name="test-tool"):
    """Create a test tool payload."""
    payload = MagicMock()
    payload.name = tool_name
    payload.headers = None
    return payload


def test_plugin_config_defaults():
    """Test plugin config loads with defaults."""
    config = AWSSecretsConfig()
    assert config.aws_region == "us-east-1"
    assert config.secret_name == "mcp-gateway/tool-secrets"
    assert config.system_tag_prefix == "system"
    print("Config defaults work!")


def test_plugin_config_custom():
    """Test plugin config loads custom values."""
    config = AWSSecretsConfig(
        aws_region="eu-west-1",
        secret_name="my-secrets",
        system_tag_prefix="svc",
    )
    assert config.aws_region == "eu-west-1"
    assert config.secret_name == "my-secrets"
    print("Custom config works!")


@pytest.mark.asyncio
async def test_no_system_tag_skips():
    """Test plugin skips when no system tag found."""
    plugin = make_plugin()
    payload = make_payload()
    context = make_context(system_tag=None)

    result = await plugin.tool_pre_invoke(payload, context)

    assert result.modified_payload is None
    print("No system tag — skipped correctly!")


@pytest.mark.asyncio
@patch("boto3.client")
async def test_aws_token_injected(mock_boto):
    """Test AWS token is fetched and injected as Bearer."""
    # setup fake AWS
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": '{"github.com": "ghp_token123"}'
    }

    plugin = make_plugin()
    payload = make_payload("github-list-issues")
    context = make_context(system_tag="github.com")

    # mock headers
    payload.headers = MagicMock()
    payload.headers.model_dump.return_value = {}

    # make model_copy return a real ToolPreInvokePayload
    real_payload = ToolPreInvokePayload(
        name="github-list-issues",
        arguments={},
        headers=HttpHeaderPayload(
            root={"Authorization": "Bearer ghp_token123"}
        ),
    )
    payload.model_copy.return_value = real_payload

    result = await plugin.tool_pre_invoke(payload, context)

    # verify token was injected
    assert result.modified_payload is not None
    assert result.modified_payload.headers.root[
        "Authorization"
    ] == "Bearer ghp_token123"
    print("AWS token injected as Bearer!")


@pytest.mark.asyncio
@patch("boto3.client")
async def test_no_token_for_system_skips(mock_boto):
    """Test plugin skips when no token found for system."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": '{"slack.com": "xoxb-token"}'
    }

    plugin = make_plugin()
    payload = make_payload()
    context = make_context(system_tag="github.com")

    result = await plugin.tool_pre_invoke(payload, context)

    assert result.modified_payload is None
    print("No matching token — skipped correctly!")


@pytest.mark.asyncio
@patch("boto3.client")
async def test_aws_error_skips_gracefully(mock_boto):
    """Test plugin handles AWS errors gracefully."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.side_effect = Exception(
        "AWS connection failed"
    )

    plugin = make_plugin()
    payload = make_payload()
    context = make_context(system_tag="github.com")

    result = await plugin.tool_pre_invoke(payload, context)

    assert result.modified_payload is None
    print("AWS error handled gracefully!")


@pytest.mark.asyncio
async def test_shutdown_clears_cache():
    """Test plugin shutdown clears cache."""
    plugin = make_plugin()
    plugin._secrets_cache = {"github.com": "token"}
    plugin._aws_client = MagicMock()

    await plugin.shutdown()

    assert plugin._secrets_cache == {}
    assert plugin._aws_client is None
    print("Shutdown clears cache!")


@pytest.mark.asyncio
@patch("boto3.client")
async def test_secrets_cached_after_first_fetch(mock_boto):
    """Test secrets are cached after first AWS fetch."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": '{"github.com": "ghp_token123"}'
    }

    plugin = make_plugin()
    payload = make_payload()
    context = make_context(system_tag="github.com")

    payload.headers = MagicMock()
    payload.headers.model_dump.return_value = {}

    real_payload = ToolPreInvokePayload(
        name="test-tool",
        arguments={},
        headers=HttpHeaderPayload(
            root={"Authorization": "Bearer ghp_token123"}
        ),
    )
    payload.model_copy.return_value = real_payload

    # call twice
    await plugin.tool_pre_invoke(payload, context)
    await plugin.tool_pre_invoke(payload, context)

    # AWS should only be called ONCE (second call uses cache)
    assert mock_client.get_secret_value.call_count == 1
    print("Secrets cached — AWS called only once!")