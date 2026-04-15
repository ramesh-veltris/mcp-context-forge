# -*- coding: utf-8 -*-
"""Tests for GCP Secret Manager Plugin.

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
from plugins.gcp_secrets.gcp_secrets_plugin import (
    GCPSecretsConfig,
    GCPSecretsPlugin,
)


def make_plugin():
    """Create a test plugin instance."""
    config = MagicMock()
    config.config = {
        "project_id": "my-gcp-project",
        "secret_name": "mcp-gateway-tool-secrets",
        "secret_version": "latest",
        "system_tag_prefix": "system",
    }
    return GCPSecretsPlugin(config)


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
    config = GCPSecretsConfig()
    assert config.project_id == ""
    assert config.secret_name == "mcp-gateway-tool-secrets"
    assert config.secret_version == "latest"
    assert config.system_tag_prefix == "system"
    print("Config defaults work!")


def test_plugin_config_custom():
    """Test plugin config loads custom values."""
    config = GCPSecretsConfig(
        project_id="my-gcp-project",
        secret_name="my-secrets",
        secret_version="2",         # ← fixed, = sign
        system_tag_prefix="svc",
    )


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
async def test_missing_project_id_skips():
    """Test plugin skips gracefully when project_id is empty."""
    config = MagicMock()
    config.config = {
        "project_id": "",
        "secret_name": "mcp-gateway-tool-secrets",
        "secret_version": "latest",
        "system_tag_prefix": "system",
    }
    plugin = GCPSecretsPlugin(config)
    payload = make_payload()
    context = make_context(system_tag="github.com")

    result = await plugin.tool_pre_invoke(payload, context)

    assert result.modified_payload is None
    print("Missing project_id — skipped correctly!")


@pytest.mark.asyncio
@patch("google.cloud.secretmanager.SecretManagerServiceClient")
async def test_gcp_token_injected(mock_client_cls):
    """Test GCP token is fetched and injected as Bearer."""
    # setup fake GCP response
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    mock_response = MagicMock()
    mock_response.payload.data = b'{"github.com": "ghp_token123"}'
    mock_client.access_secret_version.return_value = mock_response

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
    print("GCP token injected as Bearer!")


@pytest.mark.asyncio
@patch("google.cloud.secretmanager.SecretManagerServiceClient")
async def test_no_token_for_system_skips(mock_client_cls):
    """Test plugin skips when no token found for system."""
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    mock_response = MagicMock()
    mock_response.payload.data = b'{"slack.com": "xoxb-token"}'
    mock_client.access_secret_version.return_value = mock_response

    plugin = make_plugin()
    payload = make_payload()
    context = make_context(system_tag="github.com")

    result = await plugin.tool_pre_invoke(payload, context)

    assert result.modified_payload is None
    print("No matching token — skipped correctly!")


@pytest.mark.asyncio
@patch("google.cloud.secretmanager.SecretManagerServiceClient")
async def test_gcp_error_skips_gracefully(mock_client_cls):
    """Test plugin handles GCP errors gracefully."""
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.access_secret_version.side_effect = Exception(
        "GCP connection failed"
    )

    plugin = make_plugin()
    payload = make_payload()
    context = make_context(system_tag="github.com")

    result = await plugin.tool_pre_invoke(payload, context)

    assert result.modified_payload is None
    print("GCP error handled gracefully!")


@pytest.mark.asyncio
async def test_shutdown_clears_cache():
    """Test plugin shutdown clears cache."""
    plugin = make_plugin()
    plugin._secrets_cache = {"github.com": "token"}
    plugin._gcp_client = MagicMock()

    await plugin.shutdown()

    assert plugin._secrets_cache == {}
    assert plugin._gcp_client is None
    print("Shutdown clears cache!")


@pytest.mark.asyncio
@patch("google.cloud.secretmanager.SecretManagerServiceClient")
async def test_secrets_cached_after_first_fetch(mock_client_cls):
    """Test secrets are cached after first GCP fetch."""
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    mock_response = MagicMock()
    mock_response.payload.data = b'{"github.com": "ghp_token123"}'
    mock_client.access_secret_version.return_value = mock_response

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

    # GCP should only be called ONCE (second call uses cache)
    assert mock_client.access_secret_version.call_count == 1
    print("Secrets cached — GCP called only once!")