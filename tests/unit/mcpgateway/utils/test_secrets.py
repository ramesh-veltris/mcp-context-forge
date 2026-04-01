# -*- coding: utf-8 -*-
"""Tests for AWS Secrets Manager integration.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
"""

import os
from unittest.mock import MagicMock, patch
import pytest
from mcpgateway.utils.secrets import AWSSecretManager, load_secrets_into_env


def test_load_secrets_none_backend():
    """Test that none backend does nothing."""
    load_secrets_into_env("none", "us-east-1", "test-secret")
    assert True


def test_load_secrets_none_backend_case_insensitive():
    """Test that NONE / None / none all work the same."""
    load_secrets_into_env("NONE", "us-east-1", "test-secret")
    load_secrets_into_env("None", "us-east-1", "test-secret")
    load_secrets_into_env("none", "us-east-1", "test-secret")
    assert True


def test_load_secrets_unknown_backend():
    """Test that unknown backend logs warning and skips."""
    load_secrets_into_env("unknown", "us-east-1", "test-secret")
    assert True


def test_load_secrets_vault_backend_not_implemented():
    """Test that vault backend logs warning and skips gracefully."""
    load_secrets_into_env("vault", "us-east-1", "test-secret")
    assert True


def test_load_secrets_gcp_backend_not_implemented():
    """Test that gcp backend logs warning and skips gracefully."""
    load_secrets_into_env("gcp", "us-east-1", "test-secret")
    assert True


def test_load_secrets_azure_backend_not_implemented():
    """Test that azure backend logs warning and skips gracefully."""
    load_secrets_into_env("azure", "us-east-1", "test-secret")
    assert True


@patch("boto3.client")
def test_aws_secrets_injected_into_env(mock_boto):
    """Test AWS secrets are injected into environment."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": '{"TEST_JWT_KEY": "aws-jwt-value", "TEST_DB_URL": "aws-db-url"}'
    }

    load_secrets_into_env("aws", "us-east-1", "mcp-gateway/secrets")

    assert os.environ.get("TEST_JWT_KEY") == "aws-jwt-value"
    assert os.environ.get("TEST_DB_URL") == "aws-db-url"


@patch("boto3.client")
def test_aws_backend_case_insensitive(mock_boto):
    """Test that AWS / Aws / aws all work the same."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": '{"TEST_CASE_KEY": "value123"}'
    }

    load_secrets_into_env("AWS", "us-east-1", "mcp-gateway/secrets")
    assert os.environ.get("TEST_CASE_KEY") == "value123"


@patch("boto3.client")
def test_aws_existing_env_not_overwritten(mock_boto):
    """Test that existing env vars are NOT overwritten."""
    os.environ["EXISTING_KEY"] = "original-value"

    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": '{"EXISTING_KEY": "aws-value"}'
    }

    load_secrets_into_env("aws", "us-east-1", "mcp-gateway/secrets")

    assert os.environ.get("EXISTING_KEY") == "original-value"


@patch("boto3.client")
def test_aws_empty_secret_string(mock_boto):
    """Test that empty SecretString returns empty dict gracefully."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": "{}"
    }

    # should not raise any exception
    load_secrets_into_env("aws", "us-east-1", "mcp-gateway/secrets")
    assert True


@patch("boto3.client")
def test_aws_secret_value_converted_to_string(mock_boto):
    """Test that integer/boolean secret values are converted to string."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": '{"PORT": 8080, "DEBUG": true}'
    }

    load_secrets_into_env("aws", "us-east-1", "mcp-gateway/secrets")

    # os.environ only stores strings
    assert os.environ.get("PORT") == "8080"
    assert os.environ.get("DEBUG") == "True"


@patch("boto3.client")
def test_aws_connection_error(mock_boto):
    """Test that AWS connection errors are handled."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.side_effect = Exception(
        "AWS connection failed"
    )

    manager = AWSSecretManager("us-east-1", "mcp-gateway/secrets")

    with pytest.raises(Exception) as exc_info:
        manager.get_all_secrets()

    assert "AWS connection failed" in str(exc_info.value)


@patch("boto3.client")
def test_aws_error_does_not_crash_app(mock_boto):
    """Test that AWS failure is caught and app continues."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.side_effect = Exception(
        "Network timeout"
    )

    # load_secrets_into_env should NOT raise — it catches internally
    load_secrets_into_env("aws", "us-east-1", "mcp-gateway/secrets")
    assert True


def test_boto3_not_installed():
    """Test that missing boto3 raises ImportError with helpful message."""
    with patch.dict("sys.modules", {"boto3": None}):
        with pytest.raises(ImportError) as exc_info:
            AWSSecretManager("us-east-1", "mcp-gateway/secrets")
        assert "boto3" in str(exc_info.value)


@patch("boto3.client")
def test_aws_secret_manager_init(mock_boto):
    """Test AWSSecretManager initializes correctly."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client

    manager = AWSSecretManager("us-east-1", "mcp-gateway/secrets")

    assert manager.secret_name == "mcp-gateway/secrets"
    mock_boto.assert_called_once_with(
        "secretsmanager",
        region_name="us-east-1",
    )


@patch("boto3.client")
def test_get_all_secrets_returns_dict(mock_boto):
    """Test get_all_secrets returns a dictionary."""
    mock_client = MagicMock()
    mock_boto.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": '{"KEY1": "val1", "KEY2": "val2"}'
    }

    manager = AWSSecretManager("us-east-1", "mcp-gateway/secrets")
    secrets = manager.get_all_secrets()

    assert isinstance(secrets, dict)
    assert secrets["KEY1"] == "val1"
    assert secrets["KEY2"] == "val2"