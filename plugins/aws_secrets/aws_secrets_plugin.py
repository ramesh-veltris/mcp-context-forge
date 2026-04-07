# -*- coding: utf-8 -*-
"""Location: ./plugins/aws_secrets/aws_secrets_plugin.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ramesh Krishna Vanam

AWS Secrets Manager Plugin.

Fetches API tokens from AWS Secrets Manager and injects
them as Bearer tokens before tool invocation.

Unlike the Vault plugin (which reads tokens from request headers),
this plugin fetches tokens directly from AWS Secrets Manager,
so the client never needs to send or know the token.

Hook: tool_pre_invoke

Example:
    Gateway tag: system:github.com
    AWS Secret:  {"github.com": "ghp_token123"}
    Result:      Authorization: Bearer ghp_token123
"""

# Standard
import json
import logging

# Third-Party
from pydantic import BaseModel

# First-Party
from mcpgateway.plugins.framework import (
    get_attr,
    HttpHeaderPayload,
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

logger = logging.getLogger(__name__)


class AWSSecretsConfig(BaseModel):
    """Configuration for AWS Secrets Manager plugin.

    Attributes:
        aws_region: AWS region for Secrets Manager.
        secret_name: Name of the secret in AWS.
        system_tag_prefix: Prefix for system tags on gateway.
    """

    aws_region: str = "us-east-1"
    secret_name: str = "mcp-gateway/tool-secrets"
    system_tag_prefix: str = "system"


class AWSSecretsPlugin(Plugin):
    """AWS Secrets Manager plugin.

    Fetches API tokens from AWS Secrets Manager and injects
    them as Bearer tokens before tool invocation.

    This is more secure than the Vault plugin because:
    - Token never travels in the request
    - Client does not need to know the token
    - Token is stored securely in AWS
    """

    def __init__(self, config: PluginConfig):
        """Initialize the AWS Secrets plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        try:
            self._sconfig = AWSSecretsConfig.model_validate(
                self._config.config or {}
            )
        except Exception:
            self._sconfig = AWSSecretsConfig()

        # AWS client and cache
        self._aws_client = None
        self._secrets_cache = {}
        logger.info(
            "AWS Secrets plugin initialized: "
            "region=%s secret=%s",
            self._sconfig.aws_region,
            self._sconfig.secret_name,
        )

    def _get_aws_client(self):
        """Get or create AWS Secrets Manager client.

        Returns:
            boto3 secretsmanager client
        """
        if self._aws_client is None:
            import boto3  # pylint: disable=import-outside-toplevel
            self._aws_client = boto3.client(
                "secretsmanager",
                region_name=self._sconfig.aws_region,
            )
            logger.debug(
                "AWS Secrets Manager client created"
            )
        return self._aws_client

    def _fetch_secrets(self) -> dict:
        """Fetch secrets from AWS Secrets Manager.

        Returns:
            Dictionary of system → token pairs.
        """
        # return from cache if available
        if self._secrets_cache:
            logger.debug("Using cached secrets")
            return self._secrets_cache

        try:
            client = self._get_aws_client()
            response = client.get_secret_value(
                SecretId=self._sconfig.secret_name
            )
            secret_string = response.get(
                "SecretString", "{}"
            )
            self._secrets_cache = json.loads(secret_string)
            logger.info(
                "Fetched %d secrets from AWS: %s",
                len(self._secrets_cache),
                self._sconfig.secret_name,
            )
            return self._secrets_cache
        except Exception as e:
            logger.error(
                "Failed to fetch secrets from AWS: %s",
                str(e),
            )
            return {}

    async def tool_pre_invoke(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
    ) -> ToolPreInvokeResult:
        """Fetch AWS secret and inject as Bearer token.

        Args:
            payload: Tool payload containing arguments.
            context: Plugin execution context.

        Returns:
            Result with modified headers containing Bearer token.
        """
        logger.debug(
            "AWS Secrets plugin: tool=%s",
            payload.name,
        )

        # get gateway tags
        gateway_metadata = context.global_context.metadata.get(
            "gateway"
        )
        gateway_tags = get_attr(gateway_metadata, "tags", [])

        # find system tag e.g. system:github.com
        system_key = None
        system_prefix = self._sconfig.system_tag_prefix + ":"

        for tag in gateway_tags or []:
            if isinstance(tag, dict):
                tag_value = str(tag.get("label", ""))
            else:
                tag_value = str(getattr(tag, "label", tag))

            if tag_value.startswith(system_prefix):
                system_key = tag_value.split(system_prefix)[1]
                logger.debug(
                    "Found system tag: %s", system_key
                )
                break

        if not system_key:
            logger.debug(
                "No system tag found — skipping AWS lookup"
            )
            return ToolPreInvokeResult()

        # fetch secrets from AWS
        secrets = self._fetch_secrets()

        if not secrets:
            logger.warning(
                "No secrets found in AWS: %s",
                self._sconfig.secret_name,
            )
            return ToolPreInvokeResult()

        # find token for this system
        token = secrets.get(system_key)
        if not token:
            logger.warning(
                "No token for system: %s", system_key
            )
            return ToolPreInvokeResult()

        # inject token as Bearer header
        headers = (
            payload.headers.model_dump()
            if payload.headers
            else {}
        )
        headers["Authorization"] = f"Bearer {token}"
        logger.info(
            "Injected AWS token for: %s", system_key
        )

        payload = payload.model_copy(
            update={
                "headers": HttpHeaderPayload(root=headers)
            }
        )
        return ToolPreInvokeResult(modified_payload=payload)

    async def shutdown(self) -> None:
        """Shutdown plugin and clear cache."""
        self._aws_client = None
        self._secrets_cache = {}
        logger.info("AWS Secrets plugin shutdown")
        return None