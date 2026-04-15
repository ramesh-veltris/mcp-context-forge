# -*- coding: utf-8 -*-
"""Location: ./plugins/gcp_secrets/gcp_secrets_plugin.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ramesh Krishna Vanam

GCP Secret Manager Plugin.

Fetches API tokens from GCP Secret Manager and injects
them as Bearer tokens before tool invocation.

Hook: tool_pre_invoke

Example:
    Gateway tag: system:github.com
    GCP Secret:  {"github.com": "ghp_token123"}
    Result:      Authorization: Bearer ghp_token123
"""

import json
import logging

from pydantic import BaseModel

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


class GCPSecretsConfig(BaseModel):
    """Configuration for GCP Secret Manager plugin.

    Attributes:
        project_id: GCP project ID where the secret lives.
        secret_name: Name of the secret in GCP Secret Manager.
        secret_version: Version of the secret to fetch (default: latest).
        system_tag_prefix: Prefix for system tags on gateway.
    """

    project_id: str = ""
    secret_name: str = "mcp-gateway-tool-secrets"
    secret_version: str = "latest"
    system_tag_prefix: str = "system"


class GCPSecretsPlugin(Plugin):
    """GCP Secret Manager plugin.

    Fetches API tokens from GCP Secret Manager and injects
    them as Bearer tokens before tool invocation.
    """

    def __init__(self, config: PluginConfig):
        super().__init__(config)
        try:
            self._sconfig = GCPSecretsConfig.model_validate(
                self._config.config or {}
            )
        except Exception:
            self._sconfig = GCPSecretsConfig()

        self._gcp_client = None
        self._secrets_cache = {}
        logger.info(
            "GCP Secrets plugin initialized: project=%s secret=%s version=%s",
            self._sconfig.project_id,
            self._sconfig.secret_name,
            self._sconfig.secret_version,
        )

    def _get_gcp_client(self):
        """Get or create GCP Secret Manager client."""
        if self._gcp_client is None:
            from google.cloud import secretmanager
            self._gcp_client = secretmanager.SecretManagerServiceClient()
            logger.debug("GCP Secret Manager client created")
        return self._gcp_client

    def _fetch_secrets(self) -> dict:
        """Fetch secrets from GCP Secret Manager."""
        if self._secrets_cache:
            logger.debug("Using cached secrets")
            return self._secrets_cache

        if not self._sconfig.project_id:
            logger.error("GCP project_id is not configured")
            return {}

        try:
            client = self._get_gcp_client()
            secret_version_name = (
                f"projects/{self._sconfig.project_id}"
                f"/secrets/{self._sconfig.secret_name}"
                f"/versions/{self._sconfig.secret_version}"
            )
            response = client.access_secret_version(
                request={"name": secret_version_name}
            )
            secret_string = response.payload.data.decode("utf-8")
            self._secrets_cache = json.loads(secret_string)
            logger.info(
                "Fetched %d secrets from GCP: %s",
                len(self._secrets_cache),
                self._sconfig.secret_name,
            )
            return self._secrets_cache
        except Exception as e:
            logger.error("Failed to fetch secrets from GCP: %s", str(e))
            return {}

    async def tool_pre_invoke(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
    ) -> ToolPreInvokeResult:
        """Fetch GCP secret and inject as Bearer token."""
        logger.debug("GCP Secrets plugin: tool=%s", payload.name)

        gateway_metadata = context.global_context.metadata.get("gateway")
        gateway_tags = get_attr(gateway_metadata, "tags", [])

        system_key = None
        system_prefix = self._sconfig.system_tag_prefix + ":"

        for tag in gateway_tags or []:
            if isinstance(tag, dict):
                tag_value = str(tag.get("label", ""))
            else:
                tag_value = str(getattr(tag, "label", tag))

            if tag_value.startswith(system_prefix):
                system_key = tag_value.split(system_prefix)[1]
                logger.debug("Found system tag: %s", system_key)
                break

        if not system_key:
            logger.debug("No system tag found — skipping GCP lookup")
            return ToolPreInvokeResult()

        secrets = self._fetch_secrets()

        if not secrets:
            logger.warning(
                "No secrets found in GCP: %s",
                self._sconfig.secret_name,
            )
            return ToolPreInvokeResult()

        token = secrets.get(system_key)
        if not token:
            logger.warning("No token for system: %s", system_key)
            return ToolPreInvokeResult()

        headers = payload.headers.model_dump() if payload.headers else {}
        headers["Authorization"] = f"Bearer {token}"
        logger.info("Injected GCP token for: %s", system_key)

        payload = payload.model_copy(
            update={"headers": HttpHeaderPayload(root=headers)}
        )
        return ToolPreInvokeResult(modified_payload=payload)

    async def shutdown(self) -> None:
        """Shutdown plugin and clear cache."""
        self._gcp_client = None
        self._secrets_cache = {}
        logger.info("GCP Secrets plugin shutdown")
        return None