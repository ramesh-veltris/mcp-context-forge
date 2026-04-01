# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/utils/secrets.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

AWS Secrets Manager integration for ContextForge.

Fetches secrets from AWS Secrets Manager and injects
them as environment variables before app startup.

Environment variables:
    SECRETS_PROVIDER: Secret backend to use (none, aws, vault, gcp, azure)
    AWS_SECRETS_REGION: AWS region (default: us-east-1)
    AWS_SECRETS_NAME: Secret name in AWS Secrets Manager
    AWS_ACCESS_KEY_ID: AWS access key ID (optional)
    AWS_SECRET_ACCESS_KEY: AWS secret access key (optional)

Examples:
    >>> from mcpgateway.utils.secrets import load_secrets_into_env
    >>> load_secrets_into_env("none", "us-east-1", "test")
"""

import json
import logging
import os

logger = logging.getLogger(__name__)


class AWSSecretManager:
    """Connects to AWS Secrets Manager and fetches secrets.

    Examples:
        >>> m = AWSSecretManager.__new__(AWSSecretManager)
        >>> isinstance(m, AWSSecretManager)
        True
    """

    def __init__(self, region: str, secret_name: str):
        """Initialize AWS Secrets Manager client.
        Args:
            region: AWS region (e.g. us-east-1)
            secret_name: Name of the secret in AWS Secrets Manager
        """
        try:
            import boto3
            self.secret_name = secret_name
            self.client = boto3.client(
                "secretsmanager",
                region_name=region,
            )
            logger.info(
                "AWS Secrets Manager client created: "
                "region=%s secret=%s",
                region,
                secret_name,
            )
        except ImportError as e:
            logger.error(
                "boto3 not installed. Run: pip install boto3"
            )
            raise ImportError(
                "boto3 is required for AWS Secrets Manager. "
                "Install it with: pip install boto3"
            ) from e

    def get_all_secrets(self) -> dict:
        """Fetch all secrets from AWS Secrets Manager.

        Returns:
            Dictionary of secret key-value pairs.

        """
        try:
            response = self.client.get_secret_value(
                SecretId=self.secret_name
            )
            secret_string = response.get("SecretString", "{}")
            secrets = json.loads(secret_string)
            logger.info(
                "Fetched %d secrets from AWS Secrets Manager",
                len(secrets),
            )
            return secrets
        except Exception as e:
            logger.error(
                "Failed to fetch secrets from AWS: %s", str(e)
            )
            raise


def load_secrets_into_env(
    backend: str,
    region: str,
    secret_name: str,
) -> None:
    """Load secrets from backend into environment variables.

    This function should be called BEFORE the Settings class
    loads, so that secrets are available as env vars.

    Args:
        backend: Secret backend type - "none", "aws", "vault", "gcp", "azure"
        region: AWS region (only used for aws backend)
        secret_name: Secret name (only used for aws backend)

    Examples:
        >>> load_secrets_into_env("none", "us-east-1", "test")
    """

    if backend.lower() == "none":
        logger.debug(
            "SECRETS_PROVIDER=none, using environment variables"
        )
        return

    if backend.lower() == "aws":
        logger.info(
            "SECRETS_PROVIDER=aws, loading from AWS Secrets Manager..."
        )
        try:
            manager = AWSSecretManager(
                region=region,
                secret_name=secret_name,
            )
            secrets = manager.get_all_secrets()

            injected = 0
            skipped = 0
            for key, value in secrets.items():
                if key not in os.environ:
                    os.environ[key] = str(value)
                    injected += 1
                    logger.debug("Injected secret: %s", key)
                else:
                    skipped += 1
                    logger.debug(
                        "Skipped %s (already in environment)",
                        key,
                    )

            logger.info(
                "AWS secrets loaded: %d injected, %d skipped",
                injected,
                skipped,
            )
        except Exception as e:
            logger.error(
                "Failed to load secrets from AWS: %s "
                "— continuing with environment variables",
                str(e),
            )
        return

    if backend.lower() == "vault":
        logger.warning(
            "SECRETS_PROVIDER=vault: "
            "HashiCorp Vault backend is not yet implemented. "
            "Falling back to environment variables."
        )
        return

    if backend.lower() == "gcp":
        logger.warning(
            "SECRETS_PROVIDER=gcp: "
            "GCP Secret Manager backend is not yet implemented. "
            "Falling back to environment variables."
        )
        return

    if backend.lower() == "azure":
        logger.warning(
            "SECRETS_PROVIDER=azure: "
            "Azure Key Vault backend is not yet implemented. "
            "Falling back to environment variables."
        )
        return

    logger.warning(
        "Unknown SECRETS_PROVIDER=%s — "
        "valid options are: none, aws, vault, gcp, azure. "
        "Skipping secret manager.",
        backend,
    )