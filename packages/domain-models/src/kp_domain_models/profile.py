"""Deployment profile shared by the operator API and the workers.

Extracted from ``kp_operator_api.config`` (R-03) so the worker deployable can
read its profile without depending on the control-plane app package.
"""

from __future__ import annotations

from enum import StrEnum


class KPProfile(StrEnum):
    """Deployment profile that expands into concrete settings.

    - local-dev: disposable local stack (dev-auth, relaxed approvals, .env config)
    - local-hardened: production-like local stack (OIDC, strict approvals, env_file)
    - azure: managed Azure Container Apps deployment (managed config, OIDC, Key Vault)
    """

    LOCAL_DEV = "local-dev"
    LOCAL_HARDENED = "local-hardened"
    AZURE = "azure"
