"""minimize existing event ips and user agents

Revision ID: 0003_tracking_minimize
Revises: 0002_audit_chain_head
Create Date: 2026-08-03

HIGH-17 / WS-9: rewrite already-persisted tracking events so the client_ip
is a /24 (IPv4) or /64 (IPv6) prefix and user agents are truncated, matching
the new write path in the tracking API.
"""

from __future__ import annotations

from alembic import op
from kp_database.privacy import minimize_ip, minimize_user_agent
from sqlalchemy import text

revision = "0003_tracking_minimize"
down_revision = "0002_audit_chain_head"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(text("SELECT event_id, client_ip, user_agent FROM events")).mappings().all()
    for row in rows:
        new_ip = minimize_ip(row["client_ip"])
        new_ua = minimize_user_agent(row["user_agent"])
        if new_ip != row["client_ip"] or new_ua != row["user_agent"]:
            bind.execute(
                text("UPDATE events SET client_ip = :ip, user_agent = :ua WHERE event_id = :id"),
                {"ip": new_ip, "ua": new_ua, "id": row["event_id"]},
            )


def downgrade() -> None:
    # The raw IPs/agents are gone; nothing to restore.
    pass
