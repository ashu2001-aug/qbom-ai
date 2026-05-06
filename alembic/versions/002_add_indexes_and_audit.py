"""
alembic/versions/002_add_indexes_and_audit.py

Migration 002:
  - Add composite index on scans(status, created_at) for polling queries
  - Add scan_findings table with FK to scans (extracted from JSON findings for queryability)
  - Add audit_log table for API key usage tracking
  - Add GIN index on scans.findings JSONB for fast algorithm searches

Run: alembic upgrade head
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    # ── Composite index for the polling query pattern ──────────────────────────
    # GET /api/scans?status=scanning hits this heavily
    op.create_index(
        "ix_scans_status_created_at",
        "scans",
        ["status", sa.text("created_at DESC")],
        postgresql_ops={"created_at": "DESC"},
    )

    # ── GIN index for JSONB findings search ────────────────────────────────────
    # Allows: SELECT * FROM scans WHERE findings @> '[{"algorithm": "RSA-2048"}]'
    op.execute(
        "CREATE INDEX ix_scans_findings_gin ON scans USING gin(findings jsonb_path_ops)"
    )

    # ── scan_findings: relational extraction of key finding fields ─────────────
    # Populated by the reporter agent (via MCP save_finding tool)
    # Enables: SELECT * FROM scan_findings WHERE algorithm = 'RSA-2048' ORDER BY hndl_score DESC
    op.create_table(
        "scan_findings",
        sa.Column("id",               sa.String(),  primary_key=True),
        sa.Column("scan_id",          sa.String(),  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("algorithm",        sa.String(),  nullable=False),
        sa.Column("location",         sa.String(),  nullable=True),
        sa.Column("snippet",          sa.Text(),    nullable=True),
        sa.Column("hndl_score",       sa.Float(),   nullable=True),
        sa.Column("quantum_vulnerable", sa.Boolean(), server_default="true"),
        sa.Column("is_shadow_crypto", sa.Boolean(), server_default="false"),
        sa.Column("migration_path",   sa.String(),  nullable=True),
        sa.Column("source",           sa.String(),  nullable=True),   # regex_scan|codeql|tls_scan|js_scan
        sa.Column("platform",         sa.String(),  nullable=True),   # openssl|browser|network|pki
        sa.Column("created_at",       sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_sf_scan_id",   "scan_findings", ["scan_id"])
    op.create_index("ix_sf_algorithm", "scan_findings", ["algorithm"])
    op.create_index("ix_sf_hndl",      "scan_findings", ["hndl_score"])
    op.create_index("ix_sf_quantum",   "scan_findings", ["quantum_vulnerable"])

    # ── audit_log: tracks every API call for billing + security auditing ───────
    op.create_table(
        "audit_log",
        sa.Column("id",           sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("api_key_hash", sa.String(),     nullable=False),
        sa.Column("tier",         sa.String(),     nullable=True),     # free|pro
        sa.Column("method",       sa.String(10),   nullable=False),
        sa.Column("path",         sa.String(255),  nullable=False),
        sa.Column("status_code",  sa.Integer(),    nullable=True),
        sa.Column("duration_ms",  sa.Float(),      nullable=True),
        sa.Column("ip_address",   sa.String(50),   nullable=True),
        sa.Column("scan_id",      sa.String(),     nullable=True),
        sa.Column("created_at",   sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_api_key", "audit_log", ["api_key_hash"])
    op.create_index("ix_audit_created", "audit_log", ["created_at"])

    # ── Add eval_scores column to existing scans table ─────────────────────────
    # (was in the model but missing from migration 001)
    op.add_column(
        "scans",
        sa.Column("eval_scores", postgresql.JSONB(), nullable=True)
    )

    # ── Add data_sensitivity column to scans ───────────────────────────────────
    op.add_column(
        "scans",
        sa.Column("data_sensitivity", sa.String(), server_default="medium", nullable=True)
    )


def downgrade():
    op.drop_column("scans", "data_sensitivity")
    op.drop_column("scans", "eval_scores")
    op.drop_table("audit_log")
    op.drop_table("scan_findings")
    op.execute("DROP INDEX IF EXISTS ix_scans_findings_gin")
    op.drop_index("ix_scans_status_created_at", "scans")
