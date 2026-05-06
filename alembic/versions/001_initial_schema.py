"""
alembic/versions/001_initial_schema.py

Initial database schema for Q-BOM AI.
Run with: alembic upgrade head
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scans",
        sa.Column("id",            sa.String(),  primary_key=True),
        sa.Column("target",        sa.String(),  nullable=False),
        sa.Column("target_type",   sa.String(),  nullable=False, server_default="repo"),
        sa.Column("status",        sa.String(),  nullable=False, server_default="queued"),
        sa.Column("findings",      postgresql.JSONB(), nullable=True),
        sa.Column("cyclonedx_bom", postgresql.JSONB(), nullable=True),
        sa.Column("hndl_score",    sa.Float(),   nullable=True),
        sa.Column("risk_level",    sa.String(),  nullable=True),
        sa.Column("agent_trace",   postgresql.JSONB(), nullable=True),
        sa.Column("eval_scores",   postgresql.JSONB(), nullable=True),
        sa.Column("created_at",    sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at",    sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index("ix_scans_status",     "scans", ["status"])
    op.create_index("ix_scans_target",     "scans", ["target"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])

    op.create_table(
        "crypto_knowledge",
        sa.Column("id",           sa.String(), primary_key=True),
        sa.Column("algorithm",    sa.String(), nullable=False, index=True),
        sa.Column("content",      sa.Text(),   nullable=False),
        sa.Column("source",       sa.String(), nullable=False),
        sa.Column("embedding_id", sa.String(), nullable=True),
        sa.Column("created_at",   sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_crypto_knowledge_algorithm", "crypto_knowledge", ["algorithm"])

    # NOTE: scan_findings relational table is created in migration 002
    # with richer schema (snippet, source, platform columns)


def downgrade():
    op.drop_table("crypto_knowledge")
    op.drop_table("scans")
