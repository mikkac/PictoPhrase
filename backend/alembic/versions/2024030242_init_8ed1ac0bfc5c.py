"""init

Revision ID: 8ed1ac0bfc5c
Revises: 07c71f4389b6
Create Date: 2024-03-02 19:42:21.484736

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "8ed1ac0bfc5c"
down_revision = "07c71f4389b6"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(as_uuid=False), nullable=False),
        sa.Column("username", sa.String(length=254), nullable=False),
        sa.Column("hashed_password", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)
    op.drop_index("ix_user_model_email", table_name="user_model")
    op.drop_table("user_model")
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "user_model",
        sa.Column("id", sa.UUID(), autoincrement=False, nullable=False),
        sa.Column("email", sa.VARCHAR(length=254), autoincrement=False, nullable=False),
        sa.Column(
            "hashed_password",
            sa.VARCHAR(length=128),
            autoincrement=False,
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="user_model_pkey"),
    )
    op.create_index("ix_user_model_email", "user_model", ["email"], unique=True)
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_table("users")
    # ### end Alembic commands ###
