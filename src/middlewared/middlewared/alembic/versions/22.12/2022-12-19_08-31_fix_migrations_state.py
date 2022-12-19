"""Fix migrations state

Revision ID: 136adf794fed
Revises: fa4097ef2236
Create Date: 2022-12-19 08:31:55.475116+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '136adf794fed'
down_revision = 'fa4097ef2236'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('services_cifs', schema=None) as batch_op:
        batch_op.drop_column('cifs_srv_netbiosname_b')

    with op.batch_alter_table('storage_task', schema=None) as batch_op:
        batch_op.drop_column('task_state')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('storage_task', schema=None) as batch_op:
        batch_op.add_column(sa.Column('task_state', sa.TEXT(), server_default=sa.text("'{}'"), nullable=False))

    with op.batch_alter_table('services_cifs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('cifs_srv_netbiosname_b', sa.VARCHAR(length=120), nullable=True))

    # ### end Alembic commands ###
