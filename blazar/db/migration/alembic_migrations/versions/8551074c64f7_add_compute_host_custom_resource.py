# Copyright 2022 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""add compute host custom resource

Revision ID: 8551074c64f7
Revises: 02e2f2186d98
Create Date: 2022-03-21 15:06:04.917411

"""

# revision identifiers, used by Alembic.
revision = '8551074c64f7'
down_revision = '02e2f2186d98'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


def upgrade():
    op.create_table('computehost_custom_resources',
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('computehost_id',
                              sa.String(length=36), nullable=True),
                    sa.Column('resource_class',
                              sa.String(length=255), nullable=False),
                    sa.Column('pci_alias',
                              sa.String(length=255), nullable=True),
                    sa.Column('units', sa.Integer(), nullable=False),
                    sa.ForeignKeyConstraint(['computehost_id'],
                                            ['computehosts.id'], ),
                    sa.PrimaryKeyConstraint('id'))
    op.alter_column('instance_reservations', 'affinity',
                    existing_type=mysql.TINYINT(display_width=1),
                    nullable=False)

    op.add_column('instance_reservations',
                  sa.Column('custom_resources',
                            sa.Text().with_variant(mysql.MEDIUMTEXT(),
                                                   'mysql'),
                            nullable=True))


def downgrade():
    op.alter_column('instance_reservations', 'affinity',
                    existing_type=mysql.TINYINT(display_width=1),
                    nullable=True)
    op.drop_table('computehost_custom_resources')

    op.drop_column('instance_reservations', 'custom_resources')
