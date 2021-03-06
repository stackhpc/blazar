# Copyright 2019 OpenStack Foundation.
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

"""add_floatingip_reservation

Revision ID: f4084140f608
Revises: e069c014356d
Create Date: 2019-02-25 06:25:22.038890

"""

# revision identifiers, used by Alembic.
revision = 'f4084140f608'
down_revision = 'e069c014356d'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('floatingip_allocations',
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('floatingip_id',
                              sa.String(length=36), nullable=True),
                    sa.Column('reservation_id',
                              sa.String(length=36), nullable=True),

                    sa.ForeignKeyConstraint(['floatingip_id'],
                                            ['floatingips.id'], ),
                    sa.ForeignKeyConstraint(['reservation_id'],
                                            ['reservations.id'], ),
                    sa.PrimaryKeyConstraint('id'))

    op.create_table('floatingip_reservations',
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('reservation_id',
                              sa.String(length=36), nullable=True),
                    sa.Column('network_id',
                              sa.String(length=255), nullable=False),
                    sa.Column('amount', sa.Integer(), nullable=False),

                    sa.ForeignKeyConstraint(['reservation_id'],
                                            ['reservations.id'], ),
                    sa.PrimaryKeyConstraint('id'))

    op.create_table('required_floatingips',
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('address',
                              sa.String(length=255), nullable=False),
                    sa.Column('floatingip_reservation_id',
                              sa.String(length=36), nullable=True),
                    sa.ForeignKeyConstraint(['floatingip_reservation_id'],
                                            ['floatingip_reservations.id'], ),
                    sa.PrimaryKeyConstraint('id'))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('required_floatingips')
    op.drop_table('floatingip_reservations')
    op.drop_table('floatingip_allocations')
    # ### end Alembic commands ###
