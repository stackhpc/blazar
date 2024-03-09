# Copyright 2024 OpenStack Foundation.
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

"""Make affinity nullable

Revision ID: c198b1b6fb9b
Revises: 02e2f2186d98
Create Date: 2024-03-09 15:47:45.160610

"""

# revision identifiers, used by Alembic.
revision = 'c198b1b6fb9b'
down_revision = '02e2f2186d98'

from alembic import op
from sqlalchemy.dialects import mysql

def upgrade():
    op.alter_column('instance_reservations', 'affinity',
                    existing_type=mysql.TINYINT(display_width=1),
                    nullable=True)
