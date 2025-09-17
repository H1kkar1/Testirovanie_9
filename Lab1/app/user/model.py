from datetime import date
from sqlalchemy import Column, String, Table, Uuid, Date
from app.db import db_helper


user = Table(
    "user",
    db_helper.metadata_obj,
    Column("id", Uuid, primary_key=True, nullable=False, unique=True),
    Column("username", String(128), nullable=False, unique=True),
    Column("password", String(64), nullable=False),
    Column("email", String(128), nullable=False),
    Column("date", Date, default=date.today()),
    Column("token", String(), nullable=True),

)


class User:
    pass


db_helper.mapper_registry.map_imperatively(User, user)
