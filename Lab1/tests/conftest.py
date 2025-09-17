import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from app.config import settings
from app.db import db_helper
import uuid
from datetime import datetime, timedelta
import jwt
import sys
import os
from pathlib import Path
root_dir = Path(__file__).parent
sys.path.append(str(root_dir))


@pytest.fixture(scope="function")
async def async_session():
    # Получаем генератор сессии
    session_generator = db_helper.get_session()

    # Получаем сессию из генератора
    session = await session_generator.__anext__()

    try:
        yield session
    finally:
        # Закрываем генератор
        await session_generator.aclose()

@pytest.fixture
def mock_user_data():
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass"
    }


@pytest.fixture
def mock_jwt_token(mock_user_data):
    data = {"id": str(uuid.uuid4())}
    return jwt.encode(
        data,
        settings.jwt.secret,
        algorithm=settings.jwt.algorithm
    )
