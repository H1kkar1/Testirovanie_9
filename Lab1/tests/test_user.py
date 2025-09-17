import pytest
from app.user.service import (
    get_all_users,
    get_user_by_id,
    create_user,
)
from app.user.schema import UserWrite
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_create_user_success(async_session: AsyncSession, mock_user_data):
    """Test successful user creation"""
    # Arrange
    user_data = UserWrite(**mock_user_data)

    # Act
    token = await create_user(async_session, user_data)

    # Assert
    assert isinstance(token, str)
    assert len(token) > 0

    # Проверяем, что пользователь действительно создан
    users = await get_all_users(async_session)
    assert len(users) == 1
    assert users[0].username == mock_user_data["username"]
    assert users[0].email == mock_user_data["email"]
