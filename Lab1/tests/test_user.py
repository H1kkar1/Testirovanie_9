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


@pytest.mark.asyncio
async def test_get_user_by_id(async_session: AsyncSession, created_user):
    """Test getting user by ID - both found and not found cases"""
    
    # Тест 1: Получение существующего пользователя
    # Arrange - получаем всех пользователей чтобы узнать ID созданного
    users = await get_all_users(async_session)
    user_id = users[0].id

    # Act
    user = await get_user_by_id(async_session, user_id)

    # Assert
    assert user is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"
    
    # Тест 2: Попытка получения несуществующего пользователя
    # Arrange
    non_existent_id = uuid4()

    # Act & Assert
    with pytest.raises(HTTPException) as excinfo:
        await get_user_by_id(async_session, non_existent_id)

    assert excinfo.value.status_code == 404
    assert "User not found" in str(excinfo.value.detail)