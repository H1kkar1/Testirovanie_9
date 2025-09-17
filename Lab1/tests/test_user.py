import pytest
from app.user.service import (
    get_all_users,
    get_user_by_id,
    get_user_by_email,
    get_user_by_name,
    create_user,
    update_user,
    delete_user,
    authenticate_user,
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_user,
)
from app.user.schema import UserWrite, UserUpdate, Login
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4
from datetime import timedelta
import jwt
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_get_all_users(async_session: AsyncSession, created_user):
    """Test getting all users"""
    # Act
    users = await get_all_users(async_session)

    # Assert
    assert len(users) > 0
    assert users[0].username == "testuser"
    assert users[0].email == "test@example.com"


@pytest.mark.asyncio
async def test_get_user_by_id_found(async_session: AsyncSession, created_user):
    """Test getting user by ID when user exists"""
    # Arrange - сначала получаем всех пользователей чтобы узнать ID
    users = await get_all_users(async_session)
    user_id = users[0].id

    # Act
    user = await get_user_by_id(async_session, user_id)

    # Assert
    assert user is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_get_user_by_id_not_found(async_session: AsyncSession):
    """Test getting user by ID when user doesn't exist"""
    # Arrange
    non_existent_id = uuid4()

    # Act & Assert
    with pytest.raises(HTTPException) as excinfo:
        await get_user_by_id(async_session, non_existent_id)

    assert excinfo.value.status_code == 404
    assert "User not found" in str(excinfo.value.detail)


@pytest.mark.asyncio
async def test_create_user_success(async_session: AsyncSession, mock_user_data):
    """Test successful user creation"""
    # Arrange
    user = UserWrite(**mock_user_data)

    # Act
    token = await create_user(async_session, user)

    # Assert
    assert isinstance(token, str)
    assert len(token) > 0

    # Проверяем, что пользователь действительно создан
    users = await get_all_users(async_session)
    assert len(users) == 1
    assert users[0].username == mock_user_data["username"]
    assert users[0].email == mock_user_data["email"]


@pytest.mark.asyncio
async def test_get_user_by_email_found(async_session: AsyncSession, created_user):
    """Test getting user by email when user exists"""
    # Act
    user = await get_user_by_email(async_session, "test@example.com")

    # Assert
    assert user is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_get_user_by_name_found(async_session: AsyncSession, created_user):
    """Test getting user by username when user exists"""
    # Act
    user = await get_user_by_name(async_session, "testuser")

    # Assert
    assert user is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize("username, email, password, expected_success", [
    ("testuser", None, "testpass", True),  # Auth by username
    (None, "test@example.com", "testpass", True),  # Auth by email
    ("wronguser", None, "testpass", False),  # Wrong username
    (None, "wrong@example.com", "testpass", False),  # Wrong email
    (None, None, "testpass", False),  # No credentials
    ("testuser", None, "wrongpass", False),  # Wrong password
])
async def test_authenticate_user(
        async_session: AsyncSession,
        created_user,
        username,
        email,
        password,
        expected_success
):
    """Test user authentication with various scenarios"""
    login = Login(username=username, email=email, password=password)

    if expected_success:
        # Successful authentication
        user = await authenticate_user(async_session, login)
        assert user is not None
        assert user.username == "testuser" or user.email == "test@example.com"
    else:
        # Failed authentication
        with pytest.raises(HTTPException) as excinfo:
            await authenticate_user(async_session, login)
        assert excinfo.value.status_code in [401, 404]


@pytest.mark.asyncio
async def test_update_user(async_session: AsyncSession, created_user):
    """Test updating user information"""
    # Arrange
    users = await get_all_users(async_session)
    user_id = users[0].id

    update_data = UserUpdate(
        username="updateduser",
        email="updated@example.com"
    )

    # Act
    updated_user = await update_user(async_session, user_id, update_data)

    # Assert
    assert updated_user is not None
    assert updated_user.username == "updateduser"
    assert updated_user.email == "updated@example.com"


@pytest.mark.asyncio
async def test_delete_user(async_session: AsyncSession, created_user):
    """Test deleting a user"""
    # Arrange
    users = await get_all_users(async_session)
    user_id = users[0].id

    # Act
    result = await delete_user(async_session, user_id)

    # Assert
    assert result is True

    # Verify user is deleted
    with pytest.raises(HTTPException) as excinfo:
        await get_user_by_id(async_session, user_id)
    assert excinfo.value.status_code == 404


def test_verify_password_correct():
    """Test password verification with correct password"""
    plain_password = "testpass"
    hashed_password = get_password_hash(plain_password)

    result = verify_password(plain_password, hashed_password)
    assert result is True


def test_verify_password_incorrect():
    """Test password verification with incorrect password"""
    plain_password = "testpass"
    wrong_password = "wrongpass"
    hashed_password = get_password_hash(plain_password)

    result = verify_password(wrong_password, hashed_password)
    assert result is False


@pytest.mark.parametrize("data, expires_delta", [
    ({"id": str(uuid4())}, None),
    ({"id": str(uuid4())}, timedelta(minutes=30)),
    ({"username": "testuser", "email": "test@example.com"}, timedelta(hours=1)),
])
def test_create_access_token(data, expires_delta):
    """Test JWT token creation"""
    token = create_access_token(data, expires_delta)

    assert isinstance(token, str)
    assert len(token) > 0

    # Optional: verify token can be decoded
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert "exp" in decoded


@pytest.mark.asyncio
async def test_get_current_user_valid_token(async_session: AsyncSession, created_user):
    """Test getting current user with valid token"""
    # Arrange - получаем токен созданного пользователя
    users = await get_all_users(async_session)
    user_token = users[0].token

    # Act
    current_user = await get_current_user(async_session, user_token)

    # Assert
    assert current_user is not None
    assert current_user.username == "testuser"


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(async_session: AsyncSession):
    """Test getting current user with invalid token"""
    # Arrange
    invalid_token = "invalid.token.here"

    # Act & Assert
    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(async_session, invalid_token)

    assert excinfo.value.status_code == 401


# Дополнительные синхронные тесты (не требуют async_session)
def test_password_hashing():
    """Test that password hashing works correctly"""
    password = "testpassword"
    hashed = get_password_hash(password)

    assert isinstance(hashed, str)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrongpassword", hashed) is False


def test_jwt_token_validation():
    """Test JWT token validation"""
    test_data = {"user_id": "12345", "username": "testuser"}
    token = create_access_token(test_data)

    assert isinstance(token, str)
    assert len(token) > 0

    # Проверяем, что токен можно декодировать
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["user_id"] == "12345"
    assert decoded["username"] == "testuser"
    assert "exp" in decoded