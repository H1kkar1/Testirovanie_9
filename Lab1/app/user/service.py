import hashlib
import uuid
from datetime import timezone, datetime, timedelta
from typing import Annotated, Sequence, Type

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError
from pydantic import UUID4, EmailStr
from sqlalchemy import select, delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import db_helper
from app.user.schema import TokenData, Login
from app.config import settings
from app.user.model import User
from app.user.schema import UserRead, UserWrite, UserUpdate


hash_obj = hashlib.sha256()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_all_users(
        session: AsyncSession
) -> Sequence[UserRead]:
    """
    Получение всех пользователей
    """
    query = select(User)
    result = await session.scalars(query)
    return result.all()


async def get_user_by_id(
        session: AsyncSession,
        user_id: UUID4,
) -> UserRead:
    """
    Получить только 1 по id
    """
    query = select(User).filter(User.id == user_id)
    result = await session.execute(query)
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def get_user_by_email(
        session: AsyncSession,
        email: str,
) -> User:
    """
    Получить пользователя по email
    Пригодиться в фильтрах посика
    """
    query = select(User).filter(User.email == email)
    result = await session.execute(query)
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def get_user_by_name(
        session: AsyncSession,
        username: str,
) -> User:
    """
    Получить пользователя по name
    Пригодиться в фильтрах посика
    """
    query = select(User).filter(User.username == username)
    result = await session.execute(query)
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def create_user(
        session: AsyncSession,
        user: UserWrite,
) -> str:
    """
    Создание пользователя
    """
    try:
        user_id = uuid.uuid4()
        jwt_token = create_access_token({'id': str(user_id)})
        new = User(
            id=user_id,
            username=user.username,
            password=get_password_hash(user.password),
            email=user.email,
            date=None,
            token=jwt_token,

        )
        session.add(new)
        await session.commit()
        return jwt_token
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"User not created, {e}")


async def update_user(
        session: AsyncSession,
        user_update: UserUpdate,
) -> User:
    """
    Обновить данные пользователя
    """
    result = await session.execute(select(User).filter(User.id == user_update.id))
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user.photo = user_update.photo_name
    user.password = get_password_hash(user.password)
    await session.commit()
    return user


async def delete_user(
        session: AsyncSession,
        user_id: UUID4,
) -> str:
    """
    :param session: сессия с бд
    :param user_id: id пользователя
    :return: Пользователь будет удалён
    """
    try:
        query = select(User).filter(User.id == user_id)
        result = await session.execute(query)
        if result is None:
            raise HTTPException(status_code=404, detail="User not found")
        user = result.scalars().first()
        query = delete(User).where(User.id == user_id)
        await session.execute(query)
        await session.commit()
        return "Пользователь успешно удалён"
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Fail deleted {e}")


def verify_password(plain_password, hashed_password):
    """
    :param plain_password: Пароль от пользователя
    :param hashed_password: его хеш-версия
    :return: Изменение пароля
    """
    plain_password_bytes = plain_password.encode('utf-8')
    hashed_plain_password = hashlib.sha256(plain_password_bytes).hexdigest()
    return hashed_plain_password == hashed_password


def get_password_hash(password: str) -> str:
    """
    :param password: Пароль от пользователя
    :return: хеш-строка
    """
    hash_obj.update(password.encode('utf-8'))
    hex_dig = hash_obj.hexdigest()
    return hex_dig


async def authenticate_user(
        session: AsyncSession,
        login: Login
) -> str:
    """
    :param session: сессия с бд
    :param login: Набор параметров для аутентификации
    :return: Данные пользователя
    """
    if login.username is not None:
        user = await get_user_by_name(session, login.username)

    elif login.email is not None:
        user = await get_user_by_email(session, login.email)
    else:
        raise HTTPException(
        status_code=404,
        detail="Вы не ввели ни имя пользоватея, ни email",
    )
    if not user:
        raise HTTPException(
            status_code=404,
            detail="Пользователь не найден",
        )
    if not verify_password(login.password, user.password):
        raise HTTPException(
            status_code=404,
            detail="Пароль введён не верно",
        )
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """
    :param data: Данные которые будут записанны в токен
    :param expires_delta:
    :return:
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    print(to_encode)
    encoded_jwt = jwt.encode(to_encode, settings.jwt.secret, algorithm=settings.jwt.algorithm)
    return encoded_jwt


async def get_current_user(
        session: Annotated[
            AsyncSession,
            Depends(db_helper.sessionDep)
        ],
        token: Annotated[str, Depends(oauth2_scheme)]
):
    """
    :param session: сессия с бд
    :param token: токен пользователя
    :return: Данные пользователя
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt.secret, algorithms=[settings.jwt.algorithm])
        user_id: str = payload.get("id")
        print(user_id)
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(id=user_id)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user_by_id(session, token_data.id)
    if user is None:
        raise credentials_exception
    return user
