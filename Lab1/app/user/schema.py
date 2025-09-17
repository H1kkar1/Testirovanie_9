from datetime import datetime
from pydantic import BaseModel, EmailStr, UUID4, Field
from typing import Optional, Annotated


class UserBase(BaseModel):
    username: str
    email: EmailStr
    date: datetime


class UserRead(UserBase):
    id: UUID4


class UserWrite(BaseModel):
    username: str
    email: str
    password: str


class UserUpdate(BaseModel):
    id: UUID4
    username: Annotated[str, Field(min_length=3, max_length=128), None]
    email: Optional[EmailStr]


class Login(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]
    password: str


class Authorization(BaseModel):
    email: str
    password: str
    username: str


class Recovery(BaseModel):
    email: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    id: UUID4 | None = None