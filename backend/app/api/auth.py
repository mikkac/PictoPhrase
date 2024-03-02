from datetime import timedelta, datetime
from typing import Annotated
from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt

from app.api.session import session_dependency
from app.api.models import User
from app.api.config import settings


bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail='Could not validate credentials',
    headers={'WWW-Authenticate': 'Bearer'}
)

def get_password_hash(password: str):
    return bcrypt_context.hash(password)

def verify_password(password: str, hashed_password: str):
    return bcrypt_context.verify(password, hashed_password)

async def authenticate_user(username: str, password: str, session: AsyncSession = session_dependency):
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    to_encode = {
        'sub': username,
        'id': user_id,
        'exp': datetime.utcnow() + expires_delta
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.CRYPTO_ALGORITHM)
    return encoded_jwt

async def get_current_user(
    session: AsyncSession = session_dependency, token: str = Annotated[str, Depends(oauth2_bearer)],
) -> User:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.CRYPTO_ALGORITHM]
        )
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise credentials_exception
    except jwt.DecodeError:
        raise credentials_exception

    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise credentials_exception
    return user

user_dependency = Annotated[User, Depends(get_current_user)]