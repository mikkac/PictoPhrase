
from fastapi import APIRouter, HTTPException, status

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import get_password_hash, user_dependency
from app.api.session import session_dependency
from app.api.models import User, CreateUserRequest


router = APIRouter()


@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request: CreateUserRequest,
                      session: AsyncSession = session_dependency,):
    result = await session.execute(select(User).where(User.username == create_user_request.username))
    if result.scalars().first() is not None:
        raise HTTPException(status_code=400, detail="Cannot use this username")
    user = User(
        username=create_user_request.username,
        hashed_password=get_password_hash(create_user_request.password),
    )
    session.add(user)
    await session.commit()
    return user

@router.get('/', status_code=status.HTTP_200_OK)
async def user(user: user_dependency, session: AsyncSession = session_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user