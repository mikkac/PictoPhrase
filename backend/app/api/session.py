"""
SQLAlchemy async engine and sessions tools

https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
"""

from typing import Annotated
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from collections.abc import AsyncGenerator

from app.api.config import settings

if settings.ENVIRONMENT == "PYTEST":
    sqlalchemy_database_uri = settings.TEST_SQLALCHEMY_DATABASE_URI
else:
    sqlalchemy_database_uri = settings.DEFAULT_SQLALCHEMY_DATABASE_URI


async_engine = create_async_engine(sqlalchemy_database_uri, pool_pre_ping=True)
async_session = async_sessionmaker(async_engine, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session

# session_dependency = Annotated[AsyncSession, Depends(get_session)]
session_dependency = Depends(get_session)