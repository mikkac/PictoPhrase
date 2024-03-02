"""
Put here any Python code that must be runned before application startup.
It is included in `init.sh` script.

By defualt `main` create a superuser if not exists
"""

import asyncio

from sqlalchemy import select

from app.api.config import settings
from app.api.session import async_session
from app.api.auth import get_password_hash
from app.api.models import User


async def main() -> None:
    print("Start initial data")
    async with async_session() as session:
        result = await session.execute(
            select(User).where(User.username == settings.FIRST_SUPERUSER_NAME)
        )
        user = result.scalars().first()

        if user is None:
            new_superuser = User(
                username=settings.FIRST_SUPERUSER_NAME,
                hashed_password=get_password_hash(
                    settings.FIRST_SUPERUSER_PASSWORD
                ),
            )
            session.add(new_superuser)
            await session.commit()
            print("Superuser was created")
        else:
            print("Superuser already exists in database")

        print("Initial data created")


if __name__ == "__main__":
    asyncio.run(main())
