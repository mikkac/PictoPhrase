
from fastapi import APIRouter, HTTPException, status

from app.api.database import db_dependency
from app.api.auth import user_dependency

router = APIRouter(
    prefix='/user',
    tags=['user'],
)

@router.get('/me', status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user