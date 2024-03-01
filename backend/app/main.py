from fastapi import FastAPI, status, HTTPException
from app import models
from app.database import engine, db_dependency
from app.auth import router as auth_router
from app.auth import user_dependency

app = FastAPI()
app.include_router(auth_router)

models.Base.metadata.create_all(bind=engine)

@app.get('/', status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user