from fastapi import FastAPI
from app.api import models
from app.api.database import engine
from app.api.endpoints.auth import router as auth_router
from app.api.endpoints.user import router as user_router
from app.api.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    openapi_url="/openapi.json",
    docs_url="/",
)
app.include_router(auth_router)
app.include_router(user_router)

models.Base.metadata.create_all(bind=engine)
