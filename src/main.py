from fastapi import FastAPI, Depends, Form, UploadFile, File, Request, HTTPException, status
from fastapi.middleware import Middleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi.responses import FileResponse
from src.users.app import controller as auth


# DEBUG = int(cf['app']['debug'])
DEBUG = 1

# app initialization
app_title = "Auth Backend API"
app_version = "1.1.0"
app_description = "Support API for all backend related stuff (login, authentication, etc.)"

middlewares = [Middleware(CORSMiddleware)]

if DEBUG:
    app = FastAPI(
        title=app_title,
        version=app_version,
        description=app_description,
        middleware=middlewares
    )
else:
    app = FastAPI(
        title=app_title,
        version=app_version,
        description=app_description,
        openapi_url="/openapi.json",
        middleware=middlewares
    )

app.add_middleware(
    CORSMiddleware,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# security/authentication
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth")

app.include_router(auth.router, tags=['Auth'], prefix='/api/auth')


@app.on_event("startup")
def startup_event():
    # initialization
    app.scheduler = BackgroundScheduler()
    app.users_credentials = {}


@app.on_event("shutdown")
def shutdown_event():
    app.scheduler.shutdown()


@app.get("/")
async def index():
    # for health check of server when logs are disabled in production
    return {"title": app.title, "version": app.version}
