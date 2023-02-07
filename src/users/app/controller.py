from datetime import timedelta
import hashlib
from random import randbytes
from fastapi import APIRouter, Request, Response, status, Depends, HTTPException
from pydantic import EmailStr

from src.users.domain.user_service import UserService
from src.users.domain.user_schema import CreateUserSchema, LoginUserSchema, ResetPasswordSchema
from src.users.app.utils import get_user_service
from src.users.core.utils import hash_password
from src.users.core.oauth2 import require_user

# from app import oauth2
# from .. import schemas, models, utils
from src.users.core.oauth2 import AuthJWT
from src.users.core.config import settings
from src.users.core.email import Email
from src.users.core.utils import verify_password


router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


@router.post('/register', status_code=status.HTTP_201_CREATED)
async def create_user(payload: CreateUserSchema, request: Request, user_service: UserService = Depends(get_user_service)):
    # Check if user already exist
    user_query = user_service.get_user_byemail(payload.email.lower())
    user = user_query.first()
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail='Account already exist')
    # Compare password and passwordConfirm
    if payload.password != payload.passwordConfirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')
    #  Hash the password
    payload.password = hash_password(payload.password)
    del payload.passwordConfirm
    payload.role = 'user'
    payload.verified = False
    payload.email = EmailStr(payload.email.lower())

    new_user = user_service.create_user(payload)

    try:
        # Send Verification Email
        token = randbytes(10)
        hashedCode = hashlib.sha256()
        hashedCode.update(token)
        verification_code = hashedCode.hexdigest()
        user_service.update_user_verification_code(
            user_query, verification_code)

        url = f"{request.url.scheme}://{settings.WEBAPP_HOSTNAME}:{request.url.port}/api/auth/verifyemail/{token.hex()}"
        await Email(new_user, payload.email, url).sendVerificationCode()
    except Exception as error:
        print('Error', error)
        user_service.update_user_verification_code(
            user_query, None)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail='There was an error sending email')
    return {'status': 'success', 'message': 'Verification token successfully sent to your email'}


@router.post('/login')
def login(payload: LoginUserSchema, response: Response, user_service: UserService = Depends(get_user_service), Authorize: AuthJWT = Depends()):
    # Check if the user exist
    user_query = user_service.get_user_byemail(payload.email)
    user = user_query.first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # Check if user verified his email
    if not user.verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Please verify your email address')

    # Check if the password is valid
    if not verify_password(payload.password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email or Password')

    # Create access token
    access_token = Authorize.create_access_token(
        subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))

    # Create refresh token
    refresh_token = Authorize.create_refresh_token(
        subject=str(user.id), expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN))

    # Store refresh and access tokens in cookie
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token,
                        REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    # Send both access
    return {'status': 'success', 'access_token': access_token}


@router.get('/refresh')
def refresh_token(response: Response, Authorize: AuthJWT = Depends(), user_service: UserService = Depends(get_user_service)):
    try:
        Authorize.jwt_refresh_token_required()

        user_id = Authorize.get_jwt_subject()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not refresh access token')
        user_query = user_service.get_user_byid(user_id=user_id)
        user = user_query.first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='The user belonging to this token no logger exist')
        access_token = Authorize.create_access_token(
            subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))
    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Please provide refresh token')
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')
    return {'access_token': access_token}


@router.get('/logout', status_code=status.HTTP_200_OK)
def logout(response: Response, Authorize: AuthJWT = Depends(), user_id: str = Depends(require_user)):
    Authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)

    return {'status': 'success'}


@router.get('/verifyemail/{token}')
def verify_me(token: str, user_service: UserService = Depends(get_user_service)):
    hashedCode = hashlib.sha256()
    hashedCode.update(bytes.fromhex(token))
    verification_code = hashedCode.hexdigest()

    user_query = user_service.get_user_byverificationcode(verification_code)
    user = user_query.first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid code or user doesn't exist")
    if user.verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail='Email can only be verified once')

    user_service.update_user_verified(user_query)
    return {
        "status": "success",
        "message": "Account verified successfully"
    }


@router.post('/forget-password')
async def forget_password(email: str, request: Request, user_service: UserService = Depends(get_user_service)):
    # get user info
    user_query = user_service.get_user_byemail(email)
    user = user_query.first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect Email')

    try:
        token = randbytes(10)
        hashedCode = hashlib.sha256()
        hashedCode.update(token)
        verification_code = hashedCode.hexdigest()
        user_service.update_user_verification_code(
            user_query, verification_code)

        url = f"{request.url.scheme}://{settings.WEBAPP_HOSTNAME}:{request.url.port}/api/auth/check-reset-password-email/{token.hex()}"
        await Email(user, email, url).sendResetPassword()

    except Exception as error:
        print('Error', error)
        user_service.update_user_empty_verification_code(user_query)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail='There was an error sending email')
    return {'status': 'success', 'message': 'Reset password email successfully sent'}


@router.get('/check-reset-password-email/{token}')
def check_reset_password_email(token: str, user_service: UserService = Depends(get_user_service)):
    hashedCode = hashlib.sha256()
    hashedCode.update(bytes.fromhex(token))
    verification_code = hashedCode.hexdigest()
    user_query = user_service.get_user_byverificationcode(verification_code)
    user = user_query.first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid code or user doesn't exist")

    return {
        "status": "success",
        "message": "Correct reset password token"
    }


@router.post('/reset-password/{token}')
def reset_password(payload: ResetPasswordSchema, token: str, user_service: UserService = Depends(get_user_service)):
    hashedCode = hashlib.sha256()
    hashedCode.update(bytes.fromhex(token))
    verification_code = hashedCode.hexdigest()
    user_query = user_service.get_user_byverificationcode(verification_code)
    user = user_query.first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid code or user doesn't exist")

    # update user password
    if payload.password != payload.passwordConfirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

    hashed_password = hash_password(payload.password)
    user_service.update_user_password(user_query, hashed_password)
    user_service.update_user_empty_verification_code(user_query)
    return {'status': 'success', 'message': 'Password successfully reset!'}
