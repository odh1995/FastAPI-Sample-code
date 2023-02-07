from passlib.context import CryptContext
from datetime import datetime

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)


def calculate_days_left(created_at):
    delta = datetime.utcnow().date() - created_at.date()
    days_left = 90 - delta.days
    return days_left
