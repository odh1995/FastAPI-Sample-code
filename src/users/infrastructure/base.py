from sqlalchemy.orm import Session
from typing import Callable, Iterator
from contextlib import AbstractContextManager
from src.users.infrastructure.user_repository import IUserRepository
from src.users.dependencies import SessionLocal


class GenericRepository(IUserRepository):
    def __init__(self):
        self.db: Session = SessionLocal()
