from pydantic import EmailStr

from src.users.infrastructure.base import GenericRepository
from src.users.domain.models.user import User
from src.users.domain.user_schema import CreateUserSchema


class PostgresUserRepository(GenericRepository):
    def __init__(self) -> None:
        super().__init__()

    def get_user_byemail(self, email: str) -> User:
        user_query = self.db.query(User).filter(
            User.email == EmailStr(email.lower()))
        return user_query

    def get_user_byid(self, user_id: str) -> User:
        user_query = self.db.query(User).filter(User.id == user_id)
        return user_query

    def get_user_byverificationcode(self, verification_code: str) -> User:
        user_query = self.db.query(User).filter(
            User.verification_code == verification_code)
        return user_query

    def create_user(self, user: CreateUserSchema) -> User:
        new_user = User(**user.dict())
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)

        return new_user

    def update_user_verification_code(self, user: User, code: str) -> None:
        user.update({'verification_code': code}, synchronize_session=False)
        self.db.commit()

    def update_user_verified(self, user: User) -> None:
        user.update({'verified': True, 'verification_code': None})
        self.db.commit()

    def update_user_empty_verification_code(self, user: User) -> None:
        user.update({'verification_code': None}, synchronize_session=False)
        self.db.commit()

    def update_user_password(self, user: User, password: str) -> None:
        user.update({'password': password}, synchronize_session=False)
        self.db.commit()
