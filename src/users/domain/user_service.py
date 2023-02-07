from src.users.infrastructure.postgres_user_repository import PostgresUserRepository
from src.users.domain.user_schema import CreateUserSchema, UserBaseSchema
from src.users.domain.models.user import User


class UserService:
    def __init__(self, user_queries: PostgresUserRepository):
        self.__user_queries = user_queries

    def get_user_byemail(self, user_email: str) -> UserBaseSchema:
        user = self.__user_queries.get_user_byemail(user_email)
        return user

    def get_user_byid(self, user_id: str) -> UserBaseSchema:
        user = self.__user_queries.get_user_byid(user_id)
        return user

    def get_user_byverificationcode(self, verification_code: str) -> UserBaseSchema:
        user = self.__user_queries.get_user_byverificationcode(
            verification_code)
        return user

    def create_user(self, user: CreateUserSchema) -> UserBaseSchema:
        new_user = self.__user_queries.create_user(user)
        return new_user

    def update_user_verification_code(self, user: User, code: str) -> None:
        self.__user_queries.update_user_verification_code(user, code)

    def update_user_verified(self, user: User) -> None:
        self.__user_queries.update_user_verified(user)

    def update_user_empty_verification_code(self, user: User) -> None:
        self.__user_queries.update_user_empty_verification_code(user)

    def update_user_password(self, user: User, password: str) -> None:
        self.__user_queries.update_user_password(user, password)
