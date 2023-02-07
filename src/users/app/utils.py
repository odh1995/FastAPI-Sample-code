from src.users.domain.user_service import UserService
from src.users.infrastructure.postgres_user_repository import PostgresUserRepository


def get_user_service() -> UserService:
    return UserService(PostgresUserRepository())
