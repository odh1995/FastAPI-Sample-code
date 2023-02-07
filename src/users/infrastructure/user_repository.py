from abc import ABC, abstractmethod

from src.users.domain.models.user import User


class IUserRepository(ABC):
    @abstractmethod
    def get_user_byemail(self, user_email: str) -> User:
        raise NotImplementedError

    @abstractmethod
    def get_user_byid(self, user_id: str) -> User:
        raise NotImplementedError

    @abstractmethod
    def get_user_byverificationcode(self, verification_code: str) -> User:
        raise NotImplementedError

    @abstractmethod
    def create_user(self) -> User:
        raise NotImplementedError

    @abstractmethod
    def update_user_verification_code(self, user: User, code: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def update_user_verified(self, user: User) -> None:
        raise NotImplementedError

    @abstractmethod
    def update_user_empty_verification_code(self, user: User) -> None:
        raise NotImplementedError
