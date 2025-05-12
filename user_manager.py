"""
User Manager Module

Este módulo proporciona la funcionalidad para la gestión de cuentas de usuario:
- Creación, Actualización y Eliminación de cuentas de usuario
- Autenticación
- Validación de contraseña
"""

import re
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime


@dataclass
class User:
    """User data class representing a user account."""
    username: str
    email: str
    password: str  # En un sistema real, debería estar hasheada
    created_at: datetime = None
    is_active: bool = True
    last_login: datetime = None
    role: str = "user"  # Opciones: "user", "admin", "guest"

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


class UserManager:
    """Clase para gestionar cuentas de usuario."""

    def __init__(self):
        self.users: Dict[str, User] = {}

    def create_user(self, username: str, email: str, password: str, role: str = "user") -> Union[User, str]:
        if username in self.users:
            return "Username already exists"

        if not self._is_valid_email(email):
            return "Invalid email format"

        password_check = self._check_password_strength(password)
        if password_check != "ok":
            return password_check

        if role not in ["user", "admin", "guest"]:
            return "Invalid role"

        new_user = User(username=username, email=email, password=password, role=role)
        self.users[username] = new_user
        return new_user

    def get_user(self, username: str) -> Optional[User]:
        return self.users.get(username)

    def update_user(self, username: str, **kwargs) -> Union[User, str]:
        user = self.get_user(username)
        if not user:
            return "User not found"

        if "email" in kwargs and kwargs["email"] != user.email:
            if not self._is_valid_email(kwargs["email"]):
                return "Invalid email format"
            user.email = kwargs["email"]

        if "password" in kwargs:
            password_check = self._check_password_strength(kwargs["password"])
            if password_check != "ok":
                return password_check
            user.password = kwargs["password"]

        if "is_active" in kwargs:
            user.is_active = bool(kwargs["is_active"])

        if "role" in kwargs:
            if kwargs["role"] not in ["user", "admin", "guest"]:
                return "Invalid role"
            user.role = kwargs["role"]

        return user

    def delete_user(self, username: str) -> bool:
        if username in self.users:
            del self.users[username]
            return True
        return False

    def authenticate(self, username: str, password: str) -> Union[User, str]:
        user = self.get_user(username)
        if not user or user.password != password:
            return "Invalid username or password"
        if not user.is_active:
            return "Account is inactive"

        user.last_login = datetime.now()
        return user

    def list_users(self, active_only: bool = False) -> List[User]:
        if active_only:
            return [user for user in self.users.values() if user.is_active]
        return list(self.users.values())

    def _is_valid_email(self, email: str) -> bool:
        """
        Valida el formato del correo electrónico.
        """
        if not isinstance(email, str):
            return False
        pattern = r"^(?!.*\.\.)(?!\.)(?!.*\.$)(?!.*\.$)[\w\.\+\-]+(?<!\.)@[\w\-]+(\.[\w\-]+)+$"
        return re.match(pattern, email) is not None

    def _check_password_strength(self, password: str) -> str:
        if len(password) < 8:
            return "Password must be at least 8 characters long"
        if not re.search(r"[A-Z]", password):
            return "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return "Password must contain at least one digit"
        return "ok"
