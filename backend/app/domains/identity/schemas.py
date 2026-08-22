from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRegistrationRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID | str
    email: EmailStr
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    message: str
    user: UserPublic