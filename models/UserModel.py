from bson import ObjectId
from pydantic import BaseModel, ValidationError
from typing import List


class UserModel(BaseModel):
    username: str
    password: str
    email: str
    full_name: str | None = None
    disabled: bool | None = False
    userType: int


class TokenData(BaseModel):
    username: str | None = None
    scopes: List[str] = []


class CurrentUserModel(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    disabled: bool | None = None
    userType: int


class UserSignInModel(BaseModel):
    username: str
    password: str
    read_me: bool | None = True
    read_item: bool | None = False



