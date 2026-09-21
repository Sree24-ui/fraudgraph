from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Login(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-zA-Z0-9_.@-]+$')
    password: str = Field(min_length=1, max_length=128)

class UserCreate(Login):
    role: Literal['admin','analyst','viewer','ingestor']

    @field_validator('password')
    @classmethod
    def strong_length(cls, v):
        if len(v) < 14:
            raise ValueError('Use at least 14 characters')
        return v

class TransactionInput(StrictModel):
    id: str = Field(min_length=1, max_length=96, pattern=r'^[a-zA-Z0-9_.:@-]+$')
    occurred_at: StrictInt = Field(ge=0, le=32503680000000)
    sender: str = Field(min_length=1, max_length=96, pattern=r'^[a-zA-Z0-9_.:@-]+$')
    receiver: str = Field(min_length=1, max_length=96, pattern=r'^[a-zA-Z0-9_.:@-]+$')
    amount_paise: StrictInt = Field(gt=0, le=100000000000)
    provenance: Literal['synthetic','external_synthetic','real']

    @model_validator(mode='after')
    def different_accounts(self):
        if self.sender == self.receiver:
            raise ValueError('Sender and receiver must differ')
        return self

class Batch(StrictModel):
    transactions: list[TransactionInput] = Field(min_length=1, max_length=100)

class Review(StrictModel):
    status: Literal['open','investigating','escalated','dismissed']
    note: str = Field(min_length=3, max_length=2000)
    version: StrictInt = Field(ge=1)

    @field_validator('note')
    @classmethod
    def note_content(cls, value):
        if len(value.strip()) < 3:
            raise ValueError('Enter a review note')
        return value.strip()

class UserUpdate(StrictModel):
    active: bool

class PasswordChange(StrictModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=14, max_length=128)
