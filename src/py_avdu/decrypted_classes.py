from typing import Optional
from pydantic import BaseModel


class Info(BaseModel):
    secret: str
    algo: str
    digits: int
    period: Optional[int] = None
    counter: Optional[int] = None
    pin: Optional[str] = None


class Group(BaseModel):
    uuid: str
    name: str


class Entry(BaseModel):
    type: str
    uuid: str
    name: str
    issuer: str
    note: str
    icon: Optional[str] = None
    icon_mime: Optional[str] = None
    icon_hash: Optional[str] = None
    favorite: bool
    info: Info
    groups: list[str]


class Db(BaseModel):
    version: int
    entries: list[Entry]
    groups: list[Group]