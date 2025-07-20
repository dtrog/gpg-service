from pydantic import BaseModel

class KeyRequest(BaseModel):
    username: str
    password: str

