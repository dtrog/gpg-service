from pydantic import BaseModel

class DecryptRequest(BaseModel):
    username: str
    password: str
    encrypted_message: str

