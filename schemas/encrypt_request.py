from pydantic import BaseModel

class EncryptRequest(BaseModel):
    username: str
    recipient: str
    message: str

