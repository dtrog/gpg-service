from pydantic import BaseModel

class VerifyRequest(BaseModel):
    signature: str
    message: str

