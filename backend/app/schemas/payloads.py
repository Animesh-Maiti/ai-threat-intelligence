from pydantic import BaseModel


class AnalysisRequest(BaseModel):
    target: str
