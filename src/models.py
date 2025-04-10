from pydantic import BaseModel



class PatchTipReportModel(BaseModel):
    body: str
    body_content_type: str = 'markdown'
    modified_ts: str
    name: str
    original_source: str = 'WorldWatch'
    source: str = "WorldWatch"
    tags: list = []

class AnomaliTipReportModel(PatchTipReportModel):
    created_ts: str
