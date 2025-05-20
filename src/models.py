from pydantic import BaseModel




class BaseTipReportModel(BaseModel):
    body: str
    body_content_type: str = 'markdown'
    modified_ts: str
    name: str
    original_source: str = 'WorldWatch'
    source: str = "WorldWatch"

class PatchTipReportModel(BaseTipReportModel):
    tags_v2: list = []

class AnomaliTipReportModel(BaseTipReportModel):
    created_ts: str
    tags: list = []
