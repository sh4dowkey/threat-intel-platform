from fastapi import APIRouter, Depends
from fastapi import HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.core.database import get_db
from app.models.ioc import IOCRecord
from app.services.enrichment import enrichment_service, detect_ioc_type

router = APIRouter(prefix="/api/ioc", tags=["IOC"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IOCLookupRequest(BaseModel):
    value: str

    @field_validator("value")
    @classmethod
    def validate_ioc(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("IOC value cannot be empty")
        if len(v) > 256:
            raise ValueError("IOC value too long (max 256 chars)")
        if detect_ioc_type(v) == "unknown":
            raise ValueError(
                "Supported: IPv4 address, domain name, MD5/SHA1/SHA256 hash."
            )
        return v


class BulkLookupRequest(BaseModel):
    values: list[str]

    @field_validator("values")
    @classmethod
    def validate_bulk(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("values list cannot be empty")
        if len(v) > 10:
            raise ValueError("Maximum 10 IOCs per bulk request")
        return [x.strip() for x in v if x.strip()]


class IOCResponse(BaseModel):
    ioc: str
    ioc_type: str
    risk_score: int
    verdict: str
    vt_malicious: int
    vt_suspicious: int
    vt_harmless: int
    vt_total_engines: int
    vt_reputation: int
    vt_tags: list[str]
    vt_country: Optional[str]
    vt_as_owner: Optional[str]
    vt_error: Optional[str]
    abuse_confidence_score: int
    abuse_total_reports: int
    abuse_num_reporters: int
    abuse_isp: Optional[str]
    abuse_usage_type: Optional[str]
    abuse_last_reported: Optional[str]
    abuse_is_whitelisted: bool
    abuse_error: Optional[str]
    sources_queried: list[str]
    enrichment_errors: list[str]

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/lookup", response_model=IOCResponse)
async def lookup_ioc(
    request: IOCLookupRequest,
    db: AsyncSession = Depends(get_db),       # ← Depends lives here, in the signature
):
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)

    # Check for a recent record in DB first
    stmt = (
        select(IOCRecord)
        .where(IOCRecord.ioc == request.value)
        .where(IOCRecord.looked_up_at >= one_hour_ago)
        .limit(1)
    )
    existing = await db.execute(stmt)
    record = existing.scalar_one_or_none()

    if record:
        record.lookup_count += 1
        await db.commit()
        print(f"✅ Cache hit — id={record.id}, ioc={record.ioc}, "
              f"lookups={record.lookup_count}")
        return IOCResponse(**{
            c.name: getattr(record, c.name)
            for c in IOCRecord.__table__.columns
        })

    # No cache hit — run enrichment
    result = await enrichment_service.enrich(request.value)

    # Build the DB row from the enrichment result
    column_names = {c.name for c in IOCRecord.__table__.columns}
    db_record = IOCRecord(**{
        k: v for k, v in result.to_dict().items()
        if k in column_names
    })

    db.add(db_record)

    try:
        await db.commit()
        await db.refresh(db_record)
        print(f"✅ Saved to DB — id={db_record.id}, ioc={db_record.ioc}, "
              f"verdict={db_record.verdict}, risk={db_record.risk_score}")
    except Exception as e:
        await db.rollback()
        print(f"❌ DB commit failed: {type(e).__name__}: {e}")
        # Still return the enrichment result even if DB save fails
        # so the API keeps working while we debug
        return IOCResponse(**result.to_dict())

    return IOCResponse(**result.to_dict())


@router.post("/bulk", response_model=list[IOCResponse])
async def bulk_lookup(
    request: BulkLookupRequest,
    db: AsyncSession = Depends(get_db),
):
    import asyncio

    async def enrich_one(value: str) -> IOCResponse:
        try:
            result = await enrichment_service.enrich(value)

            column_names = {c.name for c in IOCRecord.__table__.columns}
            db_record = IOCRecord(**{
                k: v for k, v in result.to_dict().items()
                if k in column_names
            })
            db.add(db_record)

            return IOCResponse(**result.to_dict())
        except Exception as e:
            print(f"❌ Error enriching {value}: {e}")
            return IOCResponse(
                ioc=value,
                ioc_type=detect_ioc_type(value),
                risk_score=0, verdict="unknown",
                vt_malicious=0, vt_suspicious=0, vt_harmless=0,
                vt_total_engines=0, vt_reputation=0, vt_tags=[],
                vt_country=None, vt_as_owner=None, vt_error=None,
                abuse_confidence_score=0, abuse_total_reports=0,
                abuse_num_reporters=0, abuse_isp=None,
                abuse_usage_type=None, abuse_last_reported=None,
                abuse_is_whitelisted=False, abuse_error=None,
                sources_queried=[], enrichment_errors=[str(e)],
            )

    responses = await asyncio.gather(*[enrich_one(v) for v in request.values])

    try:
        await db.commit()
        print(f"✅ Bulk saved {len(responses)} records to DB")
    except Exception as e:
        await db.rollback()
        print(f"❌ Bulk DB commit failed: {type(e).__name__}: {e}")

    return list(responses)