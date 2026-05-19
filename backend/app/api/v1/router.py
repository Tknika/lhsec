from fastapi import APIRouter
from .organizations import router as organizations_router
from .scans import router as scans_router
from .findings import router as findings_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(organizations_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
