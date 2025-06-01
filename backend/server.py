from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pathlib import Path
import os
import logging
from typing import List, Optional

# Local imports
from backend.models import *
from backend.database import Database
from backend.auth import create_access_token, get_current_user

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Initialize database
mongo_url = os.environ['MONGO_URL']
db_name = os.environ['DB_NAME']
database = Database(mongo_url, db_name)

# Create FastAPI app
app = FastAPI(title="HushHush API", version="1.0.0")
api_router = APIRouter(prefix="/api")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Authentication endpoints
@api_router.post("/auth/register", response_model=APIResponse)
async def register(user_data: UserCreate):
    """Register a new user"""
    try:
        user = await database.create_user(user_data)
        
        # Create access token
        access_token = create_access_token(data={"sub": user.id})
        
        return APIResponse(
            success=True,
            message="User registered successfully",
            data={
                "user": UserResponse(**user.dict()),
                "access_token": access_token,
                "token_type": "bearer"
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.post("/auth/login", response_model=APIResponse)
async def login(credentials: UserLogin):
    """Login user"""
    try:
        user = await database.authenticate_user(credentials.email, credentials.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        # Create access token
        access_token = create_access_token(data={"sub": user.id})
        
        return APIResponse(
            success=True,
            message="Login successful",
            data={
                "user": UserResponse(**user.dict()),
                "access_token": access_token,
                "token_type": "bearer"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.get("/auth/me", response_model=APIResponse)
async def get_current_user_info(current_user_id: str = Depends(get_current_user)):
    """Get current user information"""
    try:
        user = await database.get_user_by_id(current_user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return APIResponse(
            success=True,
            message="User information retrieved",
            data=UserResponse(**user.dict())
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Vault endpoints
@api_router.get("/vaults", response_model=APIResponse)
async def get_vaults(
    status: Optional[str] = None,
    category: Optional[str] = None,
    featured: Optional[bool] = None,
    limit: int = 20,
    skip: int = 0
):
    """Get list of vaults"""
    try:
        vault_status = VaultStatus(status) if status else None
        vault_category = Category(category) if category else None
        
        vaults = await database.get_vault_responses(
            status=vault_status,
            category=vault_category,
            featured=featured,
            limit=limit,
            skip=skip
        )
        
        return APIResponse(
            success=True,
            message="Vaults retrieved successfully",
            data=vaults
        )
    except Exception as e:
        logger.error(f"Get vaults error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.get("/vaults/{vault_id}", response_model=APIResponse)
async def get_vault(vault_id: str):
    """Get vault details"""
    try:
        vault = await database.get_vault_by_id(vault_id)
        if not vault:
            raise HTTPException(status_code=404, detail="Vault not found")
        
        # Get whisperer info
        whisperer = await database.get_user_by_id(vault.whisperer_id)
        
        # Calculate progress and time left
        progress_percentage = (vault.pledged_amount / vault.funding_goal) * 100
        time_left = database._calculate_time_left(vault.deadline)
        
        vault_response = VaultResponse(
            id=vault.id,
            title=vault.title,
            description=vault.description,
            category=vault.category,
            secret_type=vault.secret_type,
            preview=vault.preview,
            cover_image_url=vault.cover_image_url,
            whisperer_id=vault.whisperer_id,
            whisperer_username=whisperer.username if whisperer else "Unknown",
            funding_goal=vault.funding_goal,
            pledged_amount=vault.pledged_amount,
            backers_count=vault.backers_count,
            duration_days=vault.duration_days,
            status=vault.status,
            is_featured=vault.is_featured,
            created_at=vault.created_at,
            deadline=vault.deadline,
            unlocked_at=vault.unlocked_at,
            content_warnings=vault.content_warnings,
            tags=vault.tags,
            progress_percentage=round(progress_percentage, 1),
            time_left=time_left
        )
        
        return APIResponse(
            success=True,
            message="Vault retrieved successfully",
            data=vault_response
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get vault error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.post("/vaults", response_model=APIResponse)
async def create_vault(
    vault_data: VaultCreate,
    current_user_id: str = Depends(get_current_user)
):
    """Create a new vault"""
    try:
        # Verify user can create vaults
        user = await database.get_user_by_id(current_user_id)
        if not user or user.user_type not in [UserType.WHISPERER, UserType.BOTH]:
            raise HTTPException(status_code=403, detail="Only whisperers can create vaults")
        
        vault = await database.create_vault(vault_data, current_user_id)
        
        return APIResponse(
            success=True,
            message="Vault created successfully",
            data={"vault_id": vault.id}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create vault error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.get("/vaults/{vault_id}/content", response_model=APIResponse)
async def get_vault_content(
    vault_id: str,
    current_user_id: str = Depends(get_current_user)
):
    """Get vault content (only if unlocked and user has pledged)"""
    try:
        vault = await database.get_vault_by_id(vault_id)
        if not vault:
            raise HTTPException(status_code=404, detail="Vault not found")
        
        # Check if vault is unlocked
        if vault.status != VaultStatus.UNLOCKED:
            raise HTTPException(status_code=403, detail="Vault is not unlocked yet")
        
        # Check if user has pledged
        user_pledges = await database.get_user_pledges(current_user_id)
        has_pledged = any(pledge.vault_id == vault_id for pledge in user_pledges)
        
        if not has_pledged and vault.whisperer_id != current_user_id:
            raise HTTPException(status_code=403, detail="You must pledge to access this content")
        
        return APIResponse(
            success=True,
            message="Vault content retrieved",
            data={"content": vault.content}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get vault content error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Pledge endpoints
@api_router.post("/pledges", response_model=APIResponse)
async def create_pledge(
    pledge_data: PledgeCreate,
    current_user_id: str = Depends(get_current_user)
):
    """Create a new pledge"""
    try:
        # Verify user can pledge
        user = await database.get_user_by_id(current_user_id)
        if not user or user.user_type not in [UserType.LISTENER, UserType.BOTH]:
            raise HTTPException(status_code=403, detail="Only listeners can create pledges")
        
        pledge = await database.create_pledge(pledge_data, current_user_id)
        
        return APIResponse(
            success=True,
            message="Pledge created successfully",
            data={"pledge_id": pledge.id}
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create pledge error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.get("/pledges/my", response_model=APIResponse)
async def get_my_pledges(current_user_id: str = Depends(get_current_user)):
    """Get current user's pledges"""
    try:
        pledges = await database.get_user_pledges(current_user_id)
        
        return APIResponse(
            success=True,
            message="Pledges retrieved successfully",
            data=pledges
        )
    except Exception as e:
        logger.error(f"Get pledges error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Comment endpoints
@api_router.post("/comments", response_model=APIResponse)
async def create_comment(
    comment_data: CommentCreate,
    current_user_id: str = Depends(get_current_user)
):
    """Create a comment on a vault"""
    try:
        comment = await database.create_comment(comment_data, current_user_id)
        
        return APIResponse(
            success=True,
            message="Comment created successfully",
            data=comment
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Create comment error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.get("/comments/{vault_id}", response_model=APIResponse)
async def get_vault_comments(vault_id: str):
    """Get comments for a vault"""
    try:
        comments = await database.get_vault_comments(vault_id)
        
        return APIResponse(
            success=True,
            message="Comments retrieved successfully",
            data=comments
        )
    except Exception as e:
        logger.error(f"Get comments error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# User dashboard endpoints
@api_router.get("/dashboard/whisperer", response_model=APIResponse)
async def get_whisperer_dashboard(current_user_id: str = Depends(get_current_user)):
    """Get whisperer dashboard data"""
    try:
        user = await database.get_user_by_id(current_user_id)
        if not user or user.user_type not in [UserType.WHISPERER, UserType.BOTH]:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get user's vaults
        user_vaults = await database.get_user_vaults(current_user_id)
        
        # Calculate stats
        total_earned = sum(v.pledged_amount * 0.9 for v in user_vaults if v.status == VaultStatus.UNLOCKED)
        active_vaults = len([v for v in user_vaults if v.status == VaultStatus.LIVE])
        
        return APIResponse(
            success=True,
            message="Dashboard data retrieved",
            data={
                "vaults": user_vaults,
                "stats": {
                    "total_earned": total_earned,
                    "active_vaults": active_vaults,
                    "total_vaults": len(user_vaults),
                    "credibility_score": user.credibility_score
                }
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get whisperer dashboard error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.get("/dashboard/listener", response_model=APIResponse)
async def get_listener_dashboard(current_user_id: str = Depends(get_current_user)):
    """Get listener dashboard data"""
    try:
        user = await database.get_user_by_id(current_user_id)
        if not user or user.user_type not in [UserType.LISTENER, UserType.BOTH]:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get user's pledges
        user_pledges = await database.get_user_pledges(current_user_id)
        
        # Calculate stats
        total_pledged = sum(p.amount for p in user_pledges)
        active_pledges = len([p for p in user_pledges if p.status == "authorized"])
        
        return APIResponse(
            success=True,
            message="Dashboard data retrieved",
            data={
                "pledges": user_pledges,
                "stats": {
                    "total_pledged": total_pledged,
                    "active_pledges": active_pledges,
                    "total_pledges": len(user_pledges),
                    "referral_credits": sum(p.referral_credit_earned for p in user_pledges)
                }
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get listener dashboard error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Analytics endpoints
@api_router.get("/analytics/stats", response_model=APIResponse)
async def get_platform_stats():
    """Get platform analytics"""
    try:
        vault_stats = await database.get_vault_stats()
        user_stats = await database.get_user_stats()
        
        return APIResponse(
            success=True,
            message="Analytics retrieved successfully",
            data={
                "vaults": vault_stats,
                "users": user_stats
            }
        )
    except Exception as e:
        logger.error(f"Get analytics error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Health check
@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "HushHush API is running"}

# Include router
app.include_router(api_router)

@app.on_event("shutdown")
async def shutdown_event():
    await database.close()