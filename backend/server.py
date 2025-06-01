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
from backend.payment_service import get_payment_service

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

# Pledge endpoints - Updated with payment integration
@api_router.post("/pledges", response_model=APIResponse)
async def create_pledge(
    pledge_data: PledgeCreate,
    current_user_id: str = Depends(get_current_user)
):
    """Create a new pledge with payment integration"""
    try:
        # Verify user can pledge
        user = await database.get_user_by_id(current_user_id)
        if not user or user.user_type not in [UserType.LISTENER, UserType.BOTH]:
            raise HTTPException(status_code=403, detail="Only listeners can create pledges")
        
        # Verify vault exists and is live
        vault = await database.get_vault_by_id(pledge_data.vault_id)
        if not vault:
            raise HTTPException(status_code=404, detail="Vault not found")
        if vault.status != VaultStatus.LIVE:
            raise HTTPException(status_code=400, detail="Vault is not accepting pledges")
        
        # Create Razorpay order
        payment_service = get_payment_service()
        order_data = await payment_service.create_order(
            user_id=current_user_id,
            vault_id=pledge_data.vault_id,
            amount=pledge_data.amount
        )
        
        # Create pledge in pending status
        pledge = await database.create_pledge(pledge_data, current_user_id)
        
        # Update pledge with order details
        await database.update_pledge_payment_info(
            pledge.id, 
            order_data["order_id"], 
            PaymentStatus.CREATED
        )
        
        return APIResponse(
            success=True,
            message="Payment order created successfully",
            data={
                "pledge_id": pledge.id,
                "order_id": order_data["order_id"],
                "amount": order_data["amount"],
                "currency": order_data["currency"],
                "key": order_data["key"]
            }
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

# Payment endpoints
@api_router.post("/payments/verify", response_model=APIResponse)
async def verify_payment(
    payment_data: PaymentVerify,
    current_user_id: str = Depends(get_current_user)
):
    """Verify and authorize payment"""
    try:
        # Authorize payment
        payment_service = get_payment_service()
        payment_result = await payment_service.authorize_payment(
            payment_data.razorpay_payment_id,
            payment_data.razorpay_order_id,
            payment_data.razorpay_signature
        )
        
        # Update pledge status
        await database.update_pledge_by_order_id(
            payment_data.razorpay_order_id,
            payment_data.razorpay_payment_id,
            PaymentStatus.AUTHORIZED
        )
        
        # Update vault pledged amount and check if funding goal reached
        vault = await database.get_vault_by_order_id(payment_data.razorpay_order_id)
        if vault:
            new_pledged_amount = vault.pledged_amount + (payment_result["amount"])
            await database.update_vault_pledged_amount(vault.id, new_pledged_amount)
            
            # Check if funding goal reached
            if new_pledged_amount >= vault.funding_goal:
                await database.update_vault_status(vault.id, VaultStatus.FUNDED)
                # Schedule payment captures for all pledges
                await capture_vault_payments(vault.id)
        
        return APIResponse(
            success=True,
            message="Payment authorized successfully",
            data=payment_result
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Payment verification error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.post("/payments/{payment_id}/refund", response_model=APIResponse)
async def refund_payment(
    payment_id: str,
    refund_data: RefundRequest,
    current_user_id: str = Depends(get_current_user)
):
    """Refund a payment (admin only or automated)"""
    try:
        # TODO: Add admin check
        
        payment_service = get_payment_service()
        refund_result = await payment_service.refund_payment(
            payment_id,
            refund_data.amount,
            refund_data.reason or "Goal not reached"
        )
        
        # Update pledge status
        await database.update_pledge_status_by_payment_id(
            payment_id,
            PaymentStatus.REFUNDED
        )
        
        return APIResponse(
            success=True,
            message="Payment refunded successfully",
            data=refund_result
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Payment refund error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Helper function to capture payments when goal is reached
async def capture_vault_payments(vault_id: str):
    """Capture all authorized payments for a vault when funding goal is reached"""
    try:
        # Get all authorized pledges for this vault
        authorized_pledges = await database.get_vault_pledges(vault_id, PaymentStatus.AUTHORIZED)
        
        for pledge in authorized_pledges:
            if pledge.razorpay_payment_id:
                try:
                    # Capture payment
                    payment_service = get_payment_service()
                    capture_result = await payment_service.capture_payment(
                        pledge.razorpay_payment_id,
                        pledge.amount
                    )
                    
                    # Update pledge status
                    await database.update_pledge_status(pledge.id, PaymentStatus.CAPTURED)
                    
                except Exception as e:
                    logger.error(f"Failed to capture payment {pledge.razorpay_payment_id}: {e}")
        
        # Mark vault as unlocked
        await database.update_vault_status(vault_id, VaultStatus.UNLOCKED)
        
    except Exception as e:
        logger.error(f"Error capturing vault payments: {e}")

from fastapi import Request
import json

@api_router.post("/webhooks/razorpay")
async def razorpay_webhook(request: Request):
    """Handle Razorpay webhooks"""
    try:
        # Get raw payload and signature
        payload = await request.body()
        signature = request.headers.get("X-Razorpay-Signature", "")
        
        # Verify signature
        if not payment_service.verify_webhook_signature(payload, signature):
            raise HTTPException(status_code=400, detail="Invalid signature")
        
        # Parse payload
        event_data = json.loads(payload.decode())
        event_type = event_data.get("event")
        
        # Handle webhook event
        await payment_service.handle_webhook_event(event_type, event_data)
        
        return {"status": "success"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

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