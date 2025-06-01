from motor.motor_asyncio import AsyncIOMotorClient
import os
from typing import List, Optional, Dict, Any
from backend.models import *
from datetime import datetime, timedelta
import bcrypt
import jwt
from passlib.context import CryptContext

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Database:
    def __init__(self, mongo_url: str, db_name: str):
        self.client = AsyncIOMotorClient(mongo_url)
        self.db = self.client[db_name]
        
    async def close(self):
        self.client.close()
    
    # User operations
    async def create_user(self, user_data: UserCreate) -> User:
        # Check if user exists
        existing_user = await self.db.users.find_one({"email": user_data.email})
        if existing_user:
            raise ValueError("User with this email already exists")
        
        # Hash password
        password_hash = pwd_context.hash(user_data.password)
        
        # Create user
        user = User(
            email=user_data.email,
            username=user_data.username,
            password_hash=password_hash,
            user_type=user_data.user_type,
            bio=user_data.bio,
            referred_by=user_data.referred_by
        )
        
        await self.db.users.insert_one(user.dict())
        return user
    
    async def authenticate_user(self, email: str, password: str) -> Optional[User]:
        user_data = await self.db.users.find_one({"email": email})
        if not user_data:
            return None
        
        if not pwd_context.verify(password, user_data["password_hash"]):
            return None
        
        return User(**user_data)
    
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        user_data = await self.db.users.find_one({"id": user_id})
        return User(**user_data) if user_data else None
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        user_data = await self.db.users.find_one({"email": email})
        return User(**user_data) if user_data else None
    
    async def update_user(self, user_id: str, update_data: Dict[str, Any]) -> bool:
        update_data["updated_at"] = datetime.utcnow()
        result = await self.db.users.update_one(
            {"id": user_id}, 
            {"$set": update_data}
        )
        return result.modified_count > 0
    
    # Vault operations
    async def create_vault(self, vault_data: VaultCreate, whisperer_id: str) -> Vault:
        vault = Vault(
            title=vault_data.title,
            description=vault_data.description,
            category=vault_data.category,
            secret_type=vault_data.secret_type,
            content=vault_data.content,
            preview=vault_data.preview,
            whisperer_id=whisperer_id,
            funding_goal=vault_data.funding_goal,
            duration_days=vault_data.duration_days,
            deadline=datetime.utcnow() + timedelta(days=vault_data.duration_days),
            content_warnings=vault_data.content_warnings,
            tags=vault_data.tags,
            status=VaultStatus.LIVE
        )
        
        await self.db.vaults.insert_one(vault.dict())
        return vault
    
    async def get_vault_by_id(self, vault_id: str) -> Optional[Vault]:
        vault_data = await self.db.vaults.find_one({"id": vault_id})
        return Vault(**vault_data) if vault_data else None
    
    async def get_vaults(self, 
                        status: Optional[VaultStatus] = None,
                        category: Optional[Category] = None,
                        featured: Optional[bool] = None,
                        limit: int = 20,
                        skip: int = 0) -> List[Vault]:
        query = {}
        if status:
            query["status"] = status
        if category:
            query["category"] = category
        if featured is not None:
            query["is_featured"] = featured
        
        cursor = self.db.vaults.find(query).sort("created_at", -1).skip(skip).limit(limit)
        vaults = await cursor.to_list(length=limit)
        return [Vault(**vault) for vault in vaults]
    
    async def get_vault_responses(self, 
                                status: Optional[VaultStatus] = None,
                                category: Optional[Category] = None,
                                featured: Optional[bool] = None,
                                limit: int = 20,
                                skip: int = 0) -> List[VaultResponse]:
        vaults = await self.get_vaults(status, category, featured, limit, skip)
        responses = []
        
        for vault in vaults:
            # Get whisperer info
            whisperer = await self.get_user_by_id(vault.whisperer_id)
            
            # Calculate progress and time left
            progress_percentage = (vault.pledged_amount / vault.funding_goal) * 100
            time_left = self._calculate_time_left(vault.deadline)
            
            response = VaultResponse(
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
            responses.append(response)
        
        return responses
    
    async def update_vault(self, vault_id: str, update_data: Dict[str, Any]) -> bool:
        result = await self.db.vaults.update_one(
            {"id": vault_id}, 
            {"$set": update_data}
        )
        return result.modified_count > 0
    
    async def get_user_vaults(self, user_id: str, limit: int = 20) -> List[VaultResponse]:
        vaults = await self.get_vaults(limit=limit)
        # Filter vaults where user is whisperer
        user_vaults = [v for v in vaults if v.whisperer_id == user_id]
        return await self._convert_to_vault_responses(user_vaults)
    
    # Pledge operations
    async def create_pledge(self, pledge_data: PledgeCreate, user_id: str) -> Pledge:
        # Check if vault exists
        vault = await self.get_vault_by_id(pledge_data.vault_id)
        if not vault:
            raise ValueError("Vault not found")
        
        # Calculate referral credit
        referral_credit = pledge_data.amount * 0.05 if pledge_data.referrer_id else 0.0
        
        pledge = Pledge(
            vault_id=pledge_data.vault_id,
            user_id=user_id,
            amount=pledge_data.amount,
            referrer_id=pledge_data.referrer_id,
            referral_credit_earned=referral_credit
        )
        
        # Insert pledge
        await self.db.pledges.insert_one(pledge.dict())
        
        # Update vault pledged amount and backers count
        await self.update_vault(pledge_data.vault_id, {
            "pledged_amount": vault.pledged_amount + pledge_data.amount,
            "backers_count": vault.backers_count + 1
        })
        
        # Check if funding goal is reached
        if vault.pledged_amount + pledge_data.amount >= vault.funding_goal:
            await self.update_vault(pledge_data.vault_id, {
                "status": VaultStatus.FUNDED
            })
        
        return pledge
    
    async def get_user_pledges(self, user_id: str) -> List[PledgeResponse]:
        cursor = self.db.pledges.find({"user_id": user_id}).sort("created_at", -1)
        pledges = await cursor.to_list(length=100)
        
        responses = []
        for pledge_data in pledges:
            pledge = Pledge(**pledge_data)
            vault = await self.get_vault_by_id(pledge.vault_id)
            
            response = PledgeResponse(
                id=pledge.id,
                vault_id=pledge.vault_id,
                vault_title=vault.title if vault else "Unknown",
                amount=pledge.amount,
                status=pledge.status,
                referral_credit_earned=pledge.referral_credit_earned,
                created_at=pledge.created_at
            )
            responses.append(response)
        
        return responses
    
    # Comment operations
    async def create_comment(self, comment_data: CommentCreate, user_id: str) -> Comment:
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        comment = Comment(
            vault_id=comment_data.vault_id,
            user_id=user_id,
            username=user.username,
            content=comment_data.content
        )
        
        await self.db.comments.insert_one(comment.dict())
        return comment
    
    async def get_vault_comments(self, vault_id: str) -> List[Comment]:
        cursor = self.db.comments.find({"vault_id": vault_id}).sort("created_at", -1)
        comments = await cursor.to_list(length=100)
        return [Comment(**comment) for comment in comments]
    
    # Analytics operations
    async def get_vault_stats(self) -> VaultStats:
        total_vaults = await self.db.vaults.count_documents({})
        live_vaults = await self.db.vaults.count_documents({"status": VaultStatus.LIVE})
        funded_vaults = await self.db.vaults.count_documents({"status": {"$in": [VaultStatus.FUNDED, VaultStatus.UNLOCKED]}})
        
        # Calculate totals
        pipeline = [
            {"$group": {
                "_id": None,
                "total_pledged": {"$sum": "$pledged_amount"},
                "total_goal": {"$sum": "$funding_goal"}
            }}
        ]
        result = await self.db.vaults.aggregate(pipeline).to_list(1)
        total_pledged = result[0]["total_pledged"] if result else 0.0
        
        return VaultStats(
            total_vaults=total_vaults,
            live_vaults=live_vaults,
            funded_vaults=funded_vaults,
            total_pledged=total_pledged,
            total_earned=total_pledged * 0.9  # After platform fees
        )
    
    async def get_user_stats(self) -> UserStats:
        total_users = await self.db.users.count_documents({})
        total_whisperers = await self.db.users.count_documents({"user_type": {"$in": [UserType.WHISPERER, UserType.BOTH]}})
        total_listeners = await self.db.users.count_documents({"user_type": {"$in": [UserType.LISTENER, UserType.BOTH]}})
        verified_users = await self.db.users.count_documents({"is_verified": True})
        
        return UserStats(
            total_users=total_users,
            total_whisperers=total_whisperers,
            total_listeners=total_listeners,
            verified_users=verified_users
        )
    
    # Helper methods
    def _calculate_time_left(self, deadline: datetime) -> str:
        now = datetime.utcnow()
        if now >= deadline:
            return "Expired"
        
        delta = deadline - now
        days = delta.days
        hours = delta.seconds // 3600
        
        if days > 0:
            return f"{days} days"
        elif hours > 0:
            return f"{hours} hours"
        else:
            return "Less than 1 hour"
    
    async def _convert_to_vault_responses(self, vaults: List[Vault]) -> List[VaultResponse]:
        responses = []
        for vault in vaults:
            whisperer = await self.get_user_by_id(vault.whisperer_id)
            progress_percentage = (vault.pledged_amount / vault.funding_goal) * 100
            time_left = self._calculate_time_left(vault.deadline)
            
            response = VaultResponse(
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
            responses.append(response)
        
        return responses