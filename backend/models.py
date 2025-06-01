from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import uuid

class UserType(str, Enum):
    WHISPERER = "whisperer"
    LISTENER = "listener"
    BOTH = "both"

class VaultStatus(str, Enum):
    DRAFT = "draft"
    LIVE = "live"
    FUNDED = "funded"
    UNLOCKED = "unlocked"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

class SecretType(str, Enum):
    TEXT = "text"
    AUDIO = "audio"

class Category(str, Enum):
    UNHINGED = "Unhinged"
    BOLLYWOOD = "Bollywood Insider Secrets"
    CORPORATE = "Corporate Whistleblowing"
    POLITICAL = "Political Behind-the-scenes"
    INFLUENCER = "Social Media Influencer Drama"
    SPORTS = "Sports Controversies"
    HISTORICAL = "Historical Mysteries"

# User Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    username: str
    password_hash: str
    user_type: UserType
    is_verified: bool = False
    is_active: bool = True
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    credibility_score: int = 0
    total_earned: float = 0.0
    total_pledged: float = 0.0
    referral_code: str = Field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    referred_by: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(BaseModel):
    email: str
    username: str
    password: str
    user_type: UserType
    bio: Optional[str] = None
    referred_by: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    user_type: UserType
    is_verified: bool
    avatar_url: Optional[str]
    bio: Optional[str]
    credibility_score: int
    total_earned: float
    total_pledged: float
    referral_code: str
    created_at: datetime

# Vault Models
class Vault(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    category: Category
    secret_type: SecretType
    content: str  # The actual secret content
    preview: str  # Teaser/preview content
    cover_image_url: Optional[str] = None
    whisperer_id: str
    funding_goal: float
    pledged_amount: float = 0.0
    backers_count: int = 0
    duration_days: int
    status: VaultStatus = VaultStatus.DRAFT
    is_featured: bool = False
    platform_fee_percentage: float = 5.0
    credibility_bond_percentage: float = 5.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    deadline: datetime
    unlocked_at: Optional[datetime] = None
    content_warnings: List[str] = []
    tags: List[str] = []

class VaultCreate(BaseModel):
    title: str
    description: str
    category: Category
    secret_type: SecretType
    content: str
    preview: str
    funding_goal: float
    duration_days: int
    content_warnings: List[str] = []
    tags: List[str] = []

class VaultResponse(BaseModel):
    id: str
    title: str
    description: str
    category: Category
    secret_type: SecretType
    preview: str
    cover_image_url: Optional[str]
    whisperer_id: str
    whisperer_username: str
    funding_goal: float
    pledged_amount: float
    backers_count: int
    duration_days: int
    status: VaultStatus
    is_featured: bool
    created_at: datetime
    deadline: datetime
    unlocked_at: Optional[datetime]
    content_warnings: List[str]
    tags: List[str]
    progress_percentage: float
    time_left: str

# Pledge Models
class Pledge(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vault_id: str
    user_id: str
    amount: float
    status: str = "authorized"  # authorized, captured, refunded
    referrer_id: Optional[str] = None
    referral_credit_earned: float = 0.0
    payment_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    captured_at: Optional[datetime] = None
    refunded_at: Optional[datetime] = None

class PledgeCreate(BaseModel):
    vault_id: str
    amount: float
    referrer_id: Optional[str] = None

class PledgeResponse(BaseModel):
    id: str
    vault_id: str
    vault_title: str
    amount: float
    status: str
    referral_credit_earned: float
    created_at: datetime

# Comment Models
class Comment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vault_id: str
    user_id: str
    username: str
    content: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class CommentCreate(BaseModel):
    vault_id: str
    content: str

# Analytics Models
class VaultStats(BaseModel):
    total_vaults: int
    live_vaults: int
    funded_vaults: int
    total_pledged: float
    total_earned: float

class UserStats(BaseModel):
    total_users: int
    total_whisperers: int
    total_listeners: int
    verified_users: int

# API Response Models
class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    per_page: int
    has_next: bool
    has_prev: bool