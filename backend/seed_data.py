from database import Database
from backend.models import *
import asyncio
import os
from datetime import datetime, timedelta
import random

# Sample data for seeding
SAMPLE_USERS = [
    {
        "email": "riya.kapoor@example.com",
        "username": "BollywoodInsider",
        "password": "password123",
        "user_type": UserType.WHISPERER,
        "bio": "Former assistant director with access to industry secrets. Verified Bollywood insider with 5+ years on sets.",
        "is_verified": True,
        "credibility_score": 85
    },
    {
        "email": "arjun.mehta@example.com", 
        "username": "CrimeListener",
        "password": "password123",
        "user_type": UserType.LISTENER,
        "bio": "True crime enthusiast and secret collector. Always hunting for the next big revelation.",
        "is_verified": True,
        "credibility_score": 45
    },
    {
        "email": "corporate.whale@example.com",
        "username": "SiliconSecrets",
        "password": "password123",
        "user_type": UserType.WHISPERER,
        "bio": "Senior executive at major tech companies. Know where all the bodies are buried in Silicon Valley.",
        "is_verified": True,
        "credibility_score": 92
    },
    {
        "email": "political.insider@example.com",
        "username": "CapitalWhispers",
        "password": "password123",
        "user_type": UserType.WHISPERER,
        "bio": "Former political journalist with connections in highest circles. Retired but still connected.",
        "is_verified": True,
        "credibility_score": 78
    },
    {
        "email": "sports.fan@example.com",
        "username": "GameChanger",
        "password": "password123",
        "user_type": UserType.LISTENER,
        "bio": "Sports betting expert always looking for inside information on match-fixing and player controversies.",
        "is_verified": True,
        "credibility_score": 60
    }
]

SAMPLE_VAULTS = [
    {
        "title": "Superstar's On-Set Meltdown That Cost ₹50 Crores",
        "description": "A major Bollywood A-lister's complete breakdown during a high-budget film shoot that led to the project being shelved indefinitely. Names, dates, and unreleased footage details included.",
        "category": Category.UNHINGED,
        "secret_type": SecretType.TEXT,
        "content": "During the filming of 'Project Phoenix' in March 2024, [MAJOR STAR] had a complete meltdown on set after discovering their co-star was being paid more. They threw a chair at the director, walked off set naked, and the incident was caught on camera by 12 crew members. The production company had to pay ₹50 crores in damages and the film was never completed. I have the WhatsApp screenshots between the producer and star's manager, plus the security footage timestamps.",
        "preview": "A Bollywood superstar's epic meltdown cost a production house ₹50 crores and ended a major film. I was there, I have proof, and the names will shock you.",
        "funding_goal": 75000,
        "duration_days": 14,
        "pledged_amount": 23500,
        "backers_count": 47,
        "content_warnings": ["Language", "Violence", "Adult Content"],
        "tags": ["bollywood", "exclusive", "insider", "scandal"],
        "is_featured": True
    },
    {
        "title": "Tech Unicorn's Fake Revenue Scandal",
        "description": "How India's most celebrated startup inflated revenue by 400% using shell companies and fake transactions. Complete paper trail and whistleblower evidence.",
        "category": Category.UNHINGED,
        "secret_type": SecretType.TEXT,
        "content": "Between 2022-2024, [UNICORN STARTUP] created 15 shell companies to fake ₹2000+ crores in revenue. As the CFO's assistant, I have access to the real books, bank statements, and WhatsApp groups where they planned the fraud. The company is about to go public with these fake numbers. I have 500+ pages of evidence including signed documents from the CEO admitting to the fraud in writing.",
        "preview": "India's most celebrated unicorn startup has been faking revenue using shell companies. I'm ready to expose the ₹2000+ crore fraud with full documentation.",
        "funding_goal": 125000,
        "duration_days": 21,
        "pledged_amount": 45000,
        "backers_count": 89,
        "content_warnings": ["Financial Crime", "Legal Implications"],
        "tags": ["corporate", "fraud", "startup", "whistleblower"],
        "is_featured": True
    },
    {
        "title": "Political Leader's Secret Foreign Funding Network",
        "description": "How a prominent Indian political figure receives millions in foreign funding through cryptocurrency and shell companies. Names, amounts, and transaction records included.",
        "category": Category.UNHINGED,
        "secret_type": SecretType.TEXT,
        "content": "Since 2020, [MAJOR POLITICAL LEADER] has been receiving $2M+ annually from foreign sources through a complex network of crypto wallets and shell companies registered in Dubai and Singapore. As their former digital currency advisor, I have wallet addresses, transaction histories, and recorded conversations where they discuss using this money for election campaigns. This is a clear violation of FCRA and election laws.",
        "preview": "A major Indian political figure has been secretly receiving millions in foreign funding through crypto. I have the wallet addresses and transaction proof.",
        "funding_goal": 200000,
        "duration_days": 30,
        "pledged_amount": 67000,
        "backers_count": 134,
        "content_warnings": ["Political Content", "Legal Implications", "National Security"],
        "tags": ["politics", "corruption", "foreign-funding", "crypto"],
        "is_featured": False
    },
    {
        "title": "Influencer Cartel's Price Fixing Scam",
        "description": "How top Instagram influencers formed a secret cartel to fix brand collaboration rates and destroy smaller creators. Screenshots, voice notes, and contracts included.",
        "category": Category.UNHINGED,
        "secret_type": SecretType.TEXT,
        "content": "15 top Indian influencers (5M+ followers each) formed 'The Circle' - a secret group that fixes minimum rates for brand deals, blacklists smaller creators, and manipulates trending hashtags. I was their social media manager and have 6 months of WhatsApp conversations, rate cards, and evidence of how they killed emerging creators' careers by spreading false rumors to brands.",
        "preview": "India's top influencers run a secret cartel that fixes prices and destroys smaller creators. I managed their conspiracy for 6 months.",
        "funding_goal": 50000,
        "duration_days": 12,
        "pledged_amount": 15000,
        "backers_count": 28,
        "content_warnings": ["Business Ethics", "Manipulation"],
        "tags": ["influencer", "social-media", "cartel", "conspiracy"],
        "is_featured": False
    },
    {
        "title": "Cricket Match-Fixing Ring Still Operating",
        "description": "Active match-fixing network involving international players, bookies, and team officials. Current operations, code words, and betting patterns exposed.",
        "category": Category.UNHINGED,
        "secret_type": SecretType.TEXT,
        "content": "The 2024 match-fixing network is bigger than ever. I'm a former bookie who worked with players from 3 national teams including [MAJOR CRICKET NATION]. We fixed 12 matches in the last World Cup using signal systems, predetermined scores, and cryptocurrency payments. I have player chat logs, payment records, and video evidence of signals being given during live matches. The network is still active and planning to fix upcoming series.",
        "preview": "Match-fixing in cricket never stopped - it just got smarter. I was inside the 2024 network that fixed World Cup matches. Still active.",
        "funding_goal": 300000,
        "duration_days": 25,
        "pledged_amount": 89000,
        "backers_count": 178,
        "content_warnings": ["Sports Corruption", "Gambling", "Legal Issues"],
        "tags": ["cricket", "match-fixing", "sports", "corruption"],
        "is_featured": True
    },
    {
        "title": "Media House's Fake News Factory Operations",
        "description": "How India's largest news channel manufactures fake news stories, manipulates public opinion, and gets paid by political parties for propaganda.",
        "category": Category.UNHINGED,
        "secret_type": SecretType.TEXT,
        "content": "As a senior editor at [MAJOR NEWS CHANNEL], I ran their 'Narrative Control' department for 3 years. We manufactured 200+ fake news stories, created deepfake videos of opposition leaders, and received ₹50 lakhs monthly from ruling party for propaganda. I have the complete fake news database, payment records, deepfake software access, and recorded editorial meetings where we planned disinformation campaigns.",
        "preview": "India's largest news channel runs a fake news factory. I was the chief editor for 3 years and have proof of every manufactured story.",
        "funding_goal": 150000,
        "duration_days": 18,
        "pledged_amount": 32000,
        "backers_count": 64,
        "content_warnings": ["Media Manipulation", "Political Content", "Disinformation"],
        "tags": ["media", "fake-news", "propaganda", "journalism"],
        "is_featured": False
    }
]

async def seed_database():
    """Seed the database with sample data"""
    mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
    db_name = os.environ.get('DB_NAME', 'test_database')
    
    db = Database(mongo_url, db_name)
    
    print("🗃️ Seeding database with sample data...")
    
    # Clear existing data
    await db.db.users.delete_many({})
    await db.db.vaults.delete_many({})
    await db.db.pledges.delete_many({})
    await db.db.comments.delete_many({})
    
    # Create users
    created_users = []
    for user_data in SAMPLE_USERS:
        try:
            user_create = UserCreate(**user_data)
            user = await db.create_user(user_create)
            
            # Update additional fields
            await db.update_user(user.id, {
                "is_verified": user_data.get("is_verified", False),
                "credibility_score": user_data.get("credibility_score", 0)
            })
            
            created_users.append(user)
            print(f"✅ Created user: {user.username}")
        except Exception as e:
            print(f"❌ Error creating user {user_data['username']}: {e}")
    
    # Create vaults
    whisperer_users = [u for u in created_users if u.user_type in [UserType.WHISPERER, UserType.BOTH]]
    
    for i, vault_data in enumerate(SAMPLE_VAULTS):
        try:
            whisperer = whisperer_users[i % len(whisperer_users)]
            
            vault_create = VaultCreate(
                title=vault_data["title"],
                description=vault_data["description"],
                category=vault_data["category"],
                secret_type=vault_data["secret_type"],
                content=vault_data["content"],
                preview=vault_data["preview"],
                funding_goal=vault_data["funding_goal"],
                duration_days=vault_data["duration_days"],
                content_warnings=vault_data["content_warnings"],
                tags=vault_data["tags"]
            )
            
            vault = await db.create_vault(vault_create, whisperer.id)
            
            # Update additional fields
            await db.update_vault(vault.id, {
                "pledged_amount": vault_data["pledged_amount"],
                "backers_count": vault_data["backers_count"],
                "is_featured": vault_data["is_featured"]
            })
            
            print(f"✅ Created vault: {vault.title[:50]}...")
            
            # Create some pledges for this vault
            listener_users = [u for u in created_users if u.user_type in [UserType.LISTENER, UserType.BOTH]]
            num_pledges = min(vault_data["backers_count"], len(listener_users))
            
            for j in range(num_pledges):
                listener = listener_users[j % len(listener_users)]
                pledge_amount = vault_data["pledged_amount"] / vault_data["backers_count"]
                
                pledge_create = PledgeCreate(
                    vault_id=vault.id,
                    amount=pledge_amount
                )
                
                try:
                    # Reset vault pledged amount first
                    await db.update_vault(vault.id, {
                        "pledged_amount": 0,
                        "backers_count": 0
                    })
                    
                    pledge = await db.create_pledge(pledge_create, listener.id)
                except Exception as pe:
                    print(f"❌ Error creating pledge: {pe}")
            
        except Exception as e:
            print(f"❌ Error creating vault {vault_data['title']}: {e}")
    
    # Create some comments
    all_vaults = await db.get_vaults(limit=100)
    sample_comments = [
        "This sounds absolutely insane! Can't wait for the reveal 🔥",
        "Finally someone with the guts to expose the truth",
        "I've been waiting for someone to spill this tea ☕",
        "This better be worth every rupee I'm pledging",
        "The preview alone is mind-blowing. Take my money!",
        "About time someone exposed this corruption",
        "I know this is true - I've heard rumors for years",
        "This is going to break the internet when it comes out",
        "Respect for having the courage to speak up 👏",
        "The evidence better be solid for this price"
    ]
    
    for vault in all_vaults[:3]:  # Add comments to first 3 vaults
        for j in range(5):  # 5 comments per vault
            listener = random.choice([u for u in created_users if u.user_type in [UserType.LISTENER, UserType.BOTH]])
            comment_create = CommentCreate(
                vault_id=vault.id,
                content=random.choice(sample_comments)
            )
            try:
                await db.create_comment(comment_create, listener.id)
            except Exception as ce:
                print(f"❌ Error creating comment: {ce}")
    
    await db.close()
    print("🎉 Database seeding completed!")

if __name__ == "__main__":
    asyncio.run(seed_database())