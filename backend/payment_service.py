import razorpay
import hmac
import hashlib
import os
from typing import Dict, Any, Optional
from datetime import datetime
from fastapi import HTTPException
from models import PaymentStatus, RazorpayOrder, RazorpayPayment
from database import get_database

class PaymentService:
    def __init__(self):
        self.key_id = os.getenv('RAZORPAY_KEY_ID')
        self.key_secret = os.getenv('RAZORPAY_KEY_SECRET')
        self.webhook_secret = os.getenv('RAZORPAY_WEBHOOK_SECRET')
        
        if not self.key_id or not self.key_secret:
            raise ValueError("Razorpay credentials not found in environment variables")
        
        self.client = razorpay.Client(auth=(self.key_id, self.key_secret))
    
    async def create_order(self, user_id: str, vault_id: str, amount: float) -> Dict[str, Any]:
        """Create a Razorpay order for payment authorization"""
        try:
            db = await get_database()
            
            # Amount in paise (multiply by 100)
            amount_paise = int(amount * 100)
            
            order_data = {
                "amount": amount_paise,
                "currency": "INR",
                "payment_capture": "0",  # Manual capture for crowdfunding
                "notes": {
                    "user_id": user_id,
                    "vault_id": vault_id,
                    "platform": "hushhush"
                }
            }
            
            # Create order with Razorpay
            razorpay_order = self.client.order.create(data=order_data)
            
            # Store order in database
            order = RazorpayOrder(
                razorpay_order_id=razorpay_order['id'],
                user_id=user_id,
                vault_id=vault_id,
                amount=amount_paise,
                currency="INR",
                status=PaymentStatus.CREATED,
                notes=order_data["notes"]
            )
            
            await db.orders.insert_one(order.dict())
            
            return {
                "order_id": razorpay_order['id'],
                "amount": amount_paise,
                "currency": "INR",
                "key": self.key_id
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to create order: {str(e)}")
    
    def verify_payment_signature(self, payment_id: str, order_id: str, signature: str) -> bool:
        """Verify Razorpay payment signature"""
        try:
            params_dict = {
                'razorpay_order_id': order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            }
            return self.client.utility.verify_payment_signature(params_dict)
        except:
            return False
    
    async def authorize_payment(self, payment_id: str, order_id: str, signature: str) -> Dict[str, Any]:
        """Authorize and store payment after successful verification"""
        try:
            db = await get_database()
            
            # Verify signature
            if not self.verify_payment_signature(payment_id, order_id, signature):
                raise HTTPException(status_code=400, detail="Invalid payment signature")
            
            # Get payment details from Razorpay
            payment_details = self.client.payment.fetch(payment_id)
            
            # Get order from database
            order = await db.orders.find_one({"razorpay_order_id": order_id})
            if not order:
                raise HTTPException(status_code=404, detail="Order not found")
            
            # Create payment record
            payment = RazorpayPayment(
                razorpay_payment_id=payment_id,
                razorpay_order_id=order_id,
                razorpay_signature=signature,
                user_id=order['user_id'],
                vault_id=order['vault_id'],
                amount=payment_details['amount'],
                currency=payment_details['currency'],
                status=PaymentStatus.AUTHORIZED,
                method=payment_details.get('method'),
                vpa=payment_details.get('vpa'),
                authorized_at=datetime.utcnow()
            )
            
            # Store payment
            await db.payments.insert_one(payment.dict())
            
            # Update order status
            await db.orders.update_one(
                {"razorpay_order_id": order_id},
                {"$set": {"status": PaymentStatus.AUTHORIZED}}
            )
            
            return {
                "payment_id": payment_id,
                "status": "authorized",
                "amount": payment_details['amount'] / 100,  # Convert back to rupees
                "method": payment_details.get('method')
            }
            
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to authorize payment: {str(e)}")
    
    async def capture_payment(self, payment_id: str, amount: Optional[float] = None) -> Dict[str, Any]:
        """Capture authorized payment when funding goal is reached"""
        try:
            db = await get_database()
            
            # Get payment from database
            payment = await db.payments.find_one({"razorpay_payment_id": payment_id})
            if not payment:
                raise HTTPException(status_code=404, detail="Payment not found")
            
            if payment['status'] != PaymentStatus.AUTHORIZED:
                raise HTTPException(status_code=400, detail="Payment not in authorized state")
            
            # Capture payment with Razorpay
            capture_amount = int(amount * 100) if amount else payment['amount']
            captured_payment = self.client.payment.capture(payment_id, capture_amount)
            
            # Update payment status
            await db.payments.update_one(
                {"razorpay_payment_id": payment_id},
                {
                    "$set": {
                        "status": PaymentStatus.CAPTURED,
                        "captured_at": datetime.utcnow()
                    }
                }
            )
            
            return {
                "payment_id": payment_id,
                "status": "captured",
                "amount": captured_payment['amount'] / 100
            }
            
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to capture payment: {str(e)}")
    
    async def refund_payment(self, payment_id: str, amount: Optional[float] = None, reason: str = "Goal not reached") -> Dict[str, Any]:
        """Refund payment when funding goal is not reached"""
        try:
            db = await get_database()
            
            # Get payment from database
            payment = await db.payments.find_one({"razorpay_payment_id": payment_id})
            if not payment:
                raise HTTPException(status_code=404, detail="Payment not found")
            
            # Create refund with Razorpay
            refund_amount = int(amount * 100) if amount else payment['amount']
            refund_data = {
                "amount": refund_amount,
                "speed": "normal",
                "notes": {
                    "reason": reason,
                    "vault_id": payment['vault_id']
                }
            }
            
            refund = self.client.payment.refund(payment_id, refund_data)
            
            # Update payment status
            await db.payments.update_one(
                {"razorpay_payment_id": payment_id},
                {
                    "$set": {
                        "status": PaymentStatus.REFUNDED,
                        "refunded_at": datetime.utcnow()
                    }
                }
            )
            
            return {
                "refund_id": refund['id'],
                "payment_id": payment_id,
                "status": "refunded",
                "amount": refund['amount'] / 100
            }
            
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to refund payment: {str(e)}")
    
    def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Verify webhook signature"""
        if not self.webhook_secret:
            return False
        
        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(expected_signature, signature)
    
    async def handle_webhook_event(self, event_type: str, payload: Dict[str, Any]):
        """Handle Razorpay webhook events"""
        try:
            db = await get_database()
            
            if event_type == "payment.authorized":
                payment_entity = payload['payload']['payment']['entity']
                payment_id = payment_entity['id']
                
                # Update payment status in database
                await db.payments.update_one(
                    {"razorpay_payment_id": payment_id},
                    {
                        "$set": {
                            "status": PaymentStatus.AUTHORIZED,
                            "authorized_at": datetime.utcnow()
                        }
                    }
                )
                
            elif event_type == "payment.captured":
                payment_entity = payload['payload']['payment']['entity']
                payment_id = payment_entity['id']
                
                # Update payment status in database
                await db.payments.update_one(
                    {"razorpay_payment_id": payment_id},
                    {
                        "$set": {
                            "status": PaymentStatus.CAPTURED,
                            "captured_at": datetime.utcnow()
                        }
                    }
                )
                
            elif event_type == "payment.failed":
                payment_entity = payload['payload']['payment']['entity']
                payment_id = payment_entity['id']
                
                # Update payment status in database
                await db.payments.update_one(
                    {"razorpay_payment_id": payment_id},
                    {"$set": {"status": PaymentStatus.FAILED}}
                )
                
        except Exception as e:
            print(f"Webhook handling error: {str(e)}")
            # Log error but don't raise to avoid webhook failures

# Global payment service instance
payment_service = PaymentService()