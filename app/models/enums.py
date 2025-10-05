# models/enums.py
from enum import Enum

class SubscriptionPlan(Enum):
    TRIAL = "trial"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"

class BillingCycle(Enum):
    MONTHLY = "monthly"
    ANNUAL = "annual"
    TRIAL = "trial"

class SubscriptionStatus(Enum):
    TRIAL = "trial"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELLED = "cancelled"
    SUSPENDED = "suspended"

class IntegrationStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"

class NotificationType(Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    SMS = "sms"
    PUSH = "push"

class EventType(Enum):
    PRODUCT_VERIFICATION = "product_verification"
    COUNTERFEIT_DETECTED = "counterfeit_detected"
    PRODUCT_REGISTERED = "product_registered"
    OWNERSHIP_TRANSFERRED = "ownership_transferred"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    SUBSCRIPTION_UPDATED = "subscription_updated"
    TRIAL_EXPIRING = "trial_expiring"

class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"