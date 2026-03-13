"""
CHUAuthSDK - CHU统一身份认证 SDK
"""

from .auth import CHUAuth
from .exceptions import AuthError, CaptchaRequiredError

__version__ = "1.0.0"
__all__ = ["CHUAuth", "AuthError", "CaptchaRequiredError"]
