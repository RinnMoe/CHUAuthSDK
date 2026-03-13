"""
CHUAuthSDK 异常定义
"""


class AuthError(Exception):
    """认证失败异常"""
    pass


class CaptchaRequiredError(AuthError):
    """需要验证码异常"""
    def __init__(self, captcha_image: bytes):
        self.captcha_image = captcha_image
        super().__init__("需要验证码")
