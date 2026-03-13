"""
CHUAuthSDK - CHU统一身份认证核心模块
"""

import json
import os
import time
import base64
import random
import logging
from typing import Optional, Dict, List, Any
from io import BytesIO

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from .exceptions import AuthError, CaptchaRequiredError

# 尝试导入tkinter，如果失败则设为None
try:
    import tkinter as tk
    from tkinter import ttk
    from PIL import Image, ImageTk
    TKINTER_AVAILABLE = True
except ImportError:
    tk = None  # type: ignore
    ttk = None  # type: ignore
    Image = None  # type: ignore
    ImageTk = None  # type: ignore
    TKINTER_AVAILABLE = False

logger = logging.getLogger("CHUAuthSDK")

# 默认配置
DEFAULT_CAS_URL = "https://ids.chd.edu.cn"


def _random_string(n: int) -> str:
    """生成随机字符串"""
    aes_chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
    return "".join(random.choice(aes_chars) for _ in range(n))


def _encrypt_password(password: str, salt: str) -> str:
    """AES 加密密码"""
    raw = (_random_string(64) + password).encode("utf-8")
    key = salt.encode("utf-8")
    iv = _random_string(16).encode("utf-8")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(raw, AES.block_size))
    return base64.b64encode(encrypted).decode()


class CHUAuth:
    """
    CHU统一身份认证客户端
    
    使用示例:
        auth = CHUAuth()
        session = auth.login("username", "password")
        
        # 使用 session 访问需要认证的资源
        user_info = auth.get_user_info()
    """
    
    def __init__(
        self,
        cas_url: str = DEFAULT_CAS_URL,
        cookie_dir: Optional[str] = None
    ):
        """
        初始化认证客户端
        
        Args:
            cas_url: CAS 认证服务器地址
            cookie_dir: Cookie 存储目录，None 则不持久化。
                        传入目录路径启用持久化，cookie 文件统一存放在该目录下，
                        自动命名为 cookies_{username}.json
                        例如: "cookies" 或 "/path/to/cookies"
        """
        self.cas_url = cas_url.rstrip("/")
        self.cookie_dir = cookie_dir
        self._session: Optional[requests.Session] = None
        self._current_username: Optional[str] = None
    
    @property
    def session(self) -> requests.Session:
        """获取当前会话，未登录时抛出异常"""
        if self._session is None:
            raise AuthError("尚未登录，请先调用 login() 方法")
        return self._session
    
    def _get_cookie_file(self, username: str) -> Optional[str]:
        """获取指定账号的 cookie 文件路径"""
        if not self.cookie_dir:
            return None
        os.makedirs(self.cookie_dir, exist_ok=True)
        return os.path.join(self.cookie_dir, f"cookies_{username}.json")
    
    def _save_cookies(self, session: requests.Session, username: str) -> None:
        """保存 cookies 到文件（按账号）"""
        cookie_file = self._get_cookie_file(username)
        if not cookie_file:
            return
        try:
            cookies = [
                {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
                for c in session.cookies
            ]
            with open(cookie_file, "w", encoding="utf-8") as f:
                json.dump(cookies, f, ensure_ascii=False, indent=2)
            logger.debug(f"Cookies 已保存到 {cookie_file}")
        except Exception as e:
            logger.warning(f"保存 Cookies 失败: {e}")
    
    def _load_cookies(self, username: str) -> Optional[requests.Session]:
        """从文件加载 cookies（按账号）"""
        cookie_file = self._get_cookie_file(username)
        if not cookie_file or not os.path.exists(cookie_file):
            return None
        try:
            with open(cookie_file, encoding="utf-8") as f:
                cookies_list = json.load(f)
            
            session = requests.Session()
            for c in cookies_list:
                session.cookies.set(
                    c.get("name"),
                    c.get("value"),
                    domain=c.get("domain"),
                    path=c.get("path", "/")
                )
            logger.debug(f"从 {cookie_file} 加载 Cookies")
            return session
        except Exception as e:
            logger.warning(f"加载 Cookies 失败: {e}")
            return None
    
    def _check_cookies_valid(self, session: requests.Session) -> bool:
        """检查 cookies 是否有效"""
        try:
            # 用户信息API不包含authserver路径
            resp = session.get(f"{self.cas_url}/personalInfo/common/getUserConf", timeout=10)
            if not resp.ok:
                return False
            data = resp.json()
            return data.get("code") == "0" and data.get("message") == "SUCCESS"
        except Exception:
            return False
    
    def _check_captcha(self, username: str, session: requests.Session) -> Optional[bytes]:
        """
        检查是否需要验证码
        
        Returns:
            None: 不需要验证码
            bytes: 验证码图片数据
        """
        try:
            _time = int(time.time() * 1000)
            resp = session.get(
                f"{self.cas_url}/authserver/checkNeedCaptcha.htl",
                params={"username": username, "_": _time},
                timeout=10
            )
            data = resp.json()
            
            if data.get("isNeed"):
                logger.info("需要验证码")
                captcha_resp = session.get(
                    f"{self.cas_url}/authserver/getCaptcha.htl",
                    params={"_": _time},
                    timeout=10
                )
                return captcha_resp.content
            return None
        except Exception as e:
            logger.warning(f"检查验证码失败: {e}")
            return None
    
    def _show_captcha_window(self, captcha_image: bytes) -> Optional[str]:
        """
        显示验证码窗口
        
        Args:
            captcha_image: 验证码图片数据
            
        Returns:
            用户输入的验证码，如果用户取消则返回None
        """
        if not TKINTER_AVAILABLE:
            logger.warning("tkinter或PIL不可用，无法显示验证码窗口")
            return None
        
        captcha_text = None
        
        def on_submit():
            nonlocal captcha_text
            captcha_text = entry.get().strip()
            root.destroy()
        
        def on_cancel():
            nonlocal captcha_text
            captcha_text = None
            root.destroy()
        
        # 创建窗口
        root = tk.Tk()  # type: ignore[union-attr]
        root.title("请输入验证码")
        root.geometry("300x200")
        root.resizable(False, False)
        
        # 居中显示
        root.eval('tk::PlaceWindow . center')
        
        # 显示验证码图片
        try:
            image = Image.open(BytesIO(captcha_image))  # type: ignore[union-attr]
            photo = ImageTk.PhotoImage(image)  # type: ignore[union-attr]
            
            image_label = ttk.Label(root, image=photo)  # type: ignore[union-attr]
            image_label.image = photo  # type: ignore[attr-defined]  # 保持引用
            image_label.pack(pady=10)
        except Exception as e:
            logger.error(f"显示验证码图片失败: {e}")
            ttk.Label(root, text="无法显示验证码图片").pack(pady=10)  # type: ignore[union-attr]
        
        # 输入框
        entry_frame = ttk.Frame(root)  # type: ignore[union-attr]
        entry_frame.pack(pady=5)
        
        ttk.Label(entry_frame, text="验证码:").pack(side=tk.LEFT, padx=5)  # type: ignore[union-attr]
        entry = ttk.Entry(entry_frame, width=15)  # type: ignore[union-attr]
        entry.pack(side=tk.LEFT, padx=5)  # type: ignore[union-attr]
        entry.focus()
        
        # 按钮
        button_frame = ttk.Frame(root)  # type: ignore[union-attr]
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="确定", command=on_submit).pack(side=tk.LEFT, padx=5)  # type: ignore[union-attr]
        ttk.Button(button_frame, text="取消", command=on_cancel).pack(side=tk.LEFT, padx=5)  # type: ignore[union-attr]
        
        # 绑定回车键
        entry.bind('<Return>', lambda e: on_submit())
        
        # 运行窗口
        root.mainloop()
        
        return captcha_text
    
    def _cas_login(
        self,
        username: str,
        password: str,
        captcha: Optional[str] = None
    ) -> requests.Session:
        """
        执行 CAS 登录
        
        Args:
            username: 用户名
            password: 密码
            captcha: 验证码（如果需要）
            
        Returns:
            登录成功后的 Session
            
        Raises:
            AuthError: 登录失败
            CaptchaRequiredError: 需要验证码
        """
        session = requests.Session()
        
        # 获取登录页面
        try:
            resp = session.get(f"{self.cas_url}/authserver", timeout=15)
            resp.raise_for_status()
        except Exception as e:
            raise AuthError(f"无法访问 CAS 服务器: {e}")
        
        # 解析登录表单
        soup = BeautifulSoup(resp.text, "html.parser")
        
        try:
            lt = soup.find("input", {"name": "lt"})["value"]  # type: ignore
            execution = soup.find("input", {"name": "execution"})["value"]  # type: ignore
            salt = soup.find("input", {"id": "pwdEncryptSalt"})["value"]  # type: ignore
        except (TypeError, KeyError) as e:
            raise AuthError(f"解析登录表单失败: {e}")
        
        # 检查验证码
        captcha_image = self._check_captcha(username, session)
        if captcha_image and not captcha:
            # 尝试使用图形界面显示验证码
            if TKINTER_AVAILABLE:
                captcha = self._show_captcha_window(captcha_image)
                if captcha is None:
                    raise CaptchaRequiredError(captcha_image)
            else:
                raise CaptchaRequiredError(captcha_image)
        
        # 加密密码
        encrypted_pwd = _encrypt_password(password, salt)  # type: ignore
        
        # 提交登录
        data = {
            "username": username,
            "password": encrypted_pwd,
            "captcha": captcha or "",
            "lt": lt,
            "dllt": "generalLogin",
            "cllt": "userNameLogin",
            "execution": execution,
            "_eventId": "submit",
        }
        
        try:
            resp = session.post(
                f"{self.cas_url}/authserver/login",
                data=data,
                allow_redirects=True,
                timeout=15
            )
        except Exception as e:
            raise AuthError(f"登录请求失败: {e}")
        
        # 检查登录结果
        if any(err in resp.text for err in ["统一身份认证", "密码错误", "登录失败"]):
            raise AuthError("用户名或密码错误")
        
        logger.info("CAS 登录成功")
        return session
    
    def login(
        self,
        username: str,
        password: str,
        captcha: Optional[str] = None,
        force_relogin: bool = False
    ) -> requests.Session:
        """
        登录到CHU统一身份认证系统
        
        Args:
            username: 用户名（学工号/手机号）
            password: 密码
            captcha: 验证码（如果之前抛出了 CaptchaRequiredError）
            force_relogin: 强制重新登录，忽略缓存的 cookies
            
        Returns:
            已认证的 requests.Session 对象
            
        Raises:
            AuthError: 登录失败
            CaptchaRequiredError: 需要验证码，需获取 captcha_image 并让用户输入后重试
        """
        # 尝试使用缓存的 cookies（按账号）
        if not force_relogin:
            cached_session = self._load_cookies(username)
            if cached_session and self._check_cookies_valid(cached_session):
                logger.info("使用缓存的 Cookies 登录成功")
                self._session = cached_session
                return cached_session
            else:
                logger.debug("缓存的 Cookies 无效，重新登录")
        
        # 执行 CAS 登录
        session = self._cas_login(username, password, captcha)
        
        # 保存 cookies（按账号）
        self._save_cookies(session, username)
        
        self._session = session
        self._current_username = username
        return session
    
    def login_interactive(self) -> requests.Session:
        """
        交互式登录：通过命令行提示用户输入账号密码
        
        流程：
        1. 输入账号
        2. 自动检查是否有缓存的 cookies
        3. 如果 cookies 有效，直接登录成功，无需输入密码
        4. 如果 cookies 无效，提示输入密码
        
        Returns:
            已认证的 requests.Session 对象
            
        Raises:
            AuthError: 登录失败
        """
        print("=" * 40)
        print("CHU统一身份认证登录")
        print("=" * 40)
        
        username = input("请输入学工号/手机号: ").strip()
        if not username:
            raise AuthError("账号不能为空")
        
        # 尝试使用缓存的 cookies 登录
        cached_session = self._load_cookies(username)
        if cached_session and self._check_cookies_valid(cached_session):
            print("✓ 检测到有效 cookies，自动登录成功!")
            self._session = cached_session
            self._current_username = username
            return cached_session
        
        # cookies 无效或不存在，需要输入密码
        print("未找到有效 cookies，需要输入密码")
        password = input("请输入密码: ").strip()
        if not password:
            raise AuthError("密码不能为空")
        
        try:
            return self.login(username, password)
        except CaptchaRequiredError as e:
            # 尝试使用图形界面显示验证码
            if TKINTER_AVAILABLE:
                captcha = self._show_captcha_window(e.captcha_image)
                if captcha is None:
                    raise AuthError("用户取消了验证码输入")
                return self.login(username, password, captcha=captcha)
            else:
                # 回退到保存图片文件的方式
                print("需要验证码，请查看 captcha.png")
                with open("captcha.png", "wb") as f:
                    f.write(e.captcha_image)
                
                captcha = input("请输入验证码: ").strip()
                return self.login(username, password, captcha=captcha)
    
    def login_batch(self, accounts_json: str) -> Dict[str, Any]:
        """
        批量登录：传入包含多个账号密码的 JSON 字符串或文件路径
        
        Args:
            accounts_json: JSON 字符串或 JSON 文件路径
                格式示例:
                [
                    {"username": "2021001", "password": "password1"},
                    {"username": "2021002", "password": "password2"}
                ]
                或文件路径: "accounts.json"
                
        Returns:
            登录结果字典，key 为账号，value 为登录结果
            {
                "2021001": {"success": True, "session": <Session>, "error": None},
                "2021002": {"success": False, "session": None, "error": "密码错误"}
            }
        """
        # 解析输入：可能是 JSON 字符串或文件路径
        accounts = None
        
        # 尝试作为文件路径读取
        if os.path.exists(accounts_json):
            try:
                with open(accounts_json, "r", encoding="utf-8") as f:
                    accounts = json.load(f)
                logger.info(f"从文件加载账号列表: {accounts_json}")
            except Exception as e:
                raise AuthError(f"读取账号文件失败: {e}")
        else:
            # 尝试作为 JSON 字符串解析
            try:
                accounts = json.loads(accounts_json)
            except json.JSONDecodeError as e:
                raise AuthError(f"账号列表格式错误: {e}")
        
        if not isinstance(accounts, list):
            raise AuthError("账号列表必须是数组格式")
        
        results = {}
        
        for i, account in enumerate(accounts):
            username = account.get("username")
            password = account.get("password")
            
            if not username or not password:
                results[username or f"unknown_{i}"] = {
                    "success": False,
                    "session": None,
                    "error": "缺少 username 或 password"
                }
                continue
            
            logger.info(f"正在登录账号 {i+1}/{len(accounts)}: {username}")
            
            try:
                session = self.login(username, password)
                results[username] = {
                    "success": True,
                    "session": session,
                    "error": None
                }
                logger.info(f"账号 {username} 登录成功")
            except CaptchaRequiredError:
                results[username] = {
                    "success": False,
                    "session": None,
                    "error": "需要验证码，批量登录不支持验证码"
                }
                logger.warning(f"账号 {username} 需要验证码，跳过")
            except AuthError as e:
                results[username] = {
                    "success": False,
                    "session": None,
                    "error": str(e)
                }
                logger.error(f"账号 {username} 登录失败: {e}")
        
        return results
    
    def get_cookies_dict(self) -> Dict[str, str]:
        """获取 cookies 字典"""
        return {c.name: c.value for c in self.session.cookies}  # type: ignore
    
    def get_session_id(self) -> Optional[str]:
        """获取 session ID"""
        return self.session.cookies.get("session")
    
    def get_user_info(self) -> Dict[str, Any]:
        """
        获取当前用户信息
        
        Returns:
            用户信息字典，包含 uid, cn(姓名), nickName 等字段
        """
        # 用户信息API不包含authserver路径
        resp = self.session.get(f"{self.cas_url}/personalInfo/common/getUserConf", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != "0" or data.get("message") != "SUCCESS":
            raise AuthError(f"获取用户信息失败: {data.get('message', '未知错误')}")
        return data.get("datas", {})
    
    def logout(self) -> None:
        """登出并清除会话"""
        if self._session:
            self._session.close()
            self._session = None
        
        # 删除当前账号的缓存 cookies
        if self._current_username:
            cookie_file = self._get_cookie_file(self._current_username)
            if cookie_file and os.path.exists(cookie_file):
                try:
                    os.remove(cookie_file)
                    logger.debug(f"已删除缓存的 Cookies: {cookie_file}")
                except Exception:
                    pass
        
        self._current_username = None
        logger.info("已登出")
