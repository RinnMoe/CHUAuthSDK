# CHUAuthSDK

CHU统一身份认证 Python SDK

## 安装

```bash
pip install -r requirements.txt
```

## 快速开始

```python
from CHUAuthSDK import CHUAuth, CaptchaRequiredError

# 创建认证客户端
auth = CHUAuth(cookie_dir="cookies")

try:
    # 登录
    session = auth.login("你的学工号", "你的密码")
    
    # 获取用户信息
    user_info = auth.get_user_info()
    print(f"欢迎, {user_info['cn']}!")
    
    # 使用 session 访问需要认证的资源
    resp = session.get("https://course-online.chd.edu.cn/api/radar/rollcalls")
    print(resp.json())
    
except CaptchaRequiredError as e:
    # 需要验证码（如果tkinter可用会自动弹出窗口）
    print("需要验证码")
    if not e.captcha_image:
        # tkinter窗口已显示，用户取消了输入
        print("用户取消了验证码输入")
    else:
        # tkinter不可用，保存图片文件
        with open("captcha.png", "wb") as f:
            f.write(e.captcha_image)
        print("请查看 captcha.png 并输入验证码")
        
        # 获取验证码后重新登录
        captcha_code = input("请输入验证码: ")
        session = auth.login("你的学工号", "你的密码", captcha=captcha_code)
    
except Exception as e:
    print(f"登录失败: {e}")
```

## API 文档

### CHUAuth

#### 初始化参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `cas_url` | `str` | `https://ids.chd.edu.cn` | 统一身份认证服务器地址 |
| `cookie_dir` | `Optional[str]` | `None` | Cookie 存储目录，None 则不持久化。传入目录路径启用持久化，cookie 文件统一存放在该目录下，自动命名为 "cookies_{username}.json"。例如传入 "cookies" 会生成 "cookies/cookies_2021001.json" |

#### 登录方法

SDK 提供三种登录方式

##### 1. `login(username, password, captcha=None, force_relogin=False)`

直接传入账号密码登录。

**参数:**
- `username`: 用户名（学工号/手机号）
- `password`: 密码
- `captcha`: 验证码（可选）
- `force_relogin`: 强制重新登录

**返回:** `requests.Session` - 已认证的会话对象

**示例:**
```python
auth = CHUAuth(cookie_dir="cookies")
session = auth.login("2021001", "password")
```

##### 2. `login_interactive()`

CLI 交互式登录，SDK 自动提示用户输入账号密码。

**返回:** `requests.Session` - 已认证的会话对象

**示例:**
```python
auth = CHUAuth(cookie_dir="cookies")
session = auth.login_interactive()  # 提示输入账号密码
```

##### 3. `login_batch(accounts_json)`

批量登录多个账号。

**参数:**
- `accounts_json`: JSON 字符串或 JSON 文件路径
  ```json
  [
    {"username": "2021001", "password": "password1"},
    {"username": "2021002", "password": "password2"}
  ]
  ```

**返回:** `Dict[str, Any]` - 登录结果字典
```python
{
    "2021001": {"success": True, "session": <Session>, "error": None},
    "2021002": {"success": False, "session": None, "error": "密码错误"}
}
```

**示例:**
```python
auth = CHUAuth(cookie_dir="cookies")

# 传入 JSON 字符串
results = auth.login_batch('[{"username": "2021001", "password": "pwd"}]')

# 或传入 JSON 文件路径
results = auth.login_batch("accounts.json")
```

#### 其他方法

##### `get_user_info()`

获取当前用户信息。

**返回:** `Dict[str, Any]` - 用户信息字典

##### `get_cookies_dict()`

获取 cookies 字典。

**返回:** `Dict[str, str]`

##### `get_session_id()`

获取 session ID。

**返回:** `Optional[str]`

##### `logout()`

登出并清除会话。

### 异常

#### `AuthError`

认证失败异常基类。

#### `CaptchaRequiredError`

需要验证码异常。

**属性:**
- `captcha_image`: `bytes` - 验证码图片数据

## 配置说明

### 统一身份认证服务器地址

默认: `https://ids.chd.edu.cn`

- 登录相关API使用 `/authserver` 路径（如 `https://ids.chd.edu.cn/authserver/login`）
- 用户信息API使用 `/personalInfo` 路径（如 `https://ids.chd.edu.cn/personalInfo/common/getUserConf`）


## License

MIT
