"""
CHUAuthSDK 使用示例

SDK 提供四种登录方式：
1. login_interactive() - CLI 交互式登录（SDK 提供输入提示）
2. login(username, password) - 直接传入账号密码
3. login_batch(accounts) - 批量登录多个账号
4. login(username, password) - 错误三次触发验证码（示例）
"""

from CHUAuthSDK import CHUAuth, AuthError


def demo_interactive():
    """方式1：CLI 交互式登录"""
    print("\n=== 方式1：CLI 交互式登录 ===")
    
    # verbose=True 会在需要验证码时输出提示
    auth = CHUAuth(cookie_dir="cookies", enable_ocr=True, headless=False, verbose=True)
    
    try:
        # SDK 会自动提示输入账号密码
        session = auth.login_interactive()
        print("✓ 登录成功!")
        
        user_info = auth.get_user_info()
        print(f"欢迎, {user_info.get('cn', '[无法读取用户名]')}!")
    except AuthError as e:
        print(f"✗ 登录失败: {e}")


def demo_direct():
    """方式2：直接传入账号密码"""
    print("\n=== 方式2：直接传入账号密码 ===")
    
    # 直接传参时可控制是否启用 OCR、是否 headless、是否 verbose
    auth = CHUAuth(cookie_dir="cookies", enable_ocr=True, headless=False, verbose=True)
    
    username = "你的学工号"
    password = "你的密码"
    
    try:
        session = auth.login(username, password)
        print("✓ 登录成功!")
        
        user_info = auth.get_user_info()
        print(f"欢迎, {user_info.get('cn', '[无法读取用户名]')}!")
    except AuthError as e:
        print(f"✗ 登录失败: {e}")


def demo_batch():
    """方式3：批量登录多个账号"""
    print("\n=== 方式3：批量登录 ===")
    
    auth = CHUAuth(cookie_dir="cookies")
    
    # 方式3a：传入 JSON 字符串
    accounts_json = '''
    [
        {"username": "2025902416", "password": "Lemon@CHD"},
        {"username": "2021002", "password": "password2"}
    ]
    '''
    
    # 方式3b：传入 JSON 文件路径
    # accounts_json = "accounts.json"
    
    try:
        results = auth.login_batch(accounts_json)
        
        print("\n登录结果:")
        for username, result in results.items():
            status = "✓ 成功" if result["success"] else f"✗ 失败: {result['error']}"
            print(f"  {username}: {status}")
    except AuthError as e:
        print(f"✗ 批量登录失败: {e}")


def demo_trigger_captcha():
    """方式4：触发验证码"""
    print("\n=== 方式4：触发验证码 ===")
    
    auth = CHUAuth(cookie_dir="cookies", enable_ocr=True, headless=False, verbose=True)
    
    username = "你的学工号"
    wrong_password = "错误密码123"
    
    try:
        for i in range(1, 4):
            print(f"\n>>> 第{i}次登录...")
            try:
                auth.login(username, wrong_password)
                print("⚠️ 登录成功了，可能密码正确或已有会话，请检查登录状态。")
                break
            except AuthError as e:
                print(f"  登录失败: {e}")
                if i == 3:
                    print("已连续三次失败，系统应当触发验证码")
    except AuthError as e:
        print(f"✗ 登录过程中出现错误: {e}")


def main():
    print("CHUAuthSDK 登录方式演示")
    print("=" * 40)
    print("1. CLI 交互式登录")
    print("2. 直接传入账号密码")
    print("3. 批量登录多个账号")
    print("4. 触发验证码（错误三次）")
    print("=" * 40)
    
    choice = input("请选择登录方式 (1/2/3/4): ").strip()
    
    if choice == "1":
        demo_interactive()
    elif choice == "2":
        demo_direct()
    elif choice == "3":
        demo_batch()
    elif choice == "4":
        demo_trigger_captcha()
    else:
        print("无效选择")


if __name__ == "__main__":
    main()
