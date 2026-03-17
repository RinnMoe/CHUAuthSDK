"""ddddocr 使用示例脚本

将会读取项目根目录下的 captcha_debug.png，并尝试识别其中的文字（适用于 4 位数字验证码）。

用法：
  python ddddocr_demo.py

注意：请确保已安装 ddddocr（pip install ddddocr）。
"""

import os

try:
    import ddddocr
except ImportError:
    raise SystemExit("请先安装 ddddocr: pip install ddddocr")


def main():
    path = os.path.abspath("captcha_debug.png")
    if not os.path.exists(path):
        raise SystemExit(f"文件不存在: {path}")

    with open(path, "rb") as f:
        img_bytes = f.read()

    ocr = ddddocr.DdddOcr(
                ocr=True,
                det=False,
                old=False,
                beta=False,
                use_gpu=False,
                show_ad=False,
            )
    res = None

    # 尝试最常见的识别接口
    if hasattr(ocr, "classification"):
        res = ocr.classification(img_bytes)
    elif hasattr(ocr, "ocr"):
        print("2")
        res = ocr.ocr(img_bytes)

    print(res)


if __name__ == "__main__":
    main()
