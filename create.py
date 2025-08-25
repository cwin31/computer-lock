import os
import tkinter as tk
from tkinter import messagebox, simpledialog
import hashlib

# 获取当前脚本所在目录
current_dir = os.path.dirname(os.path.abspath(__file__))

def create_password():
    """创建密码"""
    file_path = os.path.join(current_dir, "password.txt")
    
    if os.path.exists(file_path):
        messagebox.showinfo("提示", "密码已创建！请运行主程序更改密码。")
        return
        
    password = simpledialog.askstring("创建密码", "请输入新密码:", show='*')
    if not password:
        return
        
    confirm = simpledialog.askstring("确认密码", "请再次输入密码:", show='*')
    if not confirm:
        return
        
    if password != confirm:
        messagebox.showerror("错误", "两次输入的密码不一致！")
        return
        
    # SHA-256哈希
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    try:
        with open(file_path, "w", encoding='utf-8') as file:
            file.write(sha256_hash)
        messagebox.showinfo("成功", "密码创建成功！")
    except Exception as e:
        messagebox.showerror("错误", f"创建密码文件失败: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    create_password()
    
    root.destroy()
