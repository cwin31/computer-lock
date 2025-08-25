import os
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog
import hashlib

# 获取当前脚本所在目录
current_dir = os.path.dirname(os.path.abspath(__file__))

def center_window(window, width=400, height=300):
    """将窗口居中显示"""
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")

def lock_computer():
    """锁定电脑"""
    try:
        start_path = os.path.join(current_dir, "start.exe")
        if os.path.exists(start_path):
            os.startfile(start_path)
            messagebox.showinfo("成功", "电脑锁定程序已启动！")
        else:
            messagebox.showerror("错误", "未找到start.exe文件")
    except Exception as e:
        messagebox.showerror("错误", f"启动锁定程序失败: {e}")

def change_password():
    """更改密码"""
    try:
        password_file = os.path.join(current_dir, 'password.txt')
        if not os.path.exists(password_file):
            messagebox.showerror("错误", "密码文件不存在，请先创建密码")
            return
            
        with open(password_file, 'r', encoding='utf-8') as file:
            stored_hash = file.read().strip()
        
        # 验证原密码
        old_password = simpledialog.askstring("验证原密码", "请输入原密码:", show='*')
        if not old_password:
            return
            
        old_hash = hashlib.sha256(old_password.encode('utf-8')).hexdigest()
        if old_hash != stored_hash:
            messagebox.showerror("错误", "原密码错误！")
            return
        
        # 设置新密码
        new_password = simpledialog.askstring("设置新密码", "请输入新密码:", show='*')
        if not new_password:
            return
            
        confirm_password = simpledialog.askstring("确认新密码", "请再次输入新密码:", show='*')
        if not confirm_password:
            return
            
        if new_password != confirm_password:
            messagebox.showerror("错误", "两次输入的密码不一致！")
            return
            
        new_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
        
        with open(password_file, 'w', encoding='utf-8') as file:
            file.write(new_hash)
            
        messagebox.showinfo("成功", "密码修改成功！")
    except Exception as e:
        messagebox.showerror("错误", f"修改密码失败: {e}")

def create_gui():
    """创建主界面GUI"""
    root = tk.Tk()
    root.title("电脑锁定器")
    root.geometry("500x350")
    root.resizable(False, False)
    root.configure(bg="#f0f0f0")
    center_window(root, 500, 350)
    
    # 设置图标（如果有）
    icon_path = os.path.join(current_dir, "lock.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    
    # 标题
    title_label = tk.Label(root, text="电脑锁定器", font=("Arial", 20, "bold"), bg="#f0f0f0", fg="#333333")
    title_label.pack(pady=20)
    
    # 作者信息
    author_label = tk.Label(root, text="by 一只野生的win31 - Bilibili", 
                           font=("Arial", 10), bg="#f0f0f0", fg="#666666")
    author_label.pack(pady=5)
    
    # 开源地址
    github_label = tk.Label(root, text="开源地址: https://github.com/cwin31/computer-lock", 
                           font=("Arial", 9), bg="#f0f0f0", fg="#0066cc", cursor="hand2")
    github_label.pack(pady=5)
    
    # 绑定点击事件
    def open_url(event):
        import webbrowser
        webbrowser.open("https://github.com/cwin31/computer-lock")
    
    github_label.bind("<Button-1>", open_url)
    
    # 功能框架
    frame = tk.Frame(root, bg="#f0f0f0")
    frame.pack(pady=20)
    
    # 锁定按钮
    lock_btn = tk.Button(frame, text="锁定电脑", command=lock_computer, 
                        font=("Arial", 14), bg="#ff6b6b", fg="white", 
                        width=15, height=2)
    lock_btn.grid(row=0, column=0, padx=10, pady=10)
    
    # 更改密码按钮
    pwd_btn = tk.Button(frame, text="更改密码", command=change_password, 
                       font=("Arial", 14), bg="#4ecdc4", fg="white", 
                       width=15, height=2)
    pwd_btn.grid(row=0, column=1, padx=10, pady=10)
    
    # 创建密码按钮（如果不存在密码文件）
    password_file = os.path.join(current_dir, 'password.txt')
    if not os.path.exists(password_file):
        create_btn = tk.Button(root, text="创建密码", command=create_password, 
                              font=("Arial", 12), bg="#45b7d1", fg="white", 
                              width=12, height=1)
        create_btn.pack(pady=10)
    
    # 退出按钮
    exit_btn = tk.Button(root, text="退出", command=root.quit, 
                        font=("Arial", 10), bg="#999999", fg="white", 
                        width=10, height=1)
    exit_btn.pack(pady=20)
    
    root.mainloop()

def create_password():
    """创建密码"""
    try:
        password_file = os.path.join(current_dir, 'password.txt')
        if os.path.exists(password_file):
            messagebox.showinfo("提示", "密码已存在，请使用\"更改密码\"功能")
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
            
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        with open(password_file, 'w', encoding='utf-8') as file:
            file.write(password_hash)
            
        messagebox.showinfo("成功", "密码创建成功！")
    except Exception as e:
        messagebox.showerror("错误", f"创建密码失败: {e}")

if __name__ == "__main__":
    create_gui()
