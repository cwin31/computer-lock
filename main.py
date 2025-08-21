import os
os.system("title 电脑锁定器")
print("电脑锁定器（by 一只野生的win31 bilibili）")
print("开源地址：https://github.com/cwin31/computer-lock")
print('请选择要执行的操作：' )
print("锁定电脑（1）    更改密码（2）")
print("请在输入后按回车继续，请勿输入其他非数字内容！（无需输入括号）")
do = int(input("请输入数字代号："))
if do == 1:
    # 打开文件（使用默认程序）
    os.startfile("start.exe")
elif do == 2:
    try:
        with open('password.txt', 'r') as file:
            content = file.read()
    except FileNotFoundError:
        print("密码未创建，请运行安装目录下“create.exe”（5秒后自动退出）")
        import time
        time.sleep(5)
        exit(0)
    hash = 0
    while(hash != content):
        hash = 0
        password = input("请输入原密码：")
        import hashlib
        # 转换为SHA-256
        hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if hash == content:
            newpassword = input("请输入新密码：")
            newhash = hashlib.sha256(newpassword.encode('utf-8')).hexdigest()
            with open('password.txt', 'w', encoding='utf-8') as file:
                file.write(newhash)
            print("密码修改完成！")
            input("按回车退出")
        else:
            print("密码错误！")



