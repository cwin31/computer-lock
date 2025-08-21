import os

file_path = "password.txt"

def creatpassword():
    password = input("请输入您要创建的密码（输入后按回车）：")
    import hashlib
    # SHA-256
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    with open(file_path, "w") as file:
        file.write(sha256_hash)

if os.path.exists(file_path):
    print(f"密码已创建！请运行主程序更改密码！")
    input("按回车退出")
else:
    print(f"文件 {file_path} 不存在,将开始创建密码")
    creatpassword()
    input('操作完成！按回车退出')
    
