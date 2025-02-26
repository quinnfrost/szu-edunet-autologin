# szu-edunet-autologin
自动登录深圳大学校园网  
适合没有显示器的服务器，或是远程桌面需要防掉线的主机用 

25-2在粤海win10系统PS5.1 cscript5.812测试通过

# 用法

Powershell  
`./RegisterEduNet.ps1 <username> <b64password>`

>`b64password`是base64编码后的密码，用如下命令得到  
`[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('your-password-here'))`

任务计划程序  
`powershell -Command "& '<path-to-script>' '<username>' '<b64password>'"`

# Linux?
`customTEA.js`最后的读参数和输出需要修改  
需要js引擎

>原来的drcom只要一个GET，现在的深澜srun有自制base64和TEA算法
