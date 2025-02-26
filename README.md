# szu-edunet-autologin
自动登录深圳大学校园网  
适合没有显示器的服务器，或是远程桌面需要防掉线的主机用  
drcom适用宿舍区，srun适合1月升级后的教学区

25-02在粤海win10系统PS5.1 cscript5.812测试通过

# 用法

**Powershell**  
`./RegisterEduNet.ps1 <username> <b64password>`

>`b64password`是base64编码后的密码，用如下命令得到  
`[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('your-password-here'))`

**任务计划程序**  
`powershell -Command "& '<path-to-script>' '<username>' '<b64password>'"`

**iOS/macOS快捷指令（drcom）**  
网页->获取URL内容，URL：  
`http://172.30.255.42:801/eportal/portal/login?callback=dr1003&login_method=1&user_account=%2C0%2C<username>&user_password=<password>&wlan_user_ip=&wlan_user_ipv6=&wlan_user_mac=000000000000&wlan_ac_ip=&wlan_ac_name=&jsVersion=4.1.3&terminal_type=1&lang=zh-cn&v=3685&lang=zh`

# Linux?
`customTEA.js`最后的读参数和输出需要修改  
需要js引擎

>原来的drcom只要一个GET，现在的深澜srun有自制base64和TEA算法

# acid
不同地方可能不同，没有测试过
