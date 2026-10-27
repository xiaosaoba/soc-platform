@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM ============================================================
REM  Wazuh Agent 一键安装脚本 (Windows)
REM  支持: Windows 7/8/10/11, Server 2012/2016/2019/2022
REM  Manager: 172.16.113.66
REM
REM  使用方法:
REM    右键 -> 以管理员身份运行
REM    或命令行: install_wazuh_agent.bat [Agent名称]
REM ============================================================

set "WAZUH_MANAGER=172.16.113.66"
set "WAZUH_VERSION=4.14.7"
set "AGENT_NAME=%~1"

REM 如果未指定Agent名称，使用计算机名
if "%AGENT_NAME%"=="" set "AGENT_NAME=%COMPUTERNAME%"

echo.
echo ==========================================
echo   Wazuh Agent 一键安装 (Windows)
echo   Manager : %WAZUH_MANAGER%
echo   版本    : %WAZUH_VERSION%
echo   Agent名 : %AGENT_NAME%
echo ==========================================
echo.

REM 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 请以管理员身份运行此脚本！
    echo 右键点击脚本 -> 以管理员身份运行
    pause
    exit /b 1
)

REM 检测系统架构
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "ARCH=64"
    set "MSI_URL=https://packages.wazuh.com/4.x/windows/wazuh-agent-%WAZUH_VERSION%-1.msi"
) else (
    set "ARCH=32"
    set "MSI_URL=https://packages.wazuh.com/4.x/windows/wazuh-agent-%WAZUH_VERSION%-1.msi"
)
echo [信息] 系统架构: %ARCH%位
echo [信息] 下载地址: %MSI_URL%
echo.

REM 设置下载路径
set "MSI_PATH=%TEMP%\wazuh-agent-%WAZUH_VERSION%.msi"

REM 检查是否已安装
sc query WazuhSvc >nul 2>&1
if %errorlevel% equ 0 (
    echo [警告] 检测到Wazuh Agent已安装
    set /p REINSTALL=是否覆盖重新安装? (y/N): 
    if /i not "!REINSTALL!"=="y" (
        echo [信息] 已取消安装
        pause
        exit /b 0
    )
    echo [信息] 正在卸载旧版本...
    msiexec /x {BFD56F2D-8D2B-4E6A-9F1E-2C3D4E5F6A7B} /qn /norestart >nul 2>&1
    sc stop WazuhSvc >nul 2>&1
    sc delete WazuhSvc >nul 2>&1
    timeout /t 3 /nobreak >nul
)

REM 下载安装包
echo [1/4] 正在下载Wazuh Agent安装包...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('%MSI_URL%', '%MSI_PATH%')"
if not exist "%MSI_PATH%" (
    echo [错误] 下载失败，请检查网络连接
    echo 尝试手动下载: %MSI_URL%
    pause
    exit /b 1
)
echo [信息] 下载完成: %MSI_PATH%
echo.

REM 静默安装
echo [2/4] 正在安装Wazuh Agent...
msiexec /i "%MSI_PATH%" /qn /norestart WAZUH_MANAGER="%WAZUH_MANAGER%" WAZUH_AGENT_NAME="%AGENT_NAME%" WAZUH_REGISTRATION_SERVER="%WAZUH_MANAGER%"
if %errorlevel% neq 0 (
    echo [错误] 安装失败，错误码: %errorlevel%
    pause
    exit /b 1
)
echo [信息] 安装完成
echo.

REM 等待安装完成并配置
timeout /t 5 /nobreak >nul

REM 确保配置文件中的Manager地址正确
echo [3/4] 配置Agent连接...
set "OSSEC_CONF=C:\Program Files (x86)\ossec-agent\ossec.conf"
if not exist "%OSSEC_CONF%" set "OSSEC_CONF=C:\Program Files\ossec-agent\ossec.conf"

if exist "%OSSEC_CONF%" (
    REM 使用PowerShell修改配置文件中的Manager地址
    powershell -Command "$c = Get-Content '%OSSEC_CONF%' -Raw; $c = $c -replace '<address>[^<]+</address>', '<address>%WAZUH_MANAGER%</address>'; Set-Content '%OSSEC_CONF%' -Value $c -NoNewline"
    echo [信息] 配置文件已更新
) else (
    echo [警告] 未找到配置文件，跳过配置修改
)

REM 启动服务
echo [4/4] 启动Wazuh Agent服务...
sc config WazuhSvc start= auto >nul 2>&1
net start WazuhSvc >nul 2>&1

timeout /t 3 /nobreak >nul

REM 验证安装
echo.
echo ==========================================
sc query WazuhSvc | findstr "STATE" >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=3" %%a in ('sc query WazuhSvc ^| findstr "STATE"') do set "SVC_STATE=%%a"
    if "!SVC_STATE!"=="RUNNING" (
        echo [成功] Wazuh Agent 安装并启动成功！
        echo.
        echo   服务状态 : 运行中
        echo   Agent名称: %AGENT_NAME%
        echo   Manager  : %WAZUH_MANAGER%
        echo.
        echo [信息] 在Manager上执行以下命令确认注册:
        echo   sudo /var/ossec/bin/agent_control -l
        echo.
        echo [信息] Agent日志路径:
        echo   C:\Program Files (x86)\ossec-agent\ossec.log
    ) else (
        echo [警告] 服务未运行，当前状态: !SVC_STATE!
        echo 请手动启动: net start WazuhSvc
    )
) else (
    echo [错误] 服务未找到，安装可能失败
    echo 请检查安装日志或手动安装
)
echo ==========================================
echo.

REM 清理临时文件
del "%MSI_PATH%" >nul 2>&1

pause
endlocal
