@echo off
setlocal
set "APPDIR=D:\projects\dvc_api"

rem อ่านเวอร์ชันจาก .nvmrc
for /f "usebackq delims=" %%v in ("%APPDIR%\.nvmrc") do set NODEVER=%%v
call "C:\Program Files\nvm\nvm" use %NODEVER%

set PORT=4001
set NODE_ENV=production

cd /d %APPDIR%
npm run start