@echo off
rem Mutolaxona saytini Netlify ga joylash. Node.js o`rnatilgan bo`lishi kerak: https://nodejs.org
cd /d "%~dp0"
call npm install
if errorlevel 1 goto fail
call npx --yes netlify-cli deploy --prod
if errorlevel 1 goto fail
echo.
echo Tayyor. Yuqoridagi "Website URL" - saytingiz manzili.
pause
exit /b 0
:fail
echo.
echo Xato chiqdi. Yuqoridagi matnni nusxalab oling.
pause
exit /b 1
