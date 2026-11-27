@echo off
setlocal
set TABLET_IP=192.168.1.11
set PC_IP=192.168.1.70
set PORT=8766

title Configurazione Firewall - RENTRI BOOMER QR Tablet

net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Per configurare il firewall servono i permessi di amministratore.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo Creo una regola privata limitata alla rete locale.
echo Tablet autorizzato: %TABLET_IP%
echo PC centrale: %PC_IP% - Porta: %PORT%
echo Gli IP dei PC mittenti vengono verificati dall'applicazione tramite RENTRI_TABLET_SENDER_IPS nel file .env.
echo.

netsh advfirewall firewall delete rule name="RENTRI BOOMER - QR Tablet" >nul 2>nul
netsh advfirewall firewall add rule name="RENTRI BOOMER - QR Tablet" dir=in action=allow protocol=TCP localip=%PC_IP% localport=%PORT% remoteip=LocalSubnet profile=private
if errorlevel 1 (
    echo.
    echo ERRORE: Windows non ha creato la regola firewall.
    echo Controlla che PC e tablet usino gli IP indicati nel file.
    pause
    exit /b 1
)

echo.
echo REGOLA CREATA.
echo La porta 8766 accetta connessioni soltanto dalla rete privata locale.
echo L'applicazione consente la pagina QR solo al tablet %TABLET_IP% e i comandi solo ai PC elencati in RENTRI_TABLET_SENDER_IPS.
echo Se l'IP del PC cambia, modifica questo file e ripetilo.
echo.
pause
