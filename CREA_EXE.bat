@echo off
setlocal
cd /d "%~dp0"
title Creazione RENTRI BOOMER

echo.
echo ======================================================
echo             CREAZIONE EXE - RENTRI BOOMER
echo ======================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo ERRORE: Windows non trova il comando "python".
    echo Installa Python 3.13 e seleziona "Add Python to PATH" durante l'installazione.
    echo.
    pause
    exit /b 1
)

python --version
python -c "import sys; sys.exit(0 if sys.version_info[:2] == (3,13) else 1)"
if errorlevel 1 (
    echo ERRORE: serve Python 3.13. Il comando python sta usando una versione diversa.
    echo Verifica con: python --version
    echo.
    pause
    exit /b 1
)

if not exist ".env" (
    echo ERRORE: manca il file .env.
    echo Copia il file .env della versione funzionante in questa cartella,
    echo accanto ad app.py e main.py.
    echo.
    pause
    exit /b 1
)

if not exist "certificati\" (
    echo ATTENZIONE: non trovo la cartella certificati.
    echo Il programma potrebbe non riuscire a usare il certificato RENTRI.
    echo.
)

if not exist "qr_hub.py" (
    echo ERRORE: manca qr_hub.py. Riestrai lo ZIP completo prima di compilare.
    echo.
    pause
    exit /b 1
)

echo [1/4] Aggiornamento strumenti di installazione...
python -m pip install --upgrade pip
if errorlevel 1 goto errore

echo.
echo [2/4] Installazione delle librerie necessarie...
python -m pip install fastapi uvicorn httpx PyMuPDF Pillow pydantic python-dotenv cryptography PyJWT pywebview pyinstaller
if errorlevel 1 goto errore

echo.
echo [3/4] Creazione del programma EXE...
python -m PyInstaller --noconfirm --clean --windowed --onedir --name RENTRI_BOOMER --hidden-import=qr_hub --hidden-import=clr --hidden-import=uvicorn.logging --hidden-import=uvicorn.loops.auto --hidden-import=uvicorn.protocols.http.auto --hidden-import=uvicorn.lifespan.on --collect-all=webview --collect-all=fitz --collect-all=cryptography main.py
if errorlevel 1 goto errore

echo.
echo [4/4] Copia configurazione e certificati nella cartella EXE...
if not exist "dist\RENTRI_BOOMER" mkdir "dist\RENTRI_BOOMER"
copy /Y ".env" "dist\RENTRI_BOOMER\.env" >nul
if exist "certificati\" (
    if exist "dist\RENTRI_BOOMER\certificati" rmdir /S /Q "dist\RENTRI_BOOMER\certificati"
    xcopy "certificati" "dist\RENTRI_BOOMER\certificati\" /E /I /H /Y >nul
)

echo.
echo ======================================================
echo COMPILAZIONE COMPLETATA!
echo ======================================================
echo.
echo Programma: dist\RENTRI_BOOMER\RENTRI_BOOMER.exe
echo Distribuisci tutta la cartella dist\RENTRI_BOOMER, non soltanto l'EXE.
echo.
explorer "%CD%\dist\RENTRI_BOOMER"
pause
exit /b 0

:errore
echo.
echo ======================================================
echo ERRORE DURANTE LA COMPILAZIONE
echo ======================================================
echo Leggi il messaggio di errore qui sopra e fai uno screenshot.
echo Non cancellare la cartella build.
echo.
pause
exit /b 1
