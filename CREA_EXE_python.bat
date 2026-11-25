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
    echo ERRORE: il comando "python" non e' disponibile.
    echo Verifica che Python sia installato e aggiunto al PATH di Windows.
    echo.
    pause
    exit /b 1
)

echo Controllo versione Python...
python --version
python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3,13) else 1)"
if errorlevel 1 (
    echo.
    echo ERRORE: serve Python 3.13 a 64 bit.
    echo Il comando "python" sta usando una versione diversa.
    echo Installa Python 3.13 e verifica che "python --version" mostri 3.13.x.
    echo.
    pause
    exit /b 1
)

if not exist "main.py" (
    echo ERRORE: non trovo main.py.
    echo Metti questo file BAT nella cartella principale del progetto BOOMER.
    echo.
    pause
    exit /b 1
)

if not exist "app.py" (
    echo ERRORE: non trovo app.py.
    echo Metti questo file BAT nella cartella principale del progetto BOOMER.
    echo.
    pause
    exit /b 1
)

if not exist ".env" (
    echo ERRORE: manca il file .env.
    echo Copia il file .env della versione funzionante in questa cartella,
    echo cioe' accanto ad app.py e main.py.
    echo.
    pause
    exit /b 1
)

if not exist "certificati\" (
    echo ATTENZIONE: non trovo la cartella certificati.
    echo Il programma potrebbe non riuscire a usare il certificato RENTRI.
    echo.
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
python -m PyInstaller --noconfirm --clean --windowed --onedir --name RENTRI_BOOMER --hidden-import=clr --hidden-import=uvicorn.logging --hidden-import=uvicorn.loops.auto --hidden-import=uvicorn.protocols.http.auto --hidden-import=uvicorn.lifespan.on --collect-all=webview --collect-all=fitz --collect-all=cryptography main.py
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
echo Il programma si trova qui:
echo dist\RENTRI_BOOMER\RENTRI_BOOMER.exe
echo.
echo IMPORTANTE: per usare il programma, conserva e distribuisci
echo tutta la cartella dist\RENTRI_BOOMER, non soltanto il file EXE.
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
echo Non cancellare la cartella build: puo' essere utile per capire il problema.
echo.
pause
exit /b 1
