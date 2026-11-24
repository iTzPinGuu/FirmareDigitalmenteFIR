RENTRI Integration & USB Signer - Truccolo Production

Applicazione web e client API per la gestione, la firma digitale (tramite token/smartcard USB o certificato) e l'invio dei registri di carico/scarico e FIR al sistema RENTRI (Registro Elettronico Nazionale per la Tracciabilità dei Rifiuti).

📁 Struttura del Progetto

app.py: Applicazione principale (backend/server web e gestione delle rotte/interfacce).

rentri_client.py: Client per la comunicazione con le API ufficiali RENTRI (autenticazione JWT, invio dati, consultazione registri).

usb_signer.py: Modulo dedicato all'interfacciamento con dispositivi di firma digitale (PKCS#11 / Smartcard / Token USB) per la generazione dei token di autenticazione e la firma dei documenti.

ISTRUZIONI.txt: Note rapide di avvio.

(Nota: I file sensibili come .env e i certificati/chiavi private sono esclusi dal repository per motivi di sicurezza).

⚙️ Requisiti di Sistema

Python: versione 3.9 o superiore.

Driver Smartcard / Token USB: Driver PKCS#11 del produttore del dispositivo di firma installati correttamente sul sistema operativo (es. Aruba, InfoCert, Namirial, Bit4id).

Certificati RENTRI: Certificato di interoperabilità/autenticazione rilasciato dal portale RENTRI (formato .p12, .pfx o coppia .crt/.key) oppure dispositivo fisico configurato.

🚀 Installazione

Clona o estrai il progetto nella directory desiderata:

cd rentri_truccolo_production


Crea un ambiente virtuale (consigliato):

python -m venv venv


Attiva l'ambiente virtuale:

Windows: venv\Scripts\activate

Linux/macOS: source venv/bin/activate

Installa le dipendenze:
(Assicurati di installare le librerie utilizzate nel progetto, ad esempio flask/fastapi, requests, pyjwt, cryptography, PyKCS11):

pip install flask requests pyjwt cryptography PyKCS11 python-dotenv


🔐 Configurazione (.env e Certificati)

Prima di avviare l'applicazione, è necessario ricreare nella root del progetto la struttura per i certificati e il file di configurazione delle variabili d'ambiente.

1. Posizionamento Certificati

Crea una cartella certs/ (o il percorso configurato nel tuo codice) nella root del progetto e inserisci al suo interno i certificati scaricati dall'area riservata RENTRI:

rentri_truccolo_production/
├── certs/
│   ├── certificato_rentri.p12   # Oppure .crt / .pem
│   └── ...
├── .env
├── app.py
├── rentri_client.py
└── usb_signer.py


2. Creazione del file .env

Crea un file chiamato .env nella directory principale e compila i parametri richiesti dall'ambiente (Demo/Produzione):

# Ambiente RENTRI (DEMO o PROD)
RENTRI_ENV=PROD
RENTRI_BASE_URL=https://api.rentri.gov.it

# Dati Soggetto / Azienda
RENTRI_ISSUER=CODICE_FISCALE_O_IDENTIFICATIVO_ENTE
RENTRI_AUDIENCE=rentri.gov.it

# Configurazione Certificato Software (se utilizzato al posto o in aggiunta al token USB)
CERT_PATH=./certs/certificato_rentri.p12
CERT_PASSWORD=la_tua_password_certificato

# Configurazione Firma USB / PKCS#11
PKCS11_LIB_PATH=C:/Windows/System32/bit4xpki.dll  # Percorso della libreria .dll/.so del lettore
USB_PIN=12345678                                  # PIN della smartcard/token (se non inserito a runtime)

# Configurazione Applicazione Web
FLASK_ENV=production
FLASK_DEBUG=0
SECRET_KEY=chiave_segreta_casuale_per_sessioni
PORT=5000


(Adatta i nomi delle variabili d'ambiente in base a quelle effettivamente richiamate tramite os.getenv() in app.py, rentri_client.py e usb_signer.py).

▶️ Avvio dell'Applicazione

Assicurati che il token USB / Smartcard sia inserito e riconosciuto dal sistema (se previsto dal flusso di firma).

Avvia l'applicazione principale:

python app.py


Apri il browser e raggiungi l'indirizzo indicato a terminale (es. http://127.0.0.1:5000).
