# 🛡️ GajDefender

**GajDefender** is an AI-powered malware detection system capable of analyzing a wide range of file formats using classical ML, anomaly detection, and pretrained static models. It aims to detect both known and **zero-day threats** using lightweight, extensible techniques.

> ✅ Built for security teams, students, and researchers
> 📦 Supports `.pdf`, `.doc`, `.js`, `.exe`, and other file types.
> 🚀 Dockerized full-stack app using FastAPI + React + TailwindCSS

---

## 🚀 Features

- ✅ **Multi-File Support**: DOC, PDF, JS, EXE and unknown formats.
- 🧠 **ML-Based Detection**: Custom-trained classifiers using `RandomForest`.
- 🔍 **Zero-Day Protection**: One-Class SVM anomaly detectors flag suspicious files.
- ⚙️ **EMBER Integration**: Pretrained LightGBM model for static PE (EXE) file analysis.
- 🌐 **FastAPI API**: Simple REST API to scan and get results.
- 📊 **Evaluation & Confusion Matrix** for performance analysis.

---

## 🧱 Project Structure

```bash
GajDefender/
├── backend/                # FastAPI backend
│   ├── app/                # Main API + scan logic
│   ├── ember_patch/        # EMBER model utilities
│   ├── uploads/            # Uploaded file store
│   ├── Dockerfile
│   ├── requirements.txt
│   └── docker-compose.yml
├── frontend/               # React + Tailwind app
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── tailwind.config.js
```
---

## 🧰 Technologies Used

🔒 Backend
- FastAPI – blazing fast async API
- LightGBM – for PE (EXE) malware detection using pretrained EMBER
- Scikit-learn – for PDF/DOC/JS classifiers + anomaly detection
- One-Class SVM – for zero-day detection
- Uvicorn – ASGI server

🖥 Frontend
- React.js
- TailwindCSS
- Axios – for API interaction
- Heroicons – for clean UI icons

🐳 Deployment
- Docker + Compose
- Hot-reload dev support

---

## ⚙️ Setup

### 1. Clone the Repo
```bash
git clone https://github.com/atharvaupare/gajdefender.git
cd GajDefender
```
---

### 2. Dockerized Setup (Recommended)

```bash
# Start fullstack app
docker-compose up --build
```

### 3. Manual Local Setup
Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Frontend
```bash
cd frontend
npm install
npm run dev  # Starts React server at http://localhost:3000
```

---

## 🧠 How It Works

| File Type | Classifier Used            | Detection Mode      |
|-----------|----------------------------|---------------------|
| `.pdf`    | RandomForest + OneClassSVM | Structural analysis |
| `.doc`    | RandomForest + OneClassSVM | OLE, macro & embed  |
| `.js`     | RandomForest + OneClassSVM | Obfuscation-aware   |
| `.exe`    | EMBER LightGBM Model       | Static signature    |
| Other     | EMBER Model                | Raw PE fallback     |

---

## 🛡️ Supported Features

- 🔍 **Single and Batch file scan** interface
- 🌐 API endpoint `/scan` using FastAPI
- 📈 Built-in anomaly detection for zero-days
- 📦 Supports `.doc`, `.pdf`, `.js`, `.exe`, `.html`, `.bat`, `.vbs`, etc.
- 🧰 Easily extensible to support `.apk`, `.py`, `.zip`, etc.

---

## 🧠 Future Improvements

- [ ] Deep Learning model support (CNN for byte-level EXEs)
- [ ] Behavioral (dynamic) sandbox integration
- [ ] File unpacking and macro extraction for DOCX
- [ ] Explainable AI dashboard for predictions

---

## 🙌 Acknowledgements

- [EMBER Dataset](https://github.com/elastic/ember) by Endgame/Elastic
- [DikeDataset](https://www.kaggle.com/datasets/) - DOC Malware samples
- [CIC-Evasive-PDFMal2022](https://www.unb.ca/cic/datasets/pdfmal-2022.html) - PDF Malware samples
- [Benign and Malicious JavaScript Dataset](https://data.mendeley.com/datasets/3drdhrxjm7/1) by Mendeley Data
- FastAPI & Scikit-learn for enabling quick deployment

---

## 🤝 Contributing

Pull requests, issues, and suggestions welcome! Feel free to fork and enhance the project.

---

> Made by Team RedHeadRedemption ([Aahan Shetye](https://github.com/aahanshetye), [Atharva Upare](https://github.com/atharvaupare), [Swadha Khatod](https://github.com/swadha112) and [Apurva Dharam](https://github.com/ApurvaDharam))for the GajShield KJSSE Hack 8 Hackathon.





