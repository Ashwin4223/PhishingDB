# PhishingDB

A machine learning-based phishing detection app built using Python. It analyzes URLs to detect potential phishing threats. The application features a user-friendly GUI created with PySimpleGUI and uses a trained Random Forest model for prediction.

---

## 🚀 Features

- 🔍 URL-based phishing detection using extracted features
- 🧠 Trained Random Forest classifier
- 🖥️ GUI built using PySimpleGUI for ease of use
- 📋 Prediction result with simple interface
- 🔒 Focused on enhancing web security awareness

---

## 🛠️ Tech Stack

- **Python** (Core logic)
- **Pandas, Scikit-learn** (Data processing & ML model)
- **PySimpleGUI** (Graphical user interface)
- **Joblib** (Model serialization)

---

## 🧪 Dataset

- The project uses a dataset of legitimate and phishing URLs with labeled features.
- You can find the dataset used in `dataset.csv`.

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/phishing-detection-py.git
cd phishing-detection-py
pip install -r requirements.txt
```
---

## ⚠️ Important Note

- The application must be run in VS Code as Administrator.
- This is required because the code applies changes on log files, which need elevated permissions.

---

## 🛠️ Troubleshooting

- If you run the app without administrator privileges, you may encounter errors such as:
    `Permission denied while accessing log files.`
    `Inability to update or modify required system files.`
  
✅ To fix this, simply restart VS Code and run it as Administrator, then rerun the script.

---

## 🧑‍💻 How to Use

1. Run the main script:
   ```bash
   python phishing_gui.py
   ```
2. Paste the URL in the input box.
3. Hit "Check" and view the result.

---

## 📈 Future Improvements

- Web version using React and Node.js (Coming soon 🚀)
- SSL certificate validation
- Real-time blacklist integration

---

## 📸 Screenshots

![alt text](image.png)

---

## 👨‍💻 About Me

I'm **Nair Ashwin Anandpadmanbhan**, a final-year CS student passionate about cybersecurity and ethical hacking.  
Feel free to connect with me:

- ✉️ [nairashwin1109@gmail.com](mailto:nairashwin1109@gmail.com)

---

## 📄 License

This project is licensed under the MIT License.
