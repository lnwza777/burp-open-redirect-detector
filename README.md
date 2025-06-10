# Burp Open Redirect Detector

This is a **Burp Suite extension** that passively scans HTTP requests to identify **potential open redirect parameters**. The extension helps penetration testers quickly detect redirect-related parameters that are commonly misused in open redirect vulnerabilities.

---

## 🔍 Features
- Passive scanning (no requests are sent)
- Detects suspicious redirect-related parameter names
- Highlights parameters such as `url`, `redirect`, `return`, `goto`, etc.
- Integrates with Burp Scanner issue reporting

---

## 🚀 How to Use

1. Open **Burp Suite**.
2. Go to `Extender` → `Extensions`.
3. Click `Add`, choose the extension type as **Python**, and select this script.
4. The extension will automatically register itself and start detecting redirect parameters in passive scan traffic.

---

## 📋 Example of Detected Parameters

![504484825_725129749969875_4604266480555179371_n](https://github.com/user-attachments/assets/d65979e0-007b-44dd-929e-46c9690d7831)
