# QR Code Analyzer

## Overview 
This project provides a tool to verify whether a QR Code is harmful. By inputting a QR Code image as a parameter to the program, users can check the safety of the QR Code. If the QR Code performs a URL redirection, the program evaluates whether the redirected URL points to a harmful site using the VirusTotal API. Finally, the tool generates a PDF file containing the QR Code image and related information, which can be used as evidence.

## Installation 

1. Clone this repository
```
git clone https://github.com/kninami/qrcode-analyzer.git
```

2. Create and activate a virtual environment (in root folder)
```
python -m venv venv
source venv/bin/activate
```

3. Install dependencies using pip
```
pip install -r requirements.txt
```

## VirusTotal API Key Setup
1.	Get an API Key: Visit VirusTotal, log in, and copy your API key from the API Key section
2.	Create a .env File in the project root directory
3.	Add the API Key
```
VIRUSTOTAL_API_KEY=your_api_key_here
```

## Usage

```
python qrcode_detector.py /path/to/qrcode_image.png
```