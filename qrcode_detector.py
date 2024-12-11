import requests
import re
from dotenv import load_dotenv
import os
from urllib.parse import urlparse, urljoin
from PIL import Image
from PIL.ExifTags import TAGS
import qrcode
from pyzbar.pyzbar import decode
import pdf_generator

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def analyze_qr_content(data):
    """QR 코드 내용을 분석하여 구조화된 정보를 반환"""
    result = {
        "raw_data": data,
        "type": "UNKNOWN",
        "subtype": None,
        "metadata": {},
        "is_suspicious": False,
        "security_flags": []
    }
    
    # URL 분석
    if data.startswith(("http://", "https://")):
        result["type"] = "URL"
        result["subtype"] = "http" if data.startswith("http://") else "https"
        result["metadata"] = {
            "domain": data.split("/")[2],
            "protocol": data.split("://")[0],
            "path": "/".join(data.split("/")[3:])
        }

        # HTTP 사용시 보안 플래그 추가
        if data.startswith("http://"):
            result["security_flags"].append("INSECURE_PROTOCOL")
            result["is_suspicious"] = True
        
        # URL의 도메인 정보 및 악성 여부 탐지 (VIRUSTOTAL)
        try:
            safety_flag, analysis_results = check_url_safety(data)
            result["metadata"]["analysis_results"] = analysis_results
            if not safety_flag:
                result["security_flags"].append("MALICIOUS_OR_SUSPICIOUS")
                result["is_suspicious"] = True
            else:
                result["is_suspicious"] = False
        except Exception as e:
            print(f"URL 분석 오류: {e}")
            result["security_flags"].append("ANALYSIS_ERROR")
    
    # 이메일 분석
    elif data.startswith("mailto:"):
        result["type"] = "EMAIL"
        email = data[7:]
        result["metadata"] = {
            "address": email,
            "domain": email.split("@")[1] if "@" in email else None
        }
    
    # 전화번호 분석
    elif data.startswith("tel:"):
        result["type"] = "PHONE"
        phone = data[4:]
        result["metadata"] = {
            "number": phone,
            "country_code": phone.split("-")[0] if "-" in phone else None
        }
    
    # 위치정보 분석
    elif data.startswith("geo:"):
        result["type"] = "GEOLOCATION"
        coords = data[4:].split(",")
        result["metadata"] = {
            "latitude": coords[0] if len(coords) > 0 else None,
            "longitude": coords[1] if len(coords) > 1 else None
        }
    
    # WiFi 설정 분석
    elif data.startswith("WIFI:"):
        result["type"] = "WIFI"
        wifi_data = data[5:].split(";")
        wifi_info = {}
        for item in wifi_data:
            if "=" in item:
                key, value = item.split("=", 1)
                wifi_info[key] = value
        result["metadata"] = wifi_info
    
    # 텔레그램 분석
    elif data.startswith("tg:"):
        result["type"] = "TELEGRAM"
        if "login?token=" in data:
            result["subtype"] = "login"
            result["metadata"] = {
                "action": "login",
                "token": data.split("token=")[1],
            }
            result["security_flags"].append("POTENTIAL_PHISHING")
            result["is_suspicious"] = True
    
    # 기타 텍스트 패턴 분석
    else:
        # 숫자와 문자가 섞인 특정 패턴 분석
        if "-" in data and any(c.isdigit() for c in data):
            parts = data.split("-")
            if len(parts) >= 3:  # 일반적인 참조번호 형식
                result["type"] = "REFERENCE_NUMBER"
                result["metadata"] = {
                    "prefix": parts[0],
                    "code": parts[1],
                    "number": "-".join(parts[2:]),
                    "year": next((p for p in parts if len(p) == 4 and p.isdigit()), None)
                }
        else:
            result["type"] = "PLAINTEXT"
            result["metadata"] = {
                "length": len(data),
                "has_numbers": any(c.isdigit() for c in data),
                "has_special_chars": any(not c.isalnum() for c in data)
            }
    
    return result

def extract_metadata(image_path):
    metadata = {}
    try:
        with Image.open(image_path) as img:
            metadata['Format'] = img.format
            metadata['Mode'] = img.mode
            metadata['Size'] = img.size
            metadata['Info'] = img.info

            # EXIF 데이터 (JPEG만 해당)
            exif_data = img._getexif()
            if exif_data:
                metadata['EXIF'] = {TAGS.get(tag): value for tag, value in exif_data.items() if tag in TAGS}
    except Exception as e:
        print(f"Error extracting metadata: {e}")
    
    return metadata 

def process_qr_codes(image_path):
    image = Image.open(image_path)
    decoded_objects = decode(image)
    
    results = []
    for obj in decoded_objects:
        data = obj.data.decode('utf-8')
        analysis = analyze_qr_content(data)
        results.append(analysis)
        
        # 분석 결과 출력
        print(f"\nQR Code Analysis Results:")
        print(f"Type: {analysis['type']}")
        if analysis['subtype']:
            print(f"Subtype: {analysis['subtype']}")
        print(f"Metadata: {analysis['metadata']}")
        if analysis['security_flags']:
            print(f"Security Flags: {analysis['security_flags']}")
        if analysis['is_suspicious']:
            print("⚠️ Warning: This QR code might be suspicious!")
            
    return results

# URL의 도메인 정보 및 악성 여부 탐지 (VIRUSTOTAL)
def check_url_safety(url):
    safety_flag = False
    analysis_results = {}
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        print(f"분석 중인 도메인: {domain}")
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            analysis_stats = attributes.get("last_analysis_stats", {})
            
            malicious_count = analysis_stats.get("malicious", 0)
            suspicious_count = analysis_stats.get("suspicious", 0)
            
            analysis_results["malicious"] = malicious_count
            analysis_results["suspicious"] = suspicious_count
            
            if malicious_count == 0 and suspicious_count == 0:
                safety_flag = True
            else:
                safe

        else:
            print("VirusTotal API 호출 실패:", response.status_code)

    except Exception as e:
        print(f"도메인 분석 중 오류 발생: {e}")
        
    finally:
        return safety_flag, analysis_results

# 메인 함수
if __name__ == "__main__":
    image_path = './naver_qr.png'
    
    # QR 코드 디코딩
    qr_data = process_qr_codes(image_path)
    print(qr_data)
    
    # 이미지 정보 
    metadata = extract_metadata(image_path)
    print(metadata)
    
    # PDF 생성 
    pdf_generator.create_pdf_with_image_and_text(image_path, qr_data, metadata)
    