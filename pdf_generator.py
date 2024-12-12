from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

BASIC_FONT = "Helvetica"
BOLD_FONT = "Helvetica-Bold"
PDF_TITLE = "Analysis Results for QR Code"

def create_pdf_with_image_and_text(image_path, data, img_metadata, x=50, y=750, image_width=200, image_height=200):
    output_path = "qrcode_results.pdf"
    try:
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
                        
        c.setFont(BOLD_FONT, 16)  
        c.drawString(50, height - 50, PDF_TITLE)
        
        c.setFont(BASIC_FONT, 12)  
        x = 50
        y = height - 100 
        
        c.setFont(BASIC_FONT, 12)  
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key, value in item.items():
                        if key == "message":
                            c.setFont(BOLD_FONT, 12)  
                            c.setFillColor(colors.blue)  
                            c.drawString(x, y, str(value))  
                            c.setFillColor(colors.black)  # 기본 색상으로 복원
                            c.setFont(BASIC_FONT, 12)   # 기본 폰트로 복원
                            y -= 15
                        elif key == "metadata" and isinstance(value, dict):
                            c.drawString(x, y, f"{key}:")
                            y -= 15  # metadata 제목 줄 간격 설정
                            for meta_key, meta_value in value.items():
                                text_line = f"  {meta_key}: {meta_value}"  # 들여쓰기 추가
                                c.drawString(x + 10, y, text_line)  # 들여쓰기
                                y -= 15  # 줄 간격 설정
                            y -= 10  # metadata 블록 간 여백
                        else:
                            text_line = f"{key}: {value}"
                            c.drawString(x, y, text_line)
                            y -= 15  # 줄 간격 설정
                    y -= 10  # 리스트 항목 간 여백
                else:
                    c.drawString(x, y, str(item))
                    y -= 15
        
        c.drawImage(image_path, x, y - image_height - 10, width=image_width, height=image_height)
        c.save()
        print(f"PDF 생성 완료: {output_path}")
    
    except Exception as e:
        print(f"PDF 생성 오류: {e}")