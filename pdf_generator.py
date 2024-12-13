import textwrap
import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

BASIC_FONT = "Helvetica"
BOLD_FONT = "Helvetica-Bold"
PDF_TITLE = "Analysis Results for QR Code"

def draw_wrapped_text(c, text, x, y, max_width, font_size=12):
    lines = textwrap.wrap(text, width=max_width)
    c.setFont(BASIC_FONT, font_size)
    for line in lines:
        c.drawString(x, y, line)
        y -= font_size + 2 
    return y 

def create_pdf_with_image_and_text(image_path, data, img_metadata, x=50, y=750, image_width=200, image_height=200):
    file_name_with_extension = os.path.basename(image_path)
    file_name = os.path.splitext(file_name_with_extension)[0]
    output_path = "qrcode_results" + "_" + file_name + ".pdf"
    try:
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter

        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "Analysis Results for QR Code")

        # 기본 글꼴 설정
        BASIC_FONT = "Helvetica"
        BOLD_FONT = "Helvetica-Bold"
        x = 50
        y = height - 100

        # 데이터 처리
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key, value in item.items():
                        if key == "message":
                            c.setFont(BOLD_FONT, 12)
                            c.setFillColor(colors.blue)
                            y = draw_wrapped_text(c, str(value), x, y, max_width=80)  # 메시지 출력
                            c.setFillColor(colors.black)  # 기본 색상으로 복원
                            c.setFont(BASIC_FONT, 12)  # 기본 폰트로 복원
                        elif key == "metadata" and isinstance(value, dict):
                            c.drawString(x, y, f"{key}:")
                            y -= 15
                            for meta_key, meta_value in value.items():
                                text_line = f"  {meta_key}: {meta_value}"  # 들여쓰기
                                y = draw_wrapped_text(c, text_line, x + 10, y, max_width=80)  # 줄바꿈 출력
                            y -= 10  # metadata 블록 간 여백
                        else:
                            text_line = f"{key}: {value}"
                            y = draw_wrapped_text(c, text_line, x, y, max_width=80)  # 일반 텍스트 줄바꿈 출력
                    y -= 10  # 리스트 항목 간 여백
                else:
                    y = draw_wrapped_text(c, str(item), x, y, max_width=80)  # 리스트의 일반 항목 줄바꿈 출력
                    y -= 15

        c.drawImage(image_path, x, y - image_height - 10, width=image_width, height=image_height)
        c.save()
        print(f"PDF 생성 완료: {output_path}")
    
    except Exception as e:
        print(f"PDF 생성 오류: {e}")