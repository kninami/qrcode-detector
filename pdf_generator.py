from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def create_pdf_with_image_and_text(image_path, data, img_metadata, x=50, y=750, image_width=200, image_height=200):
    output_path = "output.pdf"
    try:
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
                        
        c.setFont("Helvetica-Bold", 16)  
        c.drawString(50, height - 50, "Analysis Results for QR Code")
        
        c.setFont("Helvetica", 12)  
        x = 50
        y = height - 100 
        
        c.setFont("Helvetica", 12)  
        if isinstance(data, dict):
            for key, value in data.items():
                text_line = f"{key}: {value}"
                c.drawString(x, y, text_line)
                y -= 15  # 줄 간격 설정
            
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key, value in item.items():
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