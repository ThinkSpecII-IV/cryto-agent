#!/usr/bin/env python3
import numpy as np
from PIL import Image
import os

def inject_lsb_secret():
    # 1. Định nghĩa mật khẩu mục tiêu chứa ký tự đặc biệt
    secret_msg = "FLAG{KTRATINHOC2026-@!#}"
    # Chuyển chuỗi sang dải bit nhị phân (thêm ký tự kết thúc \x00 để kết thúc chuỗi sạch)
    binary_secret = ''.join(f'{ord(c):08b}' for c in secret_msg) + '00000000'
    
    # 2. Tạo một ma trận ảnh thô rỗng (RGB) kích thước 200x200 pixel màu xanh gradient sạch
    width, height = 200, 200
    img_data = np.zeros((height, width, 3), dtype=np.uint8)
    for y in range(height):
        for x in range(width):
            img_data[y, x] = [x % 256, y % 256, 100] # Phối màu gradient nền
            
    # 3. Tiến hành nhúng dải bit nhị phân vào ma trận điểm ảnh (Kênh màu Green)
    flat_pixels = img_data.flatten()
    
    # Duyệt và thay thế bit cuối cùng (LSB) của từng kênh màu bằng bit của mật mã
    for i, bit in enumerate(binary_secret):
        if i >= len(flat_pixels):
            break
        # Xóa bit cuối cùng về 0 và cộng bit ẩn vào
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)
        
    # Tái cấu trúc lại ma trận ảnh sau khi nhúng
    stego_matrix = flat_pixels.reshape((height, width, 3))
    
    # 4. Xuất thành file ảnh PNG sạch 100% không dính nén mất dữ liệu
    output_path = "puzzles/stego_final_test.png"
    stego_image = Image.fromarray(stego_matrix)
    stego_image.save(output_path)
    print(f"🛰️  [THÀNH CÔNG]: Đã tạo file ảnh stego chứa mật mã tại: {output_path}")

if __name__ == "__main__":
    inject_lsb_secret()
