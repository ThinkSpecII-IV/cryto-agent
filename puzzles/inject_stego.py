#!/usr/bin/env python3
import cv2
import numpy as np
import os

def inject_message_to_pixels():
    # Tạo một file ảnh ma trận màu xám sạch kích thước 200x200 pixel
    img = np.zeros((200, 200, 3), dtype=np.uint8)
    img[:] = [128, 128, 128] # Đổ dải màu trung tính
    
    # Chuỗi thông điệp bí mật chúng ta muốn giấu vào dải màu Green
    secret_message = "FLAG{orbit.desktop.stego.cracked}"
    
    # Chuyển đổi chuỗi chữ sang mảng chuỗi bit nhị phân (Binary)
    binary_message = ''.join(format(ord(c), '08b') for c in secret_message)
    
    # Bơm từng bit bí mật vào Bit cuối cùng (LSB) của kênh màu Green (Index 1)
    flat_channel = img[:, :, 1].flatten()
    for idx, bit in enumerate(binary_message):
        if idx < len(flat_channel):
            # Xóa bit cuối cũ và chèn bit bí mật vào
                    flat_channel[idx] = int((flat_channel[idx] & 254) | int(bit))

            
    # Gộp dải mảng đã bơm ngược lại vào ma trận ảnh ban đầu
    img[:, :, 1] = flat_channel.reshape((200, 200))
    
    # Lưu file ảnh câu đố ra thư mục puzzles
    output_path = "puzzles/stego_challenge.png"
    cv2.imwrite(output_path, img)
    print(f"🛰️  Đã tạo câu đố ảnh thành công tại: {output_path}")

if __name__ == "__main__":
    inject_message_to_pixels()
