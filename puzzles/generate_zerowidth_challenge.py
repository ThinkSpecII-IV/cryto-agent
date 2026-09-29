#!/usr/bin/env python3
import os

def create_invisible_puzzle():
    # 1. Định nghĩa mật khẩu chứa ký tự đặc biệt cần giấu
    secret_flag = "KTRATINHOC2026-@!#"
    
    # Chuyển chuỗi sang dải bit nhị phân (8 bit cho mỗi ký tự)
    binary_stream = ''.join(f"{ord(c):08b}" for c in secret_flag)
    
    # 2. Định nghĩa bảng ánh xạ ký tự tàng hình theo ảnh của bạn
    # Bit '0' -> U+200C (Zero Width Non-Joiner)
    # Bit '1' -> U+200D (Zero Width Joiner)
    ZWN_JOINER = "\u200c"
    ZW_JOINER = "\u200d"
    
    # Chuyển đổi dải bit thành chuỗi tàng hình
    invisible_payload = "".join(ZW_JOINER if bit == '1' else ZWN_JOINER for bit in binary_stream)
    
    # 3. Chèn chuỗi tàng hình này vào giữa một câu văn bản bình thường
    cover_text_start = "Chào mừng bạn"
    cover_text_end = " đến với không gian làm việc Omni-Cipher Lab!"
    full_puzzle_text = f"{cover_text_start}{invisible_payload}{cover_text_end}"
    
    # 4. Xuất thành file .txt sạch bằng bảng mã UTF-8 chuẩn hóa
    output_path = "puzzles/zerowidth_challenge.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_puzzle_text)
        
    print("====================================================================")
    print(f"✅ [THÀNH CÔNG]: Đã tạo file câu đố tàng hình tại: {output_path}")
    print("💡 Mắt thường chỉ nhìn thấy: 'Chào mừng bạn đến với không gian làm việc...'")
    print("👾 Nhưng Kiro Bot sẽ nhìn thấy dải mã nhị phân ẩn giấu bên trong!")
    print("====================================================================")

if __name__ == "__main__":
    create_invisible_puzzle()
