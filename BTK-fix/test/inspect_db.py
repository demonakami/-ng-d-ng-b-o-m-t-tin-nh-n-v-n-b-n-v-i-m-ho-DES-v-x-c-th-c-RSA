from models import get_engine, TaiKhoan, Khoa
from sqlalchemy.orm import sessionmaker

# Kết nối DB
engine = get_engine()
Session = sessionmaker(bind=engine)
session = Session()

print("📋 Danh sách tài khoản:")
for tk in session.query(TaiKhoan).all():
    print(f"- ID: {tk.ma_tai_khoan}, Tên đăng nhập: {tk.ten_dang_nhap}")

print("\n🔐 Danh sách khóa RSA:")
for khoa in session.query(Khoa).all():
    print(f"- Tài khoản ID: {khoa.ma_tai_khoan}")
    print(f"  🔑 Public Key (rút gọn): {khoa.khoa_cong_khai[:50]}...")
    print(f"  🔒 Private Key (rút gọn): {khoa.khoa_ca_nhan[:50]}...")
    print()
