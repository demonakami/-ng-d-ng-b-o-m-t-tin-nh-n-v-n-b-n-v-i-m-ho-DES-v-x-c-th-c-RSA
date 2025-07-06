# logging_config.py
import logging
import os
from datetime import datetime

def setup_logging():
    """Cấu hình logging cho ứng dụng secure messaging"""
    
    # Tạo thư mục logs nếu chưa có
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Tên file log theo ngày
    log_filename = f"logs/secure_messaging_{datetime.now().strftime('%Y%m%d')}.log"
    
    # Cấu hình logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
        handlers=[
            # Ghi vào file
            logging.FileHandler(log_filename, encoding='utf-8'),
            # Hiển thị trên console
            logging.StreamHandler()
        ]
    )
    
    # Tạo logger riêng cho các module
    crypto_logger = logging.getLogger('crypto')
    websocket_logger = logging.getLogger('websocket')
    auth_logger = logging.getLogger('auth')
    
    return {
        'crypto': crypto_logger,
        'websocket': websocket_logger,
        'auth': auth_logger
    }

def log_crypto_operation(operation, username, status, details=None):
    """Log các thao tác mã hóa"""
    logger = logging.getLogger('crypto')
    
    if status == 'OK':
        logger.info(f"[{operation}] User: {username} - Status: {status}" + 
                   (f" - {details}" if details else ""))
    else:
        logger.error(f"[{operation}] User: {username} - Status: {status}" + 
                    (f" - {details}" if details else ""))

def log_message_flow(sender, receiver, msg_type, status, details=None):
    """Log luồng tin nhắn"""
    logger = logging.getLogger('websocket')
    
    if status in ['SENT', 'DELIVERED']:
        logger.info(f"[{msg_type}] {sender} → {receiver} - {status}" + 
                   (f" - {details}" if details else ""))
    else:
        logger.warning(f"[{msg_type}] {sender} → {receiver} - {status}" + 
                      (f" - {details}" if details else ""))

def log_security_event(event_type, username, details):
    """Log các sự kiện bảo mật"""
    logger = logging.getLogger('auth')
    logger.warning(f"[SECURITY] {event_type} - User: {username} - {details}")