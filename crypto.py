from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class CryptoManager:
    def __init__(self):
        self.key = None
        
    def generate_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """Generate a key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def set_key(self, key: bytes):
        """Set the encryption key"""
        self.key = key
        self.fernet = Fernet(key)
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt the data"""
        if not self.key:
            raise ValueError("Key not set. Please set encryption key first.")
        
        encrypted_data = self.fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt the data"""
        if not self.key:
            raise ValueError("Key not set. Please set encryption key first.")
        
        try:
            encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(encrypted_data_bytes)
            return decrypted_data.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def generate_key(self) -> bytes:
        """Generate a random key"""
        return Fernet.generate_key()