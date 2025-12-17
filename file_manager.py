import json
import os
from typing import List, Dict, Any
import base64
from datetime import datetime

class FileManager:
    def __init__(self, data_file: str = "secure_notes.json"):
        self.data_file = data_file
        self.ensure_data_file()
    
    def ensure_data_file(self):
        """Create data file if it doesn't exist"""
        if not os.path.exists(self.data_file):
            with open(self.data_file, 'w') as f:
                json.dump({"notes": [], "salt": None}, f)
    
    def save_note(self, title: str, content: str, encrypted: bool = True) -> bool:
        """Save a note to the file"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            note = {
                "title": title,
                "content": content,
                "encrypted": encrypted,
                "timestamp": self.get_current_timestamp()
            }
            
            data["notes"].append(note)
            
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error saving note: {e}")
            return False
    
    def load_notes(self) -> List[Dict[str, Any]]:
        """Load all notes from the file"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            return data.get("notes", [])
        except Exception as e:
            print(f"Error loading notes: {e}")
            return []
    
    def save_salt(self, salt: bytes):
        """Save salt to the data file"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            data["salt"] = base64.urlsafe_b64encode(salt).decode() if salt else None
            
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving salt: {e}")
    
    def load_salt(self) -> bytes:
        """Load salt from the data file"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            salt_b64 = data.get("salt")
            if salt_b64:
                return base64.urlsafe_b64decode(salt_b64.encode())
            return None
        except Exception as e:
            print(f"Error loading salt: {e}")
            return None
    
    def get_current_timestamp(self) -> str:
        """Get current timestamp string"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")