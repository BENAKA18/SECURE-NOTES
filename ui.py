import getpass
import sys
from crypto import CryptoManager
from file_manager import FileManager

class UserInterface:
    def __init__(self):
        self.crypto = CryptoManager()
        self.file_manager = FileManager()
        self.is_authenticated = False
    
    def clear_screen(self):
        """Clear the terminal screen"""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def safe_getpass(self, prompt):
    """A safe way to get password input that works in VS Code"""
    try:
        from password_input import get_password_input
        return get_password_input(prompt)
    except ImportError:
        # Fallback
        print("\n  Using visible input (install required packages for hidden input)")
        return input(prompt)
    
    def display_menu(self):
        """Display main menu"""
        print("\n" + "="*50)
        print("         SECURE NOTES APPLICATION")
        print("="*50)
        print("1. Write New Note")
        print("2. View All Notes")
        print("3. Decrypt and Read Note")
        print("4. Change Password")
        print("5. Exit")
        print("="*50)
    
    def setup_password(self):
        """Setup or verify password"""
        salt = self.file_manager.load_salt()
        
        if salt:
            # Existing user - verify password
            password = self.safe_getpass("Enter your password: ")
            if not password:
                print("✗ Password cannot be empty!")
                return False
                
            try:
                key, _ = self.crypto.generate_key_from_password(password, salt)
                self.crypto.set_key(key)
                self.is_authenticated = True
                print("✓ Authentication successful!")
                return True
            except Exception as e:
                print("✗ Authentication failed! Wrong password.")
                return False
        else:
            # New user - set up password
            print("Welcome! Let's set up your password.")
            password = self.safe_getpass("Create a strong password: ")
            
            if not password:
                print("✗ Password cannot be empty!")
                return False
                
            confirm_password = self.safe_getpass("Confirm password: ")
            
            if password != confirm_password:
                print("✗ Passwords don't match!")
                return False
            
            if len(password) < 4:
                print("✗ Password must be at least 4 characters long!")
                return False
            
            key, salt = self.crypto.generate_key_from_password(password)
            self.crypto.set_key(key)
            self.file_manager.save_salt(salt)
            self.is_authenticated = True
            print("✓ Password setup successful!")
            return True
    
    def write_note(self):
        """Write and encrypt a new note"""
        if not self.is_authenticated:
            print("Please authenticate first!")
            return
        
        print("\n--- Write New Note ---")
        title = input("Enter note title: ").strip()
        
        if not title:
            print("Title cannot be empty!")
            return
        
        print("Enter note content (press Enter twice to finish):")
        lines = []
        empty_line_count = 0
        
        while True:
            try:
                line = input()
                if line.strip() == "":
                    empty_line_count += 1
                    if empty_line_count >= 2:
                        break
                else:
                    empty_line_count = 0
                lines.append(line)
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\nInput cancelled.")
                return
        
        content = "\n".join(lines).strip()
        
        if not content:
            print("Content cannot be empty!")
            return
        
        # Encrypt the content
        try:
            encrypted_content = self.crypto.encrypt_data(content)
            success = self.file_manager.save_note(title, encrypted_content, encrypted=True)
            
            if success:
                print(f"✓ Note '{title}' encrypted and saved successfully!")
            else:
                print("✗ Failed to save note!")
        except Exception as e:
            print(f"✗ Encryption error: {e}")
    
    def view_notes(self):
        """View all notes (titles only)"""
        notes = self.file_manager.load_notes()
        
        if not notes:
            print("\nNo notes found!")
            return
        
        print("\n--- Your Notes ---")
        for i, note in enumerate(notes, 1):
            status = "🔒 ENCRYPTED" if note.get('encrypted', True) else "📄 PLAIN"
            print(f"{i}. {note['title']} - {status} - {note.get('timestamp', 'Unknown')}")
    
    def read_note(self):
        """Decrypt and read a specific note"""
        if not self.is_authenticated:
            print("Please authenticate first!")
            return
        
        notes = self.file_manager.load_notes()
        
        if not notes:
            print("\nNo notes found!")
            return
        
        self.view_notes()
        
        try:
            choice_str = input("\nEnter note number to read: ").strip()
            if not choice_str:
                print("No input provided!")
                return
                
            choice = int(choice_str) - 1
            if choice < 0 or choice >= len(notes):
                print("Invalid note number!")
                return
            
            note = notes[choice]
            
            if not note.get('encrypted', True):
                # Note is not encrypted
                print(f"\n--- {note['title']} ---")
                print(note['content'])
                print(f"\nTimestamp: {note.get('timestamp', 'Unknown')}")
                return
            
            # Decrypt the note
            try:
                decrypted_content = self.crypto.decrypt_data(note['content'])
                print(f"\n--- {note['title']} ---")
                print(decrypted_content)
                print(f"\nTimestamp: {note.get('timestamp', 'Unknown')}")
            except Exception as e:
                print(f"✗ Decryption failed: {e}")
                
        except ValueError:
            print("Please enter a valid number!")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
    
    def change_password(self):
        """Change the encryption password"""
        if not self.is_authenticated:
            print("Please authenticate first!")
            return
        
        print("\n--- Change Password ---")
        current_password = self.safe_getpass("Enter current password: ")
        
        if not current_password:
            print("✗ Password cannot be empty!")
            return
        
        # Verify current password
        salt = self.file_manager.load_salt()
        try:
            current_key, _ = self.crypto.generate_key_from_password(current_password, salt)
            # Test if the key works by trying to create a Fernet instance
            test_fernet = Fernet(current_key)
            # Test encryption/decryption
            test_data = "test"
            encrypted = test_fernet.encrypt(test_data.encode())
            test_fernet.decrypt(encrypted)
        except Exception as e:
            print("✗ Current password is incorrect!")
            return
        
        # Get new password
        new_password = self.safe_getpass("Enter new password: ")
        
        if not new_password:
            print("✗ New password cannot be empty!")
            return
            
        confirm_password = self.safe_getpass("Confirm new password: ")
        
        if new_password != confirm_password:
            print("✗ New passwords don't match!")
            return
        
        if new_password == current_password:
            print("✗ New password must be different from current password!")
            return
        
        if len(new_password) < 4:
            print("✗ New password must be at least 4 characters long!")
            return
        
        # Re-encrypt all notes with new password
        try:
            # Generate new key and salt
            new_key, new_salt = self.crypto.generate_key_from_password(new_password)
            
            # Re-encrypt all notes
            notes = self.file_manager.load_notes()
            reencrypted_notes = []
            
            for note in notes:
                if note.get('encrypted', True):
                    # Decrypt with old key
                    self.crypto.set_key(current_key)
                    try:
                        decrypted_content = self.crypto.decrypt_data(note['content'])
                        # Encrypt with new key
                        self.crypto.set_key(new_key)
                        note['content'] = self.crypto.encrypt_data(decrypted_content)
                        reencrypted_notes.append(note)
                    except Exception as e:
                        print(f"Warning: Could not re-encrypt note '{note['title']}': {e}")
                else:
                    reencrypted_notes.append(note)
            
            # Update the file manager to use the new notes
            self.file_manager.save_salt(new_salt)
            self.crypto.set_key(new_key)
            
            # Save all re-encrypted notes
            for note in reencrypted_notes:
                self.file_manager.save_note(note['title'], note['content'], note.get('encrypted', True))
            
            print("✓ Password changed successfully! All notes have been re-encrypted.")
            
        except Exception as e:
            print(f"✗ Error changing password: {e}")

# Import for change_password method
from cryptography.fernet import Fernet