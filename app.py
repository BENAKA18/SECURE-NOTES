import streamlit as st
import base64
from crypto import CryptoManager
from file_manager import FileManager

# Page configuration
st.set_page_config(
    page_title="Secure Notes App",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Initialize session state
if 'crypto' not in st.session_state:
    st.session_state.crypto = CryptoManager()
if 'file_manager' not in st.session_state:
    st.session_state.file_manager = FileManager()
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'password_set' not in st.session_state:
    st.session_state.password_set = False

def check_password_set():
    """Check if password is already set"""
    salt = st.session_state.file_manager.load_salt()
    return salt is not None

def authenticate(password):
    """Authenticate user with password"""
    try:
        salt = st.session_state.file_manager.load_salt()
        key, _ = st.session_state.crypto.generate_key_from_password(password, salt)
        st.session_state.crypto.set_key(key)
        st.session_state.authenticated = True
        return True
    except Exception as e:
        st.error(f"Authentication failed: {str(e)}")
        return False

def setup_password(password, confirm_password):
    """Setup new password"""
    if password != confirm_password:
        st.error("Passwords don't match!")
        return False
    
    if len(password) < 4:
        st.error("Password must be at least 4 characters long!")
        return False
    
    try:
        key, salt = st.session_state.crypto.generate_key_from_password(password)
        st.session_state.crypto.set_key(key)
        st.session_state.file_manager.save_salt(salt)
        st.session_state.authenticated = True
        st.session_state.password_set = True
        return True
    except Exception as e:
        st.error(f"Password setup failed: {str(e)}")
        return False

def main_app():
    """Main application after authentication"""
    st.title("🔒 Secure Notes Application")
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.radio(
        "Choose action:",
        ["Write Note", "View Notes", "Read Note", "Change Password"]
    )
    
    if app_mode == "Write Note":
        write_note()
    elif app_mode == "View Notes":
        view_notes()
    elif app_mode == "Read Note":
        read_note()
    elif app_mode == "Change Password":
        change_password()

def write_note():
    """Write and encrypt a new note"""
    st.header("📝 Write New Note")
    
    with st.form("write_note_form"):
        title = st.text_input("Note Title", placeholder="Enter a title for your note")
        content = st.text_area("Note Content", placeholder="Write your note here...", height=200)
        
        submitted = st.form_submit_button("Encrypt & Save Note")
        
        if submitted:
            if not title.strip():
                st.error("Please enter a title!")
                return
            if not content.strip():
                st.error("Please enter some content!")
                return
            
            try:
                encrypted_content = st.session_state.crypto.encrypt_data(content)
                success = st.session_state.file_manager.save_note(title, encrypted_content, encrypted=True)
                
                if success:
                    st.success(f"✅ Note '{title}' encrypted and saved successfully!")
                    st.balloons()
                else:
                    st.error("❌ Failed to save note!")
            except Exception as e:
                st.error(f"❌ Encryption error: {str(e)}")

def view_notes():
    """View all notes (titles only)"""
    st.header("📋 Your Notes")
    
    notes = st.session_state.file_manager.load_notes()
    
    if not notes:
        st.info("No notes found. Create your first note!")
        return
    
    # Display notes in a nice format
    for i, note in enumerate(notes, 1):
        with st.expander(f"{i}. {note['title']}"):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**Status:** {'🔒 Encrypted' if note.get('encrypted', True) else '📄 Plain Text'}")
                st.write(f"**Created:** {note.get('timestamp', 'Unknown')}")
            with col2:
                if st.button("📖 Read", key=f"read_{i}"):
                    st.session_state.selected_note = i - 1
                    st.rerun()

def read_note():
    """Decrypt and read a specific note"""
    st.header("📖 Read Note")
    
    notes = st.session_state.file_manager.load_notes()
    
    if not notes:
        st.info("No notes available to read.")
        return
    
    # Note selection
    note_titles = [f"{note['title']} ({note.get('timestamp', 'Unknown')})" for note in notes]
    selected_note = st.selectbox("Select a note to read:", note_titles)
    
    if selected_note:
        note_index = note_titles.index(selected_note)
        note = notes[note_index]
        
        if st.button("Decrypt and Read"):
            if not note.get('encrypted', True):
                # Note is not encrypted
                st.subheader(note['title'])
                st.text_area("Content", note['content'], height=300, key=f"plain_{note_index}")
            else:
                # Decrypt the note
                try:
                    decrypted_content = st.session_state.crypto.decrypt_data(note['content'])
                    st.subheader(note['title'])
                    st.text_area("Content", decrypted_content, height=300, key=f"decrypted_{note_index}")
                    st.caption(f"Created: {note.get('timestamp', 'Unknown')}")
                except Exception as e:
                    st.error(f"❌ Decryption failed: {str(e)}")

def change_password():
    """Change the encryption password"""
    st.header("🔑 Change Password")
    
    with st.form("change_password_form"):
        st.info("This will re-encrypt all your existing notes with the new password.")
        
        current_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        
        submitted = st.form_submit_button("Change Password")
        
        if submitted:
            if not all([current_password, new_password, confirm_password]):
                st.error("Please fill in all fields!")
                return
            
            # Verify current password
            salt = st.session_state.file_manager.load_salt()
            try:
                current_key, _ = st.session_state.crypto.generate_key_from_password(current_password, salt)
                # Test the key
                from cryptography.fernet import Fernet
                test_fernet = Fernet(current_key)
                test_data = "test"
                encrypted = test_fernet.encrypt(test_data.encode())
                test_fernet.decrypt(encrypted)
            except Exception:
                st.error("❌ Current password is incorrect!")
                return
            
            if new_password != confirm_password:
                st.error("❌ New passwords don't match!")
                return
            
            if new_password == current_password:
                st.error("❌ New password must be different from current password!")
                return
            
            if len(new_password) < 4:
                st.error("❌ New password must be at least 4 characters long!")
                return
            
            # Re-encrypt all notes with new password
            try:
                # Generate new key and salt
                new_key, new_salt = st.session_state.crypto.generate_key_from_password(new_password)
                
                # Re-encrypt all notes
                notes = st.session_state.file_manager.load_notes()
                reencrypted_count = 0
                
                for note in notes:
                    if note.get('encrypted', True):
                        # Decrypt with old key
                        st.session_state.crypto.set_key(current_key)
                        try:
                            decrypted_content = st.session_state.crypto.decrypt_data(note['content'])
                            # Encrypt with new key
                            st.session_state.crypto.set_key(new_key)
                            note['content'] = st.session_state.crypto.encrypt_data(decrypted_content)
                            reencrypted_count += 1
                        except Exception as e:
                            st.warning(f"Could not re-encrypt note '{note['title']}': {str(e)}")
                
                # Update salt and current key
                st.session_state.file_manager.save_salt(new_salt)
                st.session_state.crypto.set_key(new_key)
                
                st.success(f"✅ Password changed successfully! {reencrypted_count} notes re-encrypted.")
                
            except Exception as e:
                st.error(f"❌ Error changing password: {str(e)}")

# Main application flow
def main():
    # Check if password is set
    password_is_set = check_password_set()
    
    if not password_is_set and not st.session_state.authenticated:
        # First-time setup
        st.title("🔒 Welcome to Secure Notes!")
        st.markdown("### Let's set up your password to get started")
        
        with st.form("setup_form"):
            password = st.text_input("Create a strong password", type="password")
            confirm_password = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Setup Password")
            
            if submitted:
                if setup_password(password, confirm_password):
                    st.success("✅ Password setup successful! You can now use the app.")
                    st.rerun()
    
    elif not st.session_state.authenticated:
        # Login for existing users
        st.title("🔒 Secure Notes Login")
        
        with st.form("login_form"):
            password = st.text_input("Enter your password", type="password")
            submitted = st.form_submit_button("Login")
            
            if submitted:
                if authenticate(password):
                    st.success("✅ Login successful!")
                    st.rerun()
    
    else:
        # Main application
        main_app()
        
        # Logout button in sidebar
        st.sidebar.markdown("---")
        if st.sidebar.button("🚪 Logout"):
            st.session_state.authenticated = False
            st.session_state.crypto = CryptoManager()
            st.rerun()

if __name__ == "__main__":
    main()