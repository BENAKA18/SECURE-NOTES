from ui import UserInterface

def main():
    app = UserInterface()
    
    # Welcome message
    app.clear_screen()
    print("Welcome to Secure Notes Application!")
    print("This app encrypts your notes for maximum security.\n")
    
    # Password setup/authentication
    if not app.setup_password():
        print("Failed to authenticate. Exiting...")
        return
    
    # Main application loop
    while True:
        app.display_menu()
        
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                app.write_note()
            elif choice == '2':
                app.view_notes()
            elif choice == '3':
                app.read_note()
            elif choice == '4':
                app.change_password()
            elif choice == '5':
                print("\nThank you for using Secure Notes Application!")
                print("Goodbye! 👋")
                break
            else:
                print("Invalid choice! Please enter a number between 1-5.")
            
            input("\nPress Enter to continue...")
            app.clear_screen()
            
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            input("\nPress Enter to continue...")
            app.clear_screen()
        except Exception as e:
            print(f"\nAn error occurred: {e}")
            input("\nPress Enter to continue...")
            app.clear_screen()

if __name__ == "__main__":
    main()