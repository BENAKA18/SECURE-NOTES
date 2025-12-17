def get_password_input(prompt="Enter password: "):
    """Cross-platform password input with asterisks"""
    import sys
    import msvcrt if sys.platform == "win32" else None
    
    print(prompt, end='', flush=True)
    password = []
    
    if sys.platform == "win32":
        # Windows version
        while True:
            ch = msvcrt.getch()
            if ch in [b'\r', b'\n']:  # Enter key
                print()
                break
            elif ch == b'\x08':  # Backspace
                if password:
                    password.pop()
                    print('\b \b', end='', flush=True)
            else:
                password.append(ch.decode('utf-8'))
                print('*', end='', flush=True)
    else:
        # Unix/Linux/Mac version
        import termios
        import tty
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ['\r', '\n']:  # Enter key
                    print()
                    break
                elif ch == '\x7f':  # Backspace
                    if password:
                        password.pop()
                        print('\b \b', end='', flush=True)
                else:
                    password.append(ch)
                    print('*', end='', flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    return ''.join(password)