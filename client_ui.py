# client_ui.py
# Modern UI layout for Secure Messaging Client (optimized + rounded corners)

import tkinter as tk
from tkinter import messagebox, scrolledtext
from PIL import Image, ImageTk, ImageDraw, ImageFilter


# ================================================================
# 🔶 ROUNDED CORNER + HOVER + SHADOW UTILITIES
# ================================================================
def create_rounded_image(width, height, radius, color, shadow=False):
    """Create a rounded rectangle PIL image with optional shadow."""
    img = Image.new("RGBA", (width + 6, height + 6), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    x0, y0 = 3, 3
    x1, y1 = x0 + width, y0 + height

    if shadow:
        shadow_img = Image.new("RGBA", (width, height), (0, 0, 0, 180))
        shadow_mask = Image.new("L", (width, height), 0)
        draw_mask = ImageDraw.Draw(shadow_mask)
        draw_mask.rounded_rectangle((0, 0, width, height), radius=radius, fill=255)
        shadow_img.putalpha(shadow_mask)
        shadow_img = shadow_img.filter(ImageFilter.GaussianBlur(6))
        img.paste(shadow_img, (x0, y0), shadow_img)

    draw.rounded_rectangle((x0, y0, x1, y1), radius, fill=color)
    return img


def apply_rounded_style(btn, width=120, height=40, radius=15, 
                       bg_color="#8B85D8", text_color="white", 
                       hover_color=None, shadow=True):
    """Apply rounded corner style to button with hover effect."""
    img = create_rounded_image(width, height, radius, bg_color, shadow)
    tk_img = ImageTk.PhotoImage(img)
    
    btn._bg_image = tk_img
    btn.config(image=tk_img, compound="center", fg=text_color, 
               bd=0, relief=tk.FLAT, cursor="hand2")
    
    if hover_color:
        hover_img = create_rounded_image(width, height, radius, hover_color, shadow)
        hover_tk = ImageTk.PhotoImage(hover_img)
        btn._hover_image = hover_tk
        
        btn.bind("<Enter>", lambda e: btn.config(image=btn._hover_image))
        btn.bind("<Leave>", lambda e: btn.config(image=btn._bg_image))


# ================================================================
# 🔷 MAIN UI CLASS
# ================================================================
class SecureMessagingClientUI:
    def __init__(self, root, client):
        self.root = root
        self.client = client

        self.root.title("Secure Messaging")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        # Color palette
        self.colors = {
            'primary': '#5B4FDB',
            'secondary': '#8B85D8',
            'light': '#B8B3E8',
            'hover': '#A39BEF',
            'white': '#FFFFFF',
            'text': '#2D2D2D',
            'text_light': '#6B6B6B'
        }

        self.root.configure(bg=self.colors['primary'])
        
        # Character image cache
        self.char_image = None
        self.char_photo = None
        
        self._build_ui()
        self.show_login()  # Start with login screen

    def _build_ui(self):
        """Build all UI frames."""
        self.main_container = tk.Frame(self.root, bg=self.colors['primary'])
        self.main_container.pack(fill=tk.BOTH, expand=True)

        self._build_login_frame()
        self._build_register_frame()
        self._build_main_frame()


    # ============================================================
    # LOGIN FRAME (First Screen)
    # ============================================================
    def _build_login_frame(self):
        """Build login screen with character on left."""
        self.login_frame = tk.Frame(self.main_container, bg=self.colors['primary'])
        
        
        
        # Right side - Form
        right_frame = tk.Frame(self.login_frame, bg=self.colors['primary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=50, pady=50)
        
        form_frame = tk.Frame(right_frame, bg=self.colors['secondary'], relief=tk.FLAT)
        form_frame.pack(expand=True, pady=50, padx=30)
        
        inner_form = tk.Frame(form_frame, bg=self.colors['secondary'])
        inner_form.pack(padx=40, pady=40)
        
        # Title bar with clickable tabs
        title_bar = tk.Frame(inner_form, bg=self.colors['secondary'])
        title_bar.pack(pady=(0, 30), fill=tk.X)
        
        self.login_title_signin = tk.Label(title_bar, text="SIGN IN", 
                                          font=('Arial', 32, 'bold'),
                                          bg=self.colors['secondary'], fg='white',
                                          cursor='hand2')
        self.login_title_signin.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Label(title_bar, text="/", font=('Arial', 32, 'bold'),
                bg=self.colors['secondary'], fg=self.colors['light']).pack(side=tk.LEFT, padx=5)
        
        self.login_title_register = tk.Label(title_bar, text="REGISTER", 
                                            font=('Arial', 32, 'bold'),
                                            bg=self.colors['secondary'], 
                                            fg=self.colors['light'],
                                            cursor='hand2')
        self.login_title_register.pack(side=tk.LEFT, padx=(10, 0))
        
        # Bind click events
        self.login_title_register.bind('<Button-1>', lambda e: self.show_register())
        
        # Username
        self.login_username_entry = tk.Entry(inner_form, font=('Arial', 12), width=30,
                                             bg=self.colors['light'], fg=self.colors['text'],
                                             relief=tk.FLAT, bd=0)
        self.login_username_entry.pack(pady=10, ipady=8, padx=20, fill=tk.X)
        self.login_username_entry.insert(0, "Mailinizi Giriniz")
        self.login_username_entry.bind('<FocusIn>', 
            lambda e: self._clear_placeholder(e, "Mailinizi Giriniz"))
        
        # Password
        self.login_password_entry = tk.Entry(inner_form, font=('Arial', 12), width=30,
                                             bg=self.colors['light'], fg=self.colors['text'],
                                             relief=tk.FLAT, bd=0, show="")
        self.login_password_entry.pack(pady=10, ipady=8, padx=20, fill=tk.X)
        self.login_password_entry.insert(0, "Şifrenizi Giriniz")
        self.login_password_entry.bind('<FocusIn>', self._clear_password_placeholder)
        
        # Sign In Button
        signin_btn = tk.Button(inner_form, text="Sign In", font=('Arial', 12, 'bold'),
                               command=self.client.login)
        signin_btn.pack(pady=20)
        self.root.after(100, lambda: apply_rounded_style(
            signin_btn, 150, 40, 15, self.colors['light'], 
            self.colors['text'], self.colors['hover']))
        
        # Switch to register link
        switch_frame = tk.Frame(self.login_frame, bg=self.colors['primary'])
        switch_frame.pack(side=tk.BOTTOM, pady=20)
        
        tk.Label(switch_frame, text="Hesabınız yok mu? ",
                bg=self.colors['primary'], fg='white', 
                font=('Arial', 10)).pack(side=tk.LEFT)
        
        switch_btn = tk.Label(switch_frame, text="Kayıt Ol",
                             bg=self.colors['primary'], fg=self.colors['light'],
                             font=('Arial', 10, 'underline'), cursor='hand2')
        switch_btn.pack(side=tk.LEFT)
        switch_btn.bind('<Button-1>', lambda e: self.show_register())

    # ============================================================
    # REGISTER FRAME
    # ============================================================
    def _build_register_frame(self):
        """Build registration screen with character on right."""
        self.register_frame = tk.Frame(self.main_container, bg=self.colors['primary'])
        
        # Left side - Form
        left_frame = tk.Frame(self.register_frame, bg=self.colors['primary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=50, pady=50)
        
        form_frame = tk.Frame(left_frame, bg=self.colors['secondary'], relief=tk.FLAT)
        form_frame.pack(expand=True, pady=50, padx=30)
        
        inner_form = tk.Frame(form_frame, bg=self.colors['secondary'])
        inner_form.pack(padx=40, pady=40)
        
        # Title
        tk.Label(inner_form, text="REGISTER", font=('Arial', 32, 'bold'),
                bg=self.colors['secondary'], fg='white').pack(pady=(0, 30))
        
        # Username
        self.reg_username_entry = tk.Entry(inner_form, font=('Arial', 12), width=30,
                                           bg=self.colors['light'], fg=self.colors['text'],
                                           relief=tk.FLAT, bd=0)
        self.reg_username_entry.pack(pady=10, ipady=8, padx=20, fill=tk.X)
        self.reg_username_entry.insert(0, "Mailinizi Giriniz")
        self.reg_username_entry.bind('<FocusIn>', 
            lambda e: self._clear_placeholder(e, "Mailinizi Giriniz"))
        
        # Password
        self.reg_password_entry = tk.Entry(inner_form, font=('Arial', 12), width=30,
                                           bg=self.colors['light'], fg=self.colors['text'],
                                           relief=tk.FLAT, bd=0, show="")
        self.reg_password_entry.pack(pady=10, ipady=8, padx=20, fill=tk.X)
        self.reg_password_entry.insert(0, "Şifrenizi Giriniz")
        self.reg_password_entry.bind('<FocusIn>', self._clear_password_placeholder)
        
        # Image selection
        btn_frame = tk.Frame(inner_form, bg=self.colors['secondary'])
        btn_frame.pack(pady=20, fill=tk.X, padx=20)
        
        img_btn = tk.Button(btn_frame, text="Bir resim seç...",
                           font=('Arial', 11), command=self.client.select_image)
        img_btn.pack(side=tk.LEFT, padx=(0, 10))
        self.root.after(100, lambda: apply_rounded_style(
            img_btn, 140, 35, 12, self.colors['light'], 
            self.colors['text'], self.colors['hover']))
        
        self.reg_image_label = tk.Label(btn_frame, text="", bg=self.colors['secondary'],
                                        fg='white', font=('Arial', 9))
        self.reg_image_label.pack(side=tk.LEFT)
        
        # Sign Up Button
        signup_btn = tk.Button(inner_form, text="Sign Up", font=('Arial', 12, 'bold'),
                              command=self.client.register)
        signup_btn.pack(pady=(10, 10))
        self.root.after(100, lambda: apply_rounded_style(
            signup_btn, 150, 40, 15, self.colors['light'], 
            self.colors['text'], self.colors['hover']))
        
        # Switch to login link
        switch_frame = tk.Frame(self.register_frame, bg=self.colors['primary'])
        switch_frame.pack(side=tk.BOTTOM, pady=20)
        
        tk.Label(switch_frame, text="Zaten hesabınız var mı? ",
                bg=self.colors['primary'], fg='white', 
                font=('Arial', 10)).pack(side=tk.LEFT)
        
        switch_btn = tk.Label(switch_frame, text="Giriş Yap",
                             bg=self.colors['primary'], fg=self.colors['light'],
                             font=('Arial', 10, 'underline'), cursor='hand2')
        switch_btn.pack(side=tk.LEFT)
        switch_btn.bind('<Button-1>', lambda e: self.show_login())

    # ============================================================
    # MAIN FRAME (After Login/Register)
    # ============================================================
    def _build_main_frame(self):
        """Build main screen with mail/users tabs."""
        self.main_frame = tk.Frame(self.main_container, bg=self.colors['primary'])
        
        # Header
        header = tk.Frame(self.main_frame, bg=self.colors['primary'])
        header.pack(fill=tk.X, padx=30, pady=20)
        
        self.welcome_label = tk.Label(header, text="Welcome, Client#",
                                      font=('Arial', 24, 'bold'),
                                      bg=self.colors['primary'], fg='white')
        self.welcome_label.pack(anchor='w')

        # Sign Out button
        signout_btn = tk.Button(header, text="Sign Out", font=('Arial', 11, 'bold'),
                                command=self.sign_out)
        signout_btn.pack(side=tk.RIGHT, padx=10)

        self.root.after(100, lambda: apply_rounded_style(
            signout_btn, 110, 38, 12, self.colors['primary'],
            'white', self.colors['secondary'], shadow=False))

        # Tabs
        tab_frame = tk.Frame(self.main_frame, bg=self.colors['primary'])
        tab_frame.pack(fill=tk.X, padx=30)
        
        self.mail_tab_btn = tk.Button(tab_frame, text="Mail", font=('Arial', 12, 'bold'),
                                      command=lambda: self.switch_tab('mail'))
        self.mail_tab_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.users_tab_btn = tk.Button(tab_frame, text="Users", font=('Arial', 12, 'bold'),
                                       command=lambda: self.switch_tab('users'))
        self.users_tab_btn.pack(side=tk.LEFT)
        
        # Apply styles after creation
        self.root.after(100, self._style_tabs)
        
        # Content area
        content_frame = tk.Frame(self.main_frame, bg=self.colors['secondary'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10, 30))
        
        # Mail listbox
        self.mail_listbox = tk.Listbox(content_frame, font=('Arial', 11),
                                       bg=self.colors['light'], fg=self.colors['text'],
                                       relief=tk.FLAT, bd=0, highlightthickness=0)
        self.mail_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Users listbox
        self.users_listbox = tk.Listbox(content_frame, font=('Arial', 11),
                                        bg=self.colors['light'], fg=self.colors['text'],
                                        relief=tk.FLAT, bd=0, highlightthickness=0)
        self.users_listbox.pack_forget()
        self.users_listbox.bind("<Double-Button-1>", self.client.open_chat)
        
        # Bottom buttons
        bottom_frame = tk.Frame(self.main_frame, bg=self.colors['primary'])
        bottom_frame.pack(fill=tk.X, padx=30, pady=(0, 10))
        
        btn_container = tk.Frame(bottom_frame, bg=self.colors['primary'])
        btn_container.pack(side=tk.RIGHT)
        
        refresh_btn = tk.Button(btn_container, text="Refresh", font=('Arial', 11, 'bold'),
                               command=self.refresh_current_tab)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        self.root.after(100, lambda: apply_rounded_style(
            refresh_btn, 100, 38, 12, self.colors['primary'], 
            'white', self.colors['secondary'], shadow=False))
        
        check_btn = tk.Button(btn_container, text="Check Messages", 
                             font=('Arial', 11, 'bold'),
                             command=self.client.check_messages)
        check_btn.pack(side=tk.LEFT, padx=5)
        self.root.after(100, lambda: apply_rounded_style(
            check_btn, 160, 38, 12, self.colors['primary'], 
            'white', self.colors['secondary'], shadow=False))
        
        # Status bar
        self.status_label = tk.Label(self.main_frame, 
                                     text="not connected / logged in as client#",
                                     font=('Arial', 11), bg=self.colors['primary'],
                                     fg='white', anchor='w', padx=30, pady=15)
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.current_tab = 'mail'

    def _style_tabs(self):
        """Apply rounded styles to tab buttons."""
        apply_rounded_style(self.mail_tab_btn, 100, 38, 12, 
                           self.colors['secondary'], self.colors['text'], 
                           self.colors['hover'])
        apply_rounded_style(self.users_tab_btn, 100, 38, 12, 
                           self.colors['light'], self.colors['text'], 
                           self.colors['hover'])

    # ============================================================
    # HELPER METHODS
    # ============================================================
    def _clear_placeholder(self, event, text):
        """Clear placeholder text on focus."""
        if event.widget.get() == text:
            event.widget.delete(0, tk.END)
            event.widget.config(fg=self.colors['text'])

    def _clear_password_placeholder(self, event):
        """Clear password placeholder and enable masking."""
        if event.widget.get() == "Şifrenizi Giriniz":
            event.widget.delete(0, tk.END)
            event.widget.config(show="*", fg=self.colors['text'])

    def show_login(self):
        """Show login screen."""
        self.register_frame.pack_forget()
        self.main_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)

    def show_register(self):
        """Show register screen."""
        self.login_frame.pack_forget()
        self.main_frame.pack_forget()
        self.register_frame.pack(fill=tk.BOTH, expand=True)

    def show_main(self, username):
        """Show main screen after successful login/register."""
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.welcome_label.config(text=f"Welcome, {username}")
        self.status_label.config(text=f"logged in as {username}")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

    def switch_tab(self, tab_name):
        """Switch between mail and users tabs."""
        self.current_tab = tab_name
        
        if tab_name == 'mail':
            # Update tab colors
            apply_rounded_style(self.mail_tab_btn, 100, 38, 12,
                               self.colors['secondary'], self.colors['text'],
                               self.colors['hover'])
            apply_rounded_style(self.users_tab_btn, 100, 38, 12,
                               self.colors['light'], self.colors['text'],
                               self.colors['hover'])
            
            self.users_listbox.pack_forget()
            self.mail_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        else:
            # Update tab colors
            apply_rounded_style(self.mail_tab_btn, 100, 38, 12,
                               self.colors['light'], self.colors['text'],
                               self.colors['hover'])
            apply_rounded_style(self.users_tab_btn, 100, 38, 12,
                               self.colors['secondary'], self.colors['text'],
                               self.colors['hover'])
            
            self.mail_listbox.pack_forget()
            self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
    def sign_out(self):
        """Sign out and return to login screen."""
        # Clear fields
        self.login_username_entry.delete(0, tk.END)
        self.login_password_entry.delete(0, tk.END)
        self.login_username_entry.insert(0, "Mailinizi Giriniz")
        self.login_password_entry.insert(0, "Şifrenizi Giriniz")
        self.login_password_entry.config(show="")

        # Return to login UI
        self.main_frame.pack_forget()
        self.show_login()

    def refresh_current_tab(self):
        """Refresh currently active tab."""
        if self.current_tab == 'mail':
            self.client.refresh_mail()
        else:
            self.client.refresh_users()

    # Properties for backward compatibility
    @property
    def username_entry(self):
        return self.reg_username_entry
    
    @property
    def password_entry(self):
        return self.reg_password_entry
    
    @property
    def image_label(self):
        return self.reg_image_label


# ================================================================
# 💬 CHAT WINDOW
# ================================================================
class ChatWindow:
    def __init__(self, client, receiver):
        self.client = client
        self.receiver = receiver

        self.win = tk.Toplevel(client.root)
        self.win.title(f"Chat: {receiver}")
        self.win.geometry("600x500")
        self.win.configure(bg='#5B4FDB')

        self.win.grab_set()
        self.win.focus_force()

        # Chat area
        chat_container = tk.Frame(self.win, bg='#8B85D8')
        chat_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.chat_area = scrolledtext.ScrolledText(
            chat_container, wrap=tk.WORD, state="disabled", 
            font=('Arial', 11), bg='#B8B3E8', fg='#2D2D2D',
            relief=tk.FLAT, bd=0)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Input area
        input_frame = tk.Frame(self.win, bg='#5B4FDB')
        input_frame.pack(fill=tk.X, padx=20, pady=(0, 20))

        self.entry = tk.Entry(input_frame, font=('Arial', 12), 
                             bg='#B8B3E8', fg='#2D2D2D', 
                             relief=tk.FLAT, bd=0)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, 
                       ipady=8, padx=(0, 10))
        self.entry.focus_set()
        self.entry.bind("<Return>", lambda e: self.send_message())

        send_btn = tk.Button(input_frame, text="Send", 
                           font=('Arial', 11, 'bold'),
                           command=self.send_message)
        send_btn.pack(side=tk.RIGHT)
        
        # Apply rounded style
        self.win.after(100, lambda: apply_rounded_style(
            send_btn, 100, 38, 12, '#8B85D8', 'white', '#A39BEF'))

    def send_message(self):
        """Send message to receiver."""
        msg = self.entry.get().strip()
        if not msg:
            return
        
        ok = self.client.send_message(self.receiver, msg)
        if ok:
            self.add_message(f"You: {msg}")
            self.entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Message could not be sent.")

    def add_message(self, text):
        """Add message to chat area."""
        self.chat_area.config(state="normal")
        self.chat_area.insert(tk.END, text + "\n\n")
        self.chat_area.config(state="disabled")
        self.chat_area.see(tk.END)