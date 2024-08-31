import tkinter as tk
from tkinter import messagebox  # Import messagebox from tkinter
from tkinter import ttk
import sqlite3
import tools as t
import pyperclip  # Module to copy to clipboard

# Function to initialize the database
def init_database():
    try:
        conn = sqlite3.connect("PM.db")
        cursor = conn.cursor()
        # create passwords table if not exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            site TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """)
        # create users table if not exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
                        (id INTEGER PRIMARY KEY, 
                        username TEXT NOT NULL UNIQUE, 
                        password TEXT NOT NULL)''')
        
        # create configs table if not exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS configs
                        (id INTEGER PRIMARY KEY, 
                        key TEXT NOT NULL UNIQUE, 
                        value TEXT NOT NULL)''')
        conn.commit()
        t.init_key()
    except sqlite3.Error as e:
        tk.messagebox.showerror("Error", f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def login_interface():
    login_window = tk.Tk()
    login_window.title("Connection interface")
    login_window.geometry('350x200')

    # Lock login window dimensions
    login_window.resizable(False, False)

    login_frame = tk.Frame(login_window)
    login_frame.pack(padx=20, pady=20)

    ttk.Label(login_frame, text="Login", font=("Helvetica", 16)).grid(row=0, columnspan=3)

    ttk.Label(login_frame, text="Username:").grid(row=1, column=0)
    username_entry = ttk.Entry(login_frame)
    username_entry.grid(row=1, column=1,pady=10)

    ttk.Label(login_frame, text="Password:").grid(row=2, column=0)
    password_entry = ttk.Entry(login_frame, show="*")
    password_entry.grid(row=2, column=1)

    ttk.Button(login_frame, text="Login",command=lambda:login(username_entry.get(),password_entry.get(),login_window)).grid(row=3, column=0, columnspan=2, pady=10,sticky="w")

    ttk.Button(login_frame, text="Register",command=lambda:register_interface()).grid(row=3, column=1, columnspan=2, pady=10,sticky="e")

    login_window.mainloop()

def register_interface():
    register_window = tk.Toplevel()
    register_window.title("User Registration")
    register_window.geometry('350x200')

    # Lock register window dimensions
    register_window.resizable(False, False)

    register_frame = tk.Frame(register_window)
    register_frame.pack(padx=20, pady=20)


    ttk.Label(register_frame, text="Register User", font=("Helvetica", 16)).grid(row=0, columnspan=3)

    ttk.Label(register_frame, text="Username:").grid(row=1, column=0, sticky="w")
    username_entry = ttk.Entry(register_frame)
    username_entry.grid(row=1, column=1,pady=10, sticky="w")

    ttk.Label(register_frame, text="Password:").grid(row=2, column=0, sticky="w")
    password_entry = ttk.Entry(register_frame, show="*")
    password_entry.grid(row=2, column=1, sticky="w")

    # Function to toggle password display
    def toggle_password():
        cheked = show_password_var.get()
        if cheked == 1:
            password_entry.config(show="")
        else:
            password_entry.config(show="*")

    # Checkbox to show/hide password
    show_password_var = tk.BooleanVar()
    show_password_checkbox = ttk.Checkbutton(register_frame, text="Show password", variable=show_password_var, command=toggle_password)
    show_password_checkbox.grid(row=3, column=1, sticky="w")

    ttk.Button(register_frame, text="Register", 
               command=lambda: register_user(username_entry.get(), password_entry.get(), register_window)).grid(row=4, column=1, sticky='nesw',pady=20)
    ttk.Button(register_frame, text="Generate", 
               command=lambda: t.generate_strong_password(12, password_entry)).grid(row=2, column=2, padx=10)
    
    # Block access to main window until modal window is closed
    register_frame.grab_set()

    # Wait for the modal window to close
    register_window.wait_window()

def update_password_interface(id,site_e,username_e,password_e,tree_e):
    # Create the update password window
    update_password_window = tk.Toplevel()
    update_password_window.title("Edit password")
    update_password_window.geometry("350x200")

    # Lock update window dimensions
    update_password_window.resizable(False, False)

    # Create style
    style = ttk.Style()
    style.configure("TButton", foreground="black", background="lightgrey")

    # Create principal frame
    update_password_frame = ttk.Frame(update_password_window)
    update_password_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

    # Create labels and entries
    ttk.Label(update_password_frame, text="Site:").grid(row=0, column=0, pady=10, sticky="e")
    site_entry = ttk.Entry(update_password_frame)
    site_entry.grid(row=0, column=1, padx=10, sticky="w")
    site_entry.insert(tk.END, site_e)

    ttk.Label(update_password_frame, text="Username:").grid(row=1, column=0, pady=10, sticky="e")
    username_entry = ttk.Entry(update_password_frame)
    username_entry.grid(row=1, column=1, padx=10, sticky="w")
    username_entry.insert(tk.END, username_e)

    ttk.Label(update_password_frame, text="Password:").grid(row=2, column=0, pady=10, sticky="e")
    password_entry = ttk.Entry(update_password_frame, show="*")
    password_entry.grid(row=2, column=1, padx=10, sticky="w")
    password_entry.insert(tk.END, password_e)

    # Create buttons
    generate_button = ttk.Button(update_password_frame, text="Generate", 
                                 command=lambda: t.generate_strong_password(12, password_entry))
    generate_button.grid(row=3, column=0, pady=10, padx=10, sticky="w")

    add_button = ttk.Button(update_password_frame, text="Update", 
                            command=lambda: edit_password(id,site_entry.get(), username_entry.get(), password_entry.get(),update_password_window,tree_e))
    add_button.grid(row=3, column=1, pady=10, padx=10, sticky="e")
    
    # Block access to update password window until modal window is closed
    update_password_window.grab_set()

    # Wait for the modal window to close
    update_password_window.wait_window()

def add_password_interface(tree_e):
    # Création de la fenêtre "New password"
    new_password_window = tk.Toplevel()
    new_password_window.title("New password")
    new_password_window.geometry("350x200")

    # Verrouiller les dimensions de la fenêtre principale
    new_password_window.resizable(False, False)

    # Création du style
    style = ttk.Style()
    style.configure("TButton", foreground="black", background="lightgrey")

    # Création du cadre principal
    new_password_frame = ttk.Frame(new_password_window)
    new_password_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

    # Création des libellés et des entrées
    ttk.Label(new_password_frame, text="Site:").grid(row=0, column=0, pady=10, sticky="e")
    site_entry = ttk.Entry(new_password_frame)
    site_entry.grid(row=0, column=1, padx=10, sticky="w")

    ttk.Label(new_password_frame, text="Username:").grid(row=1, column=0, pady=10, sticky="e")
    username_entry = ttk.Entry(new_password_frame)
    username_entry.grid(row=1, column=1, padx=10, sticky="w")

    ttk.Label(new_password_frame, text="Password:").grid(row=2, column=0, pady=10, sticky="e")
    password_entry = ttk.Entry(new_password_frame, show="*")
    password_entry.grid(row=2, column=1, padx=10, sticky="w")

    # Création des boutons
    generate_button = ttk.Button(new_password_frame, text="Generate", 
                                 command=lambda: t.generate_strong_password(12, password_entry))
    generate_button.grid(row=3, column=0, pady=10, padx=10, sticky="w")

    add_button = ttk.Button(new_password_frame, text="Add", 
                            command=lambda: add_new_password(site_entry.get(), username_entry.get(), password_entry.get(),new_password_window,tree_e))
    add_button.grid(row=3, column=1, pady=10, padx=10, sticky="e")

    # Bloquer l'accès à la fenêtre principale jusqu'à ce que la fenêtre modale soit fermée
    new_password_window.grab_set()

    # Attendre que la fenêtre modale soit fermée
    new_password_window.wait_window()

def register_user(username, password,register_window):
    if t.validate_username(username) and t.validate_password(password):
        try:
            # Connexion à la base de données
            conn = sqlite3.connect("PM.db")
            cursor = conn.cursor()

            encrypt_pass = t.encrypt_password_for_user(password)
            # Insertion de l'utilisateur dans la table
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, encrypt_pass))
            conn.commit()
            register_window.destroy()
            tk.messagebox.showinfo("Success", "User registered successfully!")
        except sqlite3.Error as e:
            tk.messagebox.showerror("Error", f"Database error: {e}")
        finally:
            if conn:
                conn.close()

def add_password(site, username, password):
    # valider l'identifiant
    if not t.validate_username(username):
        return False
    
    # valider le mot de passe
    if not t.validate_password(password):
        return False
    
    encrypted_password = t.encrypt_password(password)
    try:
        conn = sqlite3.connect("PM.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO passwords (site, username, password) VALUES (?, ?, ?)", 
                       (site, username, encrypted_password))
        conn.commit()
        return True
    except sqlite3.Error as e:
        tk.messagebox.showerror("Error", f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def get_passwords():
    try:
        conn = sqlite3.connect("PM.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM passwords")
        rows = cursor.fetchall()
        passwords = []

        for row in rows:
            try:
                password = t.decrypt_password(row[3])
                passwords.append((row[0],row[1], row[2], password))
            except Exception as e:
                print(e)
                tk.messagebox.showerror("Error", f"Error decrypting password: {e}")
        return passwords
    except sqlite3.Error as e:
        print(e)
        tk.messagebox.showerror("Error", f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def update_password(entry_id,new_site, new_username, new_password):
    if entry_id and new_site and new_username and new_password:
        # valider l'identifiant
        if not t.validate_username(new_username):
            return False
        # valider le mot de passe
        if not t.validate_password(new_password):
            return False
        # Chiffrer le nouveau mot de passe
        encrypted_password = t.encrypt_password(new_password)
        try:
            conn = sqlite3.connect("PM.db")
            cursor = conn.cursor()

            cursor.execute("UPDATE passwords SET site=?, username=?, password=? WHERE id=?", 
                        (new_site, new_username, encrypted_password, entry_id))
            conn.commit()
            return True
        except sqlite3.Error as e:
            tk.messagebox.showerror("Error", f"Database error: {e}")
            return False
        finally:
            if conn:
                conn.close()
    else:
        tk.messagebox.showinfo("Info", "One or more fields are empty !")
        return False

def edit_password(id,site,username,password,w_e,tree_e):
    if id and site and username and password:
        if update_password(id,site,username,password):
            w_e.destroy()
            create_table(tree_e)
    else:
        # Afficher un message d'information
        tk.messagebox.showinfo("Info", "One or more fields are empty")

def login(username,password,login_window):
    # Récupérer les informations de connexion
    password_from_database = get_password_from_database(username)
    if(username and password):
        # Vérifier si les informations sont correctes
        if t.check_password(password, password_from_database):
            # fermer la fenêtre login
            login_window.destroy()
            # Ouvrir l'interface principale
            main_window()
        else:
            # Afficher un message d'erreur
            tk.messagebox.showerror("Error", "Invalid username or password")

def add_new_password(site,username,password,fn,tree_e):
    if site and username and password:
        if add_password(site, username, password):
            fn.destroy()
            create_table(tree_e)
    else:
        # Afficher un message d'information
        tk.messagebox.showinfo("Info", "One or more fields are empty")

def get_password_from_database(username):
    try:
        # Connexion à la base de données
        conn = sqlite3.connect("PM.db")
        cursor = conn.cursor()

        # Exécuter une requête pour récupérer le mot de passe correspondant à l'utilisateur
        cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        row = cursor.fetchone()

        # Vérifier si un enregistrement a été trouvé
        if row:
            return row[0]  # Renvoyer le mot de passe trouvé

    except sqlite3.Error as e:
        tk.messagebox.showerror("Error",f"Error while retrieving the password {e}")

    finally:
        if conn:
            conn.close()

    return None  # Renvoyer None si aucun mot de passe n'a été trouvé

def delete_password(entry_id):
    try:
        # Connexion à la base de données
        conn = sqlite3.connect("PM.db")
        cursor = conn.cursor()

        # Exécuter la requête de suppression
        cursor.execute("DELETE FROM passwords WHERE id=?", (entry_id,))

        # Valider la transaction
        conn.commit()
        return True
    except sqlite3.Error as e:
        # Afficher une erreur en cas d'échec de la suppression
        tk.messagebox.showerror("Error", f"Database error: {e}")
        return False
    finally:
        # Fermer la connexion à la base de données
        if conn:
            conn.close()

def create_table(tree_e):
        # récuperer la liste des sites enregistrés
        passwords = get_passwords()
        # Supprimer tous les éléments actuels de l'arbre
        tree_e.delete(*tree_e.get_children())

        # Ajouter les données à la table
        for row in passwords:
            tree_e.insert("", tk.END, text=row[0], values=(row[0],row[1],row[2], '*********', row[3]))

def add_entry(tree_e):
    # Fonction pour ajouter une entrée
    add_password_interface(tree_e)

def update_entry(tree_e):
    # Récupérer l'élément sélectionné dans la TreeView
    item_id = tree_e.focus()

    # Vérifier si un élément est sélectionné
    if item_id:
        # Récupérer les valeurs de l'élément sélectionné
        values = tree_e.item(item_id, "values")

        # Vérifier si des valeurs ont été récupérées
        if values:
            update_password_interface(values[0],values[1],values[2],values[3],tree_e)
        else:
            tk.messagebox.showinfo("Info","No value associated with this item in the TreeView.")
    else:
        tk.messagebox.showinfo("Info","No item selected in the TreeView.")

def delete_entry(tree_e):
    # Récupérer l'élément sélectionné dans la TreeView
    item_id = tree_e.focus()

    # Vérifier si un élément est sélectionné
    if item_id:
        # Récupérer les valeurs de l'élément sélectionné
        values = tree_e.item(item_id, "values")

        # Vérifier si des valeurs ont été récupérées
        if values:
            # Demander une confirmation à l'utilisateur avant de supprimer l'entrée
            confirmation = tk.messagebox.askyesno("Confirmation", "Do you really want to delete this item ?")

            if confirmation:
                # Supprimer l'entrée de la base de données
                if delete_password(values[0]):
                    # Supprimer l'élément de la TreeView
                    tree_e.delete(item_id)
                    create_table(tree_e)
                    # Afficher un message de confirmation
                    tk.messagebox.showinfo("Success","The item has been successfully deleted.")
        else:
            tk.messagebox.showinfo("Info","No value associated with this item in the TreeView.")
    else:
        tk.messagebox.showinfo("Info","No item selected in the TreeView.")

def copy_username(tree):
    selected_item = tree.selection()
    if selected_item:
        username = tree.item(selected_item)["values"][2]
        pyperclip.copy(username)
    else:
        tk.messagebox.showinfo("Info","No item selected in the TreeView.")

def copy_password(tree):
    selected_item = tree.selection()
    if selected_item:
        password = tree.item(selected_item)["values"][4]
        pyperclip.copy(password)
    else:
        tk.messagebox.showinfo("Info","No item selected in the TreeView.")

def main_window():
    # Créer la fenêtre principale
    main_window = tk.Tk()
    main_window.title("Password Manager")
    main_window.geometry("950x600")

    # Verrouiller les dimensions de la fenêtre principale
    main_window.resizable(False, False)

    # Création du style
    style = ttk.Style()
    style.configure("TButton", foreground="black", background="lightgrey")

    # Création de la table de données à gauche
    tree_frame = ttk.Frame(main_window)
    tree_frame.pack(side=tk.LEFT, fill=tk.Y)

    tree = ttk.Treeview(tree_frame, columns=("ID","Site", "Username", "Password","PasswordText"), show="headings")
    tree.heading("ID", text="#")
    tree.heading("Site", text="Site")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.heading("PasswordText", text="Password")
    
    # Masquer la colonne "PasswordText" dans l'en-tête
    tree["displaycolumns"] = ("ID", "Site", "Username", "Password")
    
    # Centrer le texte dans la colonne PasswordText
    tree.heading("Password", text="Password", anchor="center")
    tree.heading("Username", text="Username", anchor="center")
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    create_table(tree)  # Créer la table de données

    # Création des boutons à droite
    button_frame = ttk.Frame(main_window)
    button_frame.pack(side=tk.RIGHT, fill=tk.Y)

    add_button = ttk.Button(button_frame, text="Add", command=lambda: add_entry(tree))
    add_button.pack(pady=10, padx=20, fill=tk.X)

    update_button = ttk.Button(button_frame, text="Update", command=lambda: update_entry(tree)) 
    update_button.pack(pady=10, padx=20, fill=tk.X)

    delete_button = ttk.Button(button_frame, text="Delete", command=lambda: delete_entry(tree))
    delete_button.pack(pady=10, padx=20, fill=tk.X)

    # boutons de copie de l'identifiant
    copy_username_button = ttk.Button(button_frame, text="Copy username", command=lambda: copy_username(tree))
    copy_username_button.pack(pady=10, padx=20, fill=tk.X)

    # boutons de copie du mot de passe
    copy_password_button = ttk.Button(button_frame, text="Copy password", command=lambda: copy_password(tree))
    copy_password_button.pack(pady=10, padx=20, fill=tk.X)

    # fermer l'application
    quit_button = ttk.Button(button_frame, text="Quit", command= main_window.destroy)
    quit_button.pack(pady=10, padx=20, fill=tk.X)

    main_window.mainloop()

if __name__ == "__main__":
    init_database()
    login_interface()