import os
import tkinter as tk
import sqlite3
import re
import bcrypt
import random
import string
import base64
from cryptography.fernet import Fernet


def get_key():
    try:
        # Connexion à la base de données
        conn = sqlite3.connect("PM.db")
        cursor = conn.cursor()

        # Exécuter une requête pour récupérer le mot de passe correspondant à l'utilisateur
        cursor.execute("SELECT value FROM configs WHERE key=?", ('KEY',))
        row = cursor.fetchone()

        # Vérifier si un enregistrement a été trouvé
        if row:
            return row[0]  # Renvoyer la valeur

    except sqlite3.Error as e:
        tk.messagebox.showerror("Error",f"Error while retrieving the key {e}")

    finally:
        if conn:
            conn.close()

    return None  # Renvoyer None si aucun mot de passe n'a été trouvé

def add_new_key(key):
    try:
        conn = sqlite3.connect("PM.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO configs (key,value) VALUES (?,?)", ('KEY',key))
        conn.commit()
        return True
    except sqlite3.Error as e:
        tk.messagebox.showerror("Error", f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def init_key():
    try:
        if not get_key():
            key = generate_key(32)
            add_new_key(key)
            print(key)

    except sqlite3.Error as e:
        tk.messagebox.showerror("Error", f"Database error: {e}")

# Générer une clé robuste
def generate_key(length=32):
    return os.urandom(length)

def encode_64(key):
    key = get_key()
    # Encoder la clé en base64
    return base64.urlsafe_b64encode(key)

def decode_64(key64):
    # Décoder la clé
    return base64.urlsafe_b64decode(key64)

def encrypt_password(password):
    key = get_key()
    # Encodage de la clé en base64
    encoded_key = encode_64(key)
    
    # Création d'un objet Fernet avec la clé encodée
    fr = Fernet(encoded_key)
    
    # Chiffrement du mot de passe
    encrypted_password = fr.encrypt(password.encode())
    
    return encrypted_password

# Fonction pour déchiffrer un mot de passe
def decrypt_password(encrypted_password):
    key = get_key()
    # Décoder la clé base64
    decoded_key = base64.urlsafe_b64encode(key)
    
    # Créer un objet Fernet avec la clé décodée
    fr = Fernet(decoded_key)
    
    # Décrypter le mot de passe et le décoder
    decrypted_password = fr.decrypt(encrypted_password).decode()
    
    return decrypted_password

def generate_strong_password(length=12, password_e=None):
    # Vérifier si password_e est spécifié
    if password_e is None:
        raise ValueError("Password entry is not specified !")

    # Chars à utiliser pour générer le mot de passe
    chars = string.ascii_letters + string.digits + string.punctuation

    # Assurer qu'au moins un caractère de chaque catégorie est inclus dans le mot de passe
    password = ''.join(random.choice(string.ascii_lowercase) for _ in range(3))
    password += ''.join(random.choice(string.ascii_uppercase) for _ in range(3))
    password += ''.join(random.choice(string.digits) for _ in range(2))
    password += ''.join(random.choice(string.punctuation) for _ in range(2))

    # Ajouter des caractères aléatoires jusqu'à la longueur désirée
    password += ''.join(random.choice(chars) for _ in range(length - len(password)))

    # Mélanger les caractères pour augmenter l'entropie
    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)

    # Effacer le contenu existant de l'entrée de mot de passe et insérer le nouveau mot de passe généré
    if password_e:
        password_e.delete(0, tk.END)
        password_e.insert(0, password)

    return password

# Fonction pour chiffrer un mot de passe
def encrypt_password_for_user(password):
    # Générer un salt aléatoire
    salt = bcrypt.gensalt()

    # Crypter le mot de passe avec le salt
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    return hashed_password

def check_password(input_password, hashed_password):
    if (not input_password or hashed_password == None ): return False
    # Vérifier si le mot de passe en texte brut correspond au mot de passe crypté
    return bcrypt.checkpw(input_password.encode(), hashed_password)

def validate_username(username):
    # Supprimer les espaces blancs au début et à la fin
    username = username.strip()

    # Vérification de la longueur minimale
    if len(username) < 5:
        tk.messagebox.showinfo("Info", "Username must have more than 5 characters !")
        return False

    # Vérification de la présence de caractères autorisés
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        tk.messagebox.showinfo("Info", 'Special characters are not allowed except "-" and "_" !')
        return False

    return True

def validate_password(password):
    # Vérification de la longueur minimale
    if len(password) < 12:
        tk.messagebox.showinfo("Info", "Password must have more than 12 characters or equal !")
        return False

    # Vérification de la présence de lettres minuscules, majuscules, chiffres et caractères spéciaux
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_^\s])[A-Za-z\d\W_]+$', password):
        tk.messagebox.showinfo("Info", "Invalid password !")
        return False

    return True
