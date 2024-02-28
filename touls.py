import os
import tkinter as tk
import bcrypt
import random
import string
import base64
from cryptography.fernet import Fernet

# Clé de chiffrement
key = b'"\xb7\x1b\x11\xc8E"\xc4w/o\xa8\xcf\xb6:\xac\x14fx\xfb\xcbx\x84\xf2\x03\xd3~\xf1\xa0kn\x17' 


# Générer une clé robuste
def generer_cle_robuste(longueur=32):
    return os.urandom(longueur)

def encode_64(cle):
    # Encoder la clé en base64
    return base64.urlsafe_b64encode(cle)

def decode_64(cle64):
    # Décoder la clé
    return base64.urlsafe_b64decode(cle64)

def encrypt_password(password):
    # Encodage de la clé en base64
    cle_encodee = encode_64(key)
    
    # Création d'un objet Fernet avec la clé encodée
    cipher_suite = Fernet(cle_encodee)
    
    # Chiffrement du mot de passe
    encrypted_password = cipher_suite.encrypt(password.encode())
    
    return encrypted_password

# Fonction pour déchiffrer un mot de passe
def decrypt_password(encrypted_password):
    # Décoder la clé base64
    decoded_key = base64.urlsafe_b64encode(key)
    
    # Créer un objet Fernet avec la clé décodée
    cipher_suite = Fernet(decoded_key)
    
    # Décrypter le mot de passe et le décoder
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    
    return decrypted_password

def generate_strong_password(length=12, password_e=None):
    # Vérifier si password_e est spécifié
    if password_e is None:
        raise ValueError("Password entry is not specified")

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

    print("Password:", f"[{password}]")
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
