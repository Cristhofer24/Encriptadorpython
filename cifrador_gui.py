import os
import rsa
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pgpy
from pgpy import PGPKey, PGPMessage
from tkinter import simpledialog, messagebox
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, CompressionAlgorithm  # Importación corregida
from datetime import timedelta
# Función para cifrar datos simétricamente con una contraseña personalizada
def encrypt_symmetric(password, data):
    key = password.encode().ljust(32)[:32]  # Asegurar que el key tenga 32 bytes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

# Función para descifrar datos simétricos con una contraseña personalizada
def decrypt_symmetric(password, encrypted_data):
    key = password.encode().ljust(32)[:32]
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

# Genera claves RSA pública y privada para cifrado asimétrico
def generate_rsa_keys():
    public_key, private_key = rsa.newkeys(2048)
    return public_key, private_key

# Función para cifrar el archivo seleccionado (Simétrico)
def encrypt_file_symmetric():
    file_path = filedialog.askopenfilename(title="Selecciona un archivo para cifrar (Simétrico)")
    if not file_path:
        return
    
    password = simpledialog.askstring("Contraseña", "Introduce una contraseña para cifrar:", show="*")
    if not password:
        return

    try:
        with open(file_path, "rb") as file:
            data = file.read()
        encrypted_data = encrypt_symmetric(password, data)

        output_file = file_path + ".enc"
        with open(output_file, "wb") as file:
            file.write(encrypted_data)

        messagebox.showinfo("Éxito", f"Archivo cifrado simétricamente guardado como: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar el archivo: {e}")

# Función para descifrar archivo (Simétrico)
def decrypt_file_symmetric():
    file_path = filedialog.askopenfilename(title="Selecciona un archivo para descifrar (Simétrico)", filetypes=[("Encrypted files", "*.enc")])
    if not file_path:
        return
    
    password = simpledialog.askstring("Contraseña", "Introduce la contraseña para descifrar:", show="*")
    if not password:
        return

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = decrypt_symmetric(password, encrypted_data)

        output_file = file_path.replace(".enc", "_decrypted")
        with open(output_file, "wb") as file:
            file.write(decrypted_data)

        messagebox.showinfo("Éxito", f"Archivo descifrado guardado como: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar el archivo: {e}")

# Función para cifrar texto ingresado por el usuario con RSA (Asimétrico)


# Directorio de salida para guardar las claves y el mensaje cifrado
output_directory = r"C:\Users\USER\Documents\ITSQMET\Cuarto Nivel\Seguridad Informatica\Programa de encriptacion\Claves Asimetricas"
os.makedirs(output_directory, exist_ok=True)  # Asegura que el directorio existe

# Función para generar claves RSA compatibles con PGP
def generate_pgp_rsa_keys():
    # Crear una nueva clave RSA para PGP (2048 bits)
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    
    # Crear una UID (identificación de usuario) con email y nombre opcional
    uid = pgpy.PGPUID.new("User Cris", email="cgramal@yo.com")
    
    # Añadir UID a la clave con permisos de cifrado y firma, e incluir la expiración (2 años)
    key.add_uid(uid,
                usage={KeyFlags.EncryptCommunications, KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA256],
                expiration=timedelta(days=365 * 2))  # Expira en 2 años
    
    return key

# Función para cifrar texto en formato compatible con PGP
def encrypt_input_text_asymmetric():
    # Solicitar al usuario el texto a cifrar
    text = simpledialog.askstring("Entrada de texto", "Escribe el texto a cifrar (Asimétrico):")
    if not text:
        return

    try:
        # Generar claves RSA compatibles con PGP
        key = generate_pgp_rsa_keys()

        # Crear mensaje PGP con el texto ingresado
        message = pgpy.PGPMessage.new(text)

        # Cifrar el mensaje con la clave pública
        with key.unlock("your_passphrase_here"):  # Asegura que la clave esté desbloqueada, si tiene una frase de paso
            encrypted_message = key.pubkey.encrypt(message)

        # Guardar la clave pública en formato PGP
        with open(os.path.join(output_directory, "public_key.asc"), "w") as pub_file:
            pub_file.write(str(key.pubkey))

        # Guardar la clave privada en formato PGP
        with open(os.path.join(output_directory, "private_key.asc"), "w") as priv_file:
            priv_file.write(str(key))

        # Guardar el mensaje cifrado en formato ASCII para compatibilidad con Kleopatra
        with open(os.path.join(output_directory, "encrypted_text.asc"), "w") as enc_file:
            enc_file.write(str(encrypted_message))

        # Mostrar mensaje de éxito
        messagebox.showinfo("Éxito", "Texto cifrado y claves guardadas exitosamente en " + output_directory)
    
    except Exception as e:
        # Mostrar mensaje de error si el cifrado falla
        messagebox.showerror("Error", f"Error al cifrar el texto: {e}")
# # Función para descifrar texto con RSA
# def decrypt_text_asymmetric():
#     private_key_path = filedialog.askopenfilename(title="Selecciona la clave privada para descifrar (Asimétrico)", filetypes=[("Private Key Files", "*.pem")])
#     if not private_key_path:
#         return

#     try:
#         with open(private_key_path, "rb") as priv_key_file:
#             private_key = rsa.PrivateKey.load_pkcs1(priv_key_file.read())

#         with open("encrypted_text.bin", "rb") as enc_text_file:
#             encrypted_text = enc_text_file.read()
#         decrypted_text = rsa.decrypt(encrypted_text, private_key).decode('utf-8')

#         messagebox.showinfo("Texto Descifrado", f"Texto descifrado: {decrypted_text}")
#     except Exception as e:
#         messagebox.showerror("Error", f"Error al descifrar el texto: {e}")

# Configura la interfaz gráfica con tkinter
root = tk.Tk()
root.title("Cifrador de Archivos y Texto")
root.geometry("500x600")
root.configure(bg="#282c34")

title_label = tk.Label(root, text="Cifrador de Archivos y Texto", font=("Arial", 18, "bold"), bg="#282c34", fg="#61dafb")
title_label.pack(pady=10)

# Botones para cifrado simétrico
encrypt_file_symmetric_button = tk.Button(
    root, text="Cifrar archivo (Simétrico)", font=("Arial", 12),
    command=encrypt_file_symmetric, bg="#61dafb", fg="#282c34", width=25, height=2
)
encrypt_file_symmetric_button.pack(pady=10)

decrypt_file_symmetric_button = tk.Button(
    root, text="Descifrar archivo (Simétrico)", font=("Arial", 12),
    command=decrypt_file_symmetric, bg="#61dafb", fg="#282c34", width=25, height=2
)
decrypt_file_symmetric_button.pack(pady=10)

# Botones para cifrado asimétrico
encrypt_text_asymmetric_button = tk.Button(
    root, text="Cifrar texto (Asimétrico)", font=("Arial", 12),
    command=encrypt_input_text_asymmetric, bg="#61dafb", fg="#282c34", width=25, height=2
)
encrypt_text_asymmetric_button.pack(pady=10)

# decrypt_text_asymmetric_button = tk.Button(
#     root, text="Descifrar texto (Asimétrico)", font=("Arial", 12),
#     command=decrypt_text_asymmetric, bg="#61dafb", fg="#282c34", width=25, height=2
# )
# decrypt_text_asymmetric_button.pack(pady=10)

root.mainloop()
