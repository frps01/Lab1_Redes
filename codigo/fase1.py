"""
Fase 1: Identidad criptográfica (KDF + RSA)
-------------------------------------------
- Construye una "clave fuerte" a partir de Nombre + Rol usando PBKDF2.
- Agrega un SALT aleatorio para que dos personas con datos parecidos
  generen claves distintas.
- Genera un par de llaves RSA de 2048 bits para cada miembro.
"""

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa

# Parámetros del laboratorio
ITERACIONES = 200_000     # iteraciones de PBKDF2 (mientras más, más costoso de atacar)
LARGO_CLAVE = 32          # 32 bytes = 256 bits derivados
LARGO_SALT  = 16          # 16 bytes = 128 bits de SALT
RSA_BITS    = 2048

CARPETA_KEYS = "keys"


# Nombre función: generar_salt
# Parámetros: ninguno
# Descripción: devuelve LARGO_SALT bytes aleatorios usando os.urandom.
def generar_salt():
    return os.urandom(LARGO_SALT)


# Nombre función: derivar_clave
# Parámetros: nombre (str), rol (str), salt (bytes)
# Descripción: arma la base "nombre|rol" y aplica PBKDF2-HMAC-SHA256 con SALT
#              para obtener 32 bytes pseudoaleatorios.
def derivar_clave(nombre, rol, salt):
    base = f"{nombre}|{rol}".encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=LARGO_CLAVE,
        salt=salt,
        iterations=ITERACIONES,
    )
    return kdf.derive(base)


# Nombre función: generar_par_rsa
# Parámetros: ninguno
# Descripción: genera una llave privada RSA de 2048 bits y su pública.
def generar_par_rsa():
    privada = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    publica = privada.public_key()
    return privada, publica


# Nombre función: guardar_llaves
# Parámetros: miembro (str), privada, publica, password (bytes)
# Descripción: guarda la privada en PEM cifrada con `password` y la pública en PEM.
def guardar_llaves(miembro, privada, publica, password):
    pem_priv = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    pem_pub = publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(f"{CARPETA_KEYS}/{miembro}_private.pem", "wb") as f:
        f.write(pem_priv)
    with open(f"{CARPETA_KEYS}/{miembro}_public.pem", "wb") as f:
        f.write(pem_pub)


# Nombre función: guardar_salt
# Parámetros: miembro (str), salt (bytes)
# Descripción: guarda el SALT del miembro en un archivo .salt.
def guardar_salt(miembro, salt):
    with open(f"{CARPETA_KEYS}/{miembro}.salt", "wb") as f:
        f.write(salt)


# Nombre función: cargar_llave_privada
# Parámetros: miembro (str), password (bytes)
# Descripción: lee y descifra la llave privada del miembro.
def cargar_llave_privada(miembro, password):
    with open(f"{CARPETA_KEYS}/{miembro}_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


# Nombre función: cargar_llave_publica
# Parámetros: miembro (str)
# Descripción: lee la llave pública del miembro.
def cargar_llave_publica(miembro):
    with open(f"{CARPETA_KEYS}/{miembro}_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


# Nombre función: cargar_salt
# Parámetros: miembro (str)
# Descripción: lee el SALT guardado para un miembro.
def cargar_salt(miembro):
    with open(f"{CARPETA_KEYS}/{miembro}.salt", "rb") as f:
        return f.read()


# Nombre función: crear_identidad
# Parámetros: miembro (str), nombre (str), rol (str)
# Descripción: pipeline completo: SALT → KDF → par RSA → guardar archivos.
def crear_identidad(miembro, nombre, rol):
    print(f"\nGenerando identidad para {miembro} ({nombre}, {rol})")

    salt = generar_salt()
    clave_kdf = derivar_clave(nombre, rol, salt)
    privada, publica = generar_par_rsa()

    guardar_salt(miembro, salt)
    guardar_llaves(miembro, privada, publica, password=clave_kdf)

    print(f"  SALT       : {salt.hex()}")
    print(f"  Clave KDF  : {clave_kdf.hex()[:16]}... (32 bytes)")
    print(f"  Llaves RSA : {miembro}_private.pem, {miembro}_public.pem")


def main():
    os.makedirs(CARPETA_KEYS, exist_ok=True)
    print("=" * 60)
    print("FASE 1: Identidad criptográfica (KDF + RSA)")
    print("=" * 60)

    miembros = [
        ("MiembroA", "Moises Gonzalez", "Comandante"),
        ("MiembroB", "Elena Vargas",    "Estratega"),
        ("MiembroC", "Dimitri Volkov",  "Ingeniero"),
        ("MiembroD", "Sofia Reyes",     "Operador"),
    ]
    for miembro, nombre, rol in miembros:
        crear_identidad(miembro, nombre, rol)

    print("\nFase 1 completada. Archivos en ./keys/")


if __name__ == "__main__":
    main()
