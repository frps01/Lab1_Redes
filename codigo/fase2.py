"""
Fase 2: Cifrado híbrido y comparación ECB vs CBC
------------------------------------------------
- Cifrado híbrido: AES-128 (rápido) para el archivo + RSA-OAEP (seguro)
  para enviar la clave AES al destinatario.
- Demostración visual de ECB vs CBC sobre el BMP del silo.
"""

import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fase1 import cargar_llave_publica, cargar_llave_privada, derivar_clave, cargar_salt

LARGO_AES   = 16   # AES-128 = 16 bytes de clave
LARGO_BLOQUE = 16  # AES tiene bloques de 16 bytes
HEADER_BMP  = 54   # tamaño del header BMP estándar


# ------------------------------------------------------------------
# Cifrado simétrico AES-128-CBC con padding PKCS7
# ------------------------------------------------------------------

# Nombre función: aes_cbc_cifrar
# Parámetros: clave (bytes 16), datos (bytes), iv (bytes 16)
# Descripción: cifra `datos` con AES-128-CBC aplicando padding PKCS7.
def aes_cbc_cifrar(clave, datos, iv):
    padder = padding.PKCS7(128).padder()
    datos_pad = padder.update(datos) + padder.finalize()
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(datos_pad) + encryptor.finalize()


# Nombre función: aes_cbc_descifrar
# Parámetros: clave (bytes 16), datos (bytes), iv (bytes 16)
# Descripción: descifra AES-128-CBC y quita el padding PKCS7.
def aes_cbc_descifrar(clave, datos, iv):
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plano_pad = decryptor.update(datos) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(plano_pad) + unpadder.finalize()


# ------------------------------------------------------------------
# Cifrado asimétrico RSA-OAEP (para envolver la clave AES)
# ------------------------------------------------------------------

# Nombre función: rsa_cifrar
# Parámetros: publica (RSA pública), datos (bytes)
# Descripción: cifra con RSA usando OAEP-SHA256 (relleno seguro recomendado).
def rsa_cifrar(publica, datos):
    return publica.encrypt(
        datos,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# Nombre función: rsa_descifrar
# Parámetros: privada (RSA privada), datos (bytes)
# Descripción: descifra con RSA-OAEP-SHA256.
def rsa_descifrar(privada, datos):
    return privada.decrypt(
        datos,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ------------------------------------------------------------------
# Cifrado híbrido (AES + RSA)
# ------------------------------------------------------------------

# Nombre función: cifrar_hibrido
# Parámetros: archivo_in (str), archivo_out (str), destinatario (str)
# Descripción: cifra el archivo con AES-128-CBC y la clave AES con RSA-OAEP.
#              Empaqueta [enc_clave_aes | iv | ciphertext] en el archivo de salida.
def cifrar_hibrido(archivo_in, archivo_out, destinatario):
    publica = cargar_llave_publica(destinatario)

    with open(archivo_in, "rb") as f:
        datos = f.read()

    clave_aes = os.urandom(LARGO_AES)
    iv = os.urandom(LARGO_BLOQUE)
    ciphertext = aes_cbc_cifrar(clave_aes, datos, iv)
    enc_clave = rsa_cifrar(publica, clave_aes)

    # Formato: [2 bytes len(enc_clave)] [enc_clave] [iv 16B] [ciphertext]
    paquete = len(enc_clave).to_bytes(2, "big") + enc_clave + iv + ciphertext
    with open(archivo_out, "wb") as f:
        f.write(paquete)

    print(f"  Archivo cifrado: {archivo_out} ({len(paquete)} bytes)")
    print(f"    Clave AES (hex): {clave_aes.hex()}")
    print(f"    IV (hex)       : {iv.hex()}")


# Nombre función: descifrar_hibrido
# Parámetros: archivo_in (str), archivo_out (str), destinatario (str), password (bytes)
# Descripción: invierte cifrar_hibrido. Recupera el archivo original.
def descifrar_hibrido(archivo_in, archivo_out, destinatario, password):
    privada = cargar_llave_privada(destinatario, password)
    with open(archivo_in, "rb") as f:
        paquete = f.read()

    largo = int.from_bytes(paquete[:2], "big")
    enc_clave = paquete[2:2 + largo]
    iv = paquete[2 + largo:2 + largo + 16]
    ciphertext = paquete[2 + largo + 16:]

    clave_aes = rsa_descifrar(privada, enc_clave)
    plano = aes_cbc_descifrar(clave_aes, ciphertext, iv)

    with open(archivo_out, "wb") as f:
        f.write(plano)

    print(f"  Archivo recuperado: {archivo_out} ({len(plano)} bytes)")


# ------------------------------------------------------------------
# Demostración ECB vs CBC sobre BMP
# ------------------------------------------------------------------

# Nombre función: cifrar_bmp
# Parámetros: clave (bytes 16), bmp (bytes), modo (str: "ECB" o "CBC"), iv (bytes o None)
# Descripción: cifra solo el cuerpo del BMP (mantiene el header de 54 bytes
#              intacto para que el archivo siga siendo visible como imagen).
def cifrar_bmp(clave, bmp, modo, iv=None):
    header = bmp[:HEADER_BMP]
    cuerpo = bmp[HEADER_BMP:]

    # Cortamos al múltiplo de 16 más cercano para no necesitar padding visible
    largo = len(cuerpo) - (len(cuerpo) % LARGO_BLOQUE)
    cuerpo_alineado = cuerpo[:largo]
    cola = cuerpo[largo:]

    if modo == "ECB":
        cipher = Cipher(algorithms.AES(clave), modes.ECB())
    else:
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))

    enc = cipher.encryptor()
    cuerpo_cifrado = enc.update(cuerpo_alineado) + enc.finalize()

    return header + cuerpo_cifrado + cola


# Nombre función: prueba_ecb_vs_cbc
# Parámetros: bmp_in (str)
# Descripción: cifra el BMP en ECB y CBC con la MISMA clave para comparar
#              visualmente la fuga de patrones.
def prueba_ecb_vs_cbc(bmp_in):
    print("\n  Comparación ECB vs CBC sobre", bmp_in)
    with open(bmp_in, "rb") as f:
        bmp = f.read()

    clave = os.urandom(LARGO_AES)
    iv = os.urandom(LARGO_BLOQUE)

    bmp_ecb = cifrar_bmp(clave, bmp, "ECB")
    bmp_cbc = cifrar_bmp(clave, bmp, "CBC", iv)

    with open("output/silo_ECB.bmp", "wb") as f:
        f.write(bmp_ecb)
    with open("output/silo_CBC.bmp", "wb") as f:
        f.write(bmp_cbc)

    print("    output/silo_ECB.bmp  -> patrones del original aún visibles")
    print("    output/silo_CBC.bmp  -> aspecto de ruido aleatorio")


def main():
    os.makedirs("output", exist_ok=True)

    print("=" * 60)
    print("FASE 2: Cifrado híbrido y prueba ECB vs CBC")
    print("=" * 60)

    # 1) Cifrado híbrido del plano del silo: A envía a B
    print("\n[1] Cifrado híbrido del plano del silo (A -> B)")
    cifrar_hibrido(
        archivo_in="data/silo_circuito.bmp",
        archivo_out="output/silo_hybrid_for_B.bin",
        destinatario="MiembroB",
    )

    # Para verificar el round-trip regeneramos la password de MiembroB
    salt_b = cargar_salt("MiembroB")
    pass_b = derivar_clave("Francisco Pino", "202373051-3", salt_b)
    descifrar_hibrido(
        archivo_in="output/silo_hybrid_for_B.bin",
        archivo_out="output/silo_recuperado.bmp",
        destinatario="MiembroB",
        password=pass_b,
    )

    # Comprobación: ¿el archivo recuperado es idéntico al original?
    with open("data/silo_circuito.bmp", "rb") as f:
        original = f.read()
    with open("output/silo_recuperado.bmp", "rb") as f:
        recuperado = f.read()
    print(f"  Verificación: original == recuperado -> {original == recuperado}")

    # 2) Prueba ECB vs CBC
    print("\n[2] Prueba visual ECB vs CBC")
    prueba_ecb_vs_cbc("data/silo_circuito.bmp")

    print("\nFase 2 completada. Archivos en ./output/")


if __name__ == "__main__":
    main()
