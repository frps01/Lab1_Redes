"""
Fase 3: Firma digital y protocolo Sign-then-Encrypt
---------------------------------------------------
- El emisor firma el mensaje con su llave privada (RSA-PSS).
- Luego cifra "mensaje + firma" con cifrado híbrido AES + RSA.
- El receptor descifra y verifica la firma.
- Si un solo bit fue alterado, la firma no valida y se imprime
  "SABOTAJE DETECTADO".
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.exceptions import InvalidSignature

from fase1 import cargar_llave_publica, cargar_llave_privada, derivar_clave, cargar_salt
from fase2 import (
    aes_cbc_cifrar, aes_cbc_descifrar,
    rsa_cifrar, rsa_descifrar,
    LARGO_AES, LARGO_BLOQUE,
)

LARGO_FIRMA = 256  # firma RSA-2048 = 256 bytes


# Nombre función: firmar
# Parámetros: privada (RSA privada), mensaje (bytes)
# Descripción: firma el mensaje con RSA-PSS y SHA-256.
def firmar(privada, mensaje):
    return privada.sign(
        mensaje,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


# Nombre función: verificar
# Parámetros: publica (RSA pública), mensaje (bytes), firma (bytes)
# Descripción: verifica la firma. Devuelve True si es válida, False si no.
def verificar(publica, mensaje, firma):
    try:
        publica.verify(
            firma,
            mensaje,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# Nombre función: sign_then_encrypt
# Parámetros: emisor (str), receptor (str), mensaje (bytes), pass_emisor (bytes)
# Descripción: Protocolo Sign-then-Encrypt.
#              1) Firma con la privada del emisor.
#              2) Concatena mensaje + firma.
#              3) Cifra todo con AES-128-CBC (clave aleatoria, IV aleatorio).
#              4) Envuelve la clave AES con RSA-OAEP del receptor.
def sign_then_encrypt(emisor, receptor, mensaje, pass_emisor):
    priv_emisor = cargar_llave_privada(emisor, pass_emisor)
    pub_receptor = cargar_llave_publica(receptor)

    # 1 y 2: firmar y concatenar
    firma = firmar(priv_emisor, mensaje)
    paquete = mensaje + firma

    # 3 y 4: cifrado híbrido del paquete
    clave_aes = os.urandom(LARGO_AES)
    iv = os.urandom(LARGO_BLOQUE)
    ciphertext = aes_cbc_cifrar(clave_aes, paquete, iv)
    enc_clave = rsa_cifrar(pub_receptor, clave_aes)

    salida = len(enc_clave).to_bytes(2, "big") + enc_clave + iv + ciphertext

    print(f"  {emisor} -> {receptor}")
    print(f"    mensaje  : {len(mensaje)} bytes")
    print(f"    firma    : {len(firma)} bytes")
    print(f"    paquete  : {len(salida)} bytes (enc_clave + iv + cifrado)")
    return salida


# Nombre función: decrypt_then_verify
# Parámetros: receptor (str), pass_receptor (bytes), emisor_esperado (str), blob (bytes)
# Descripción: Protocolo inverso. Descifra y verifica la firma. Si algo
#              falla, imprime "SABOTAJE DETECTADO" y retorna None.
def decrypt_then_verify(receptor, pass_receptor, emisor_esperado, blob):
    priv_rec = cargar_llave_privada(receptor, pass_receptor)
    pub_emisor = cargar_llave_publica(emisor_esperado)

    # Desempaquetar
    largo = int.from_bytes(blob[:2], "big")
    enc_clave = blob[2:2 + largo]
    iv = blob[2 + largo:2 + largo + 16]
    ciphertext = blob[2 + largo + 16:]

    # Descifrar
    try:
        clave_aes = rsa_descifrar(priv_rec, enc_clave)
        paquete = aes_cbc_descifrar(clave_aes, ciphertext, iv)
    except Exception:
        print(f"  >>> SABOTAJE DETECTADO (descifrado falló)")
        return None

    if len(paquete) < LARGO_FIRMA:
        print("  >>> SABOTAJE DETECTADO (paquete muy corto)")
        return None

    # Separar mensaje y firma
    mensaje = paquete[:-LARGO_FIRMA]
    firma = paquete[-LARGO_FIRMA:]

    # Verificar firma
    if verificar(pub_emisor, mensaje, firma):
        print(f"  {receptor} <- {emisor_esperado}: firma válida ✓")
        return mensaje
    else:
        print(f"  >>> SABOTAJE DETECTADO (firma inválida)")
        return None


# Nombre función: password_de
# Parámetros: miembro (str), nombre (str), rol (str)
# Descripción: helper que regenera la password (material PBKDF2) de un miembro
#              leyendo su SALT desde disco.
def password_de(miembro, nombre, rol):
    salt = cargar_salt(miembro)
    return derivar_clave(nombre, rol, salt)


def main():
    os.makedirs("output", exist_ok=True)

    print("=" * 60)
    print("FASE 3: Firma digital y Sign-then-Encrypt")
    print("=" * 60)

    pass_a = password_de("MiembroA", "Moises Gonzalez", "Comandante")
    pass_b = password_de("MiembroB", "Elena Vargas",    "Estratega")
    pass_c = password_de("MiembroC", "Dimitri Volkov",  "Ingeniero")

    # --- Caso 1: A le envía un mensaje legítimo a B ---
    print("\n[Caso 1] Mensaje legítimo A -> B")
    msg_ab = b"Activar protocolo Golgotha. Coordenadas: 41N 70W. Hora: 03:00 UTC."
    print(f"  Mensaje original: {msg_ab.decode()}")
    blob_ab = sign_then_encrypt("MiembroA", "MiembroB", msg_ab, pass_a)
    with open("output/msg_A_to_B.bin", "wb") as f:
        f.write(blob_ab)
    recibido = decrypt_then_verify("MiembroB", pass_b, "MiembroA", blob_ab)
    print(f"  Mensaje descifrado: {recibido.decode()}")
    assert recibido == msg_ab

    # --- Caso 2: B le responde a C ---
    print("\n[Caso 2] Mensaje legítimo B -> C")
    msg_bc = b"Confirmar recepcion. Resguardar fragmento Shamir."
    blob_bc = sign_then_encrypt("MiembroB", "MiembroC", msg_bc, pass_b)
    with open("output/msg_B_to_C.bin", "wb") as f:
        f.write(blob_bc)
    decrypt_then_verify("MiembroC", pass_c, "MiembroB", blob_bc)

    # --- Caso 3: alguien altera 1 bit del paquete A->B ---
    print("\n[Caso 3] Alguien altera 1 bit del paquete (intento de sabotaje)")
    blob_alterado = bytearray(blob_ab)
    pos = len(blob_alterado) // 2
    blob_alterado[pos] ^= 0x01
    print(f"  Bit alterado en byte {pos} de {len(blob_alterado)}")
    with open("output/msg_A_to_B_tampered.bin", "wb") as f:
        f.write(bytes(blob_alterado))
    res = decrypt_then_verify("MiembroB", pass_b, "MiembroA", bytes(blob_alterado))
    assert res is None

    # --- Caso 4: C intenta hacerse pasar por A ---
    print("\n[Caso 4] C intenta firmar diciendo ser A")
    msg_falso = b"Cancelar la operacion. (mensaje falso)"
    blob_falso = sign_then_encrypt("MiembroC", "MiembroB", msg_falso, pass_c)
    res = decrypt_then_verify("MiembroB", pass_b, "MiembroA", blob_falso)
    assert res is None

    print("\nFase 3 completada.")


if __name__ == "__main__":
    main()
