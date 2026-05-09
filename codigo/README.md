# Laboratorio 2 - Redes de Computadores 2026-1

Operación "Claves de Guerra" - Implementación en Python.

## Requisitos

- Python 3.10 o superior
- `pip` para instalar dependencias
- Linux / macOS (Windows también funciona ejecutando cada `python3 faseX.py`)

Una sola dependencia externa: `cryptography`.

## Estructura

```
codigo/
├── fase1.py            # KDF (PBKDF2) + RSA-2048
├── fase2.py            # Cifrado híbrido AES + RSA, prueba ECB vs CBC
├── fase3.py            # Firma digital RSA-PSS y Sign-then-Encrypt
├── fase4.py            # Esquema de Shamir (3 de 4)
├── Makefile            # Automatización
├── requirements.txt
├── README.md
├── data/
│   └── silo_circuito.bmp
├── keys/               # SALTs y llaves PEM (generados por fase1)
└── output/             # BMPs ECB/CBC, paquetes cifrados, fragmentos
```

## Cómo correr

```bash
# Instalar dependencias y correr las 4 fases:
make all

# Solo correr (después de instalar):
make run

# Borrar archivos generados:
make clean
```

Cada fase se puede correr por separado:

```bash
make fase1
make fase2
make fase3
make fase4
```

O directamente con Python:

```bash
python3 fase1.py
python3 fase2.py
python3 fase3.py
python3 fase4.py
```

> Las fases 2 y 3 usan las llaves generadas por la fase 1, así que la
> primera vez hay que correr la fase 1 antes.

## Qué genera cada fase

| Fase | Genera |
|------|--------|
| 1 | `keys/MiembroX.salt`, `keys/MiembroX_private.pem`, `keys/MiembroX_public.pem` para X = A, B, C, D |
| 2 | `output/silo_hybrid_for_B.bin`, `output/silo_recuperado.bmp`, `output/silo_ECB.bmp`, `output/silo_CBC.bmp` |
| 3 | `output/msg_A_to_B.bin`, `output/msg_B_to_C.bin`, `output/msg_A_to_B_tampered.bin` |
| 4 | `output/share_1.txt` ... `output/share_4.txt` |

## Algoritmos usados

- **PBKDF2-HMAC-SHA256** con SALT aleatorio para derivar una clave a partir
  de Nombre + Rol.
- **RSA-2048** con OAEP-SHA256 para cifrado y PSS-SHA256 para firma.
- **AES-128-CBC** con padding PKCS7 e IV aleatorio para cifrado simétrico.
- **Cifrado híbrido**: AES cifra el archivo, RSA cifra la clave AES.
- **Sign-then-Encrypt**: primero se firma, luego se cifra (mensaje + firma).
- **Shamir** sobre un primo grande P > 2^256, con aritmética entera modular.
