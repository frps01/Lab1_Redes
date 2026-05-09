"""
Fase 4: Compartición de secretos (esquema de Shamir, t=3, n=4)
--------------------------------------------------------------
- Se reparte una clave de 256 bits en 4 fragmentos.
- Se necesitan 3 de 4 para reconstruirla.
- Toda la matemática se hace con enteros y aritmética modular en Python
  (NO punto flotante: ver pregunta C del informe).
"""

import os
import secrets

# Primo grande mayor que 2^256, suficiente para nuestro secreto de 256 bits.
# Trabajar módulo P garantiza divisiones exactas (cada elemento no nulo
# tiene inverso modular) y que cualquier cuenta dé enteros.
P = 2**521 - 1

T = 3   # umbral: cuántos miembros se necesitan para reconstruir
N = 4   # cantidad total de fragmentos


# ------------------------------------------------------------------
# Polinomio y aritmética modular
# ------------------------------------------------------------------

# Nombre función: evaluar_poly
# Parámetros: coefs (list[int]), x (int)
# Descripción: evalúa f(x) = c0 + c1*x + c2*x^2 + ... módulo P.
def evaluar_poly(coefs, x):
    resultado = 0
    for c in reversed(coefs):
        resultado = (resultado * x + c) % P
    return resultado


# Nombre función: inverso_mod
# Parámetros: a (int)
# Descripción: devuelve el inverso multiplicativo de `a` módulo P.
#              Python 3.8+ permite calcularlo con pow(a, -1, P).
def inverso_mod(a):
    return pow(a % P, -1, P)


# ------------------------------------------------------------------
# Generación de fragmentos (Shamir)
# ------------------------------------------------------------------

# Nombre función: dividir_secreto
# Parámetros: secreto (int), t (int), n (int)
# Descripción: construye un polinomio aleatorio de grado t-1 cuyo término
#              independiente es `secreto`, y devuelve n puntos (x, f(x))
#              con x = 1..n.
def dividir_secreto(secreto, t=T, n=N):
    # secreto = a0; los demás coeficientes son aleatorios
    coefs = [secreto] + [secrets.randbelow(P - 1) + 1 for _ in range(t - 1)]
    fragmentos = [(x, evaluar_poly(coefs, x)) for x in range(1, n + 1)]
    return fragmentos


# ------------------------------------------------------------------
# Reconstrucción (interpolación de Lagrange en x=0)
# ------------------------------------------------------------------

# Nombre función: lagrange_en_cero
# Parámetros: fragmentos (list[(x, y)])
# Descripción: reconstruye f(0) = secreto a partir de un subconjunto de
#              fragmentos usando Lagrange:
#                  f(0) = Σ y_i * Π_{j≠i} (-x_j)/(x_i - x_j)  mod P
def lagrange_en_cero(fragmentos):
    secreto = 0
    k = len(fragmentos)
    for i in range(k):
        xi, yi = fragmentos[i]
        num = 1
        den = 1
        for j in range(k):
            if i == j:
                continue
            xj, _ = fragmentos[j]
            num = (num * (-xj)) % P
            den = (den * (xi - xj)) % P
        # división modular = multiplicación por el inverso modular
        li_0 = (num * inverso_mod(den)) % P
        secreto = (secreto + yi * li_0) % P
    return secreto


# ------------------------------------------------------------------
# Persistencia y casos de prueba
# ------------------------------------------------------------------

# Nombre función: guardar_fragmentos
# Parámetros: fragmentos (list[(x, y)])
# Descripción: guarda cada fragmento en un archivo "share_<x>.txt" con
#              el formato "x:y" en hexadecimal.
def guardar_fragmentos(fragmentos):
    for x, y in fragmentos:
        with open(f"output/share_{x}.txt", "w") as f:
            f.write(f"{x}:{hex(y)}\n")


# Nombre función: probar_caso
# Parámetros: titulo (str), subset (list), secreto_real (int)
# Descripción: aplica Lagrange sobre `subset` y compara con el secreto real.
def probar_caso(titulo, subset, secreto_real):
    print(f"\n  {titulo} (k={len(subset)})")
    print(f"    Fragmentos usados: {[x for x, _ in subset]}")
    intento = lagrange_en_cero(subset)
    if intento == secreto_real:
        print(f"    Reconstruido: {hex(intento)[:34]}...")
        print(f"    >>> COINCIDE con el secreto: ÉXITO")
    else:
        print(f"    Reconstruido: {hex(intento)[:34]}...")
        print(f"    Secreto real: {hex(secreto_real)[:34]}...")
        print(f"    >>> NO COINCIDE: el resultado parece aleatorio")


def main():
    os.makedirs("output", exist_ok=True)

    print("=" * 60)
    print(f"FASE 4: Esquema de Shamir (t={T}, n={N})")
    print("=" * 60)

    # 1) Crear la "clave maestra" de 256 bits aleatoria
    secreto_bytes = os.urandom(32)
    secreto = int.from_bytes(secreto_bytes, "big")
    print(f"\n  Clave maestra (hex): {secreto_bytes.hex()}")

    # 2) Dividir
    fragmentos = dividir_secreto(secreto)
    print("\n  Fragmentos generados:")
    for x, y in fragmentos:
        print(f"    Miembro {x}: {hex(y)[:38]}...")
    guardar_fragmentos(fragmentos)
    print("  Guardados en output/share_1.txt ... share_4.txt")

    # 3) Probar todos los casos
    print("\n  Casos de reconstrucción:")
    probar_caso("Caso A: 3 fragmentos (A, B, C)", fragmentos[:3], secreto)
    probar_caso("Caso B: 3 fragmentos (B, C, D)", fragmentos[1:], secreto)
    probar_caso("Caso C: 4 fragmentos (todos)",   fragmentos,     secreto)
    probar_caso("Caso D: 2 fragmentos (insuficiente)", fragmentos[:2], secreto)
    probar_caso("Caso E: 1 fragmento (insuficiente)",  fragmentos[:1], secreto)

    print("\nFase 4 completada.")


if __name__ == "__main__":
    main()
