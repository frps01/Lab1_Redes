# Makefile - Laboratorio 2 Redes de Computadores 2026-1

PYTHON = python3
PIP    = pip3

.PHONY: all install run fase1 fase2 fase3 fase4 clean help

all: install run

install:
	$(PIP) install -r requirements.txt --break-system-packages || \
	$(PIP) install -r requirements.txt

run: fase1 fase2 fase3 fase4
	@echo ""
	@echo "Todas las fases ejecutadas correctamente."

fase1:
	@echo ""
	$(PYTHON) fase1.py

fase2: fase1
	@echo ""
	$(PYTHON) fase2.py

fase3: fase1
	@echo ""
	$(PYTHON) fase3.py

fase4:
	@echo ""
	$(PYTHON) fase4.py

clean:
	rm -f keys/*.pem keys/*.salt
	rm -f output/*.bmp output/*.bin output/*.txt
	@echo "Archivos generados eliminados."

help:
	@echo "Targets disponibles:"
	@echo "  make all      - instala dependencias y ejecuta las 4 fases"
	@echo "  make install  - instala las dependencias"
	@echo "  make run      - ejecuta las 4 fases"
	@echo "  make fase1    - ejecuta solo la fase 1"
	@echo "  make fase2    - ejecuta la fase 2 (depende de fase 1)"
	@echo "  make fase3    - ejecuta la fase 3 (depende de fase 1)"
	@echo "  make fase4    - ejecuta la fase 4"
	@echo "  make clean    - borra los archivos generados"
