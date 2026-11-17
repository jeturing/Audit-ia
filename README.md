# 🕵️ Audit-ia — Web Audit QA v4

[![Product](https://img.shields.io/badge/product-Herramienta%20interna-blue?style=flat-square)](https://jeturing.com)
[![Stack](https://img.shields.io/badge/stack-Python-336791?style=flat-square)](https://jeturing.com)
[![License](https://img.shields.io/badge/license-Proprietary-orange?style=flat-square)](https://jeturing.com)

**Auditor web de un solo fichero (`web.py`): auditoría funcional y de seguridad completa de un sitio — rastreo automático con pausa y reanudación, captura completa de red y consola, detección de errores JS, enlaces rotos y formularios, comprobaciones OWASP Top 10 y de superficie de exposición, descubrimiento de API y reporte HTML por dominio y fecha.**

> 📍 **Disciplina de estado** — cada capacidad de este README lleva su estado: **Construido** (en `main`, con pruebas o evidencia) · **En desarrollo** (en una rama) · **Diseñado** (especificado, sin construir) · **Concepto** (idea registrada). Los estados nunca se mezclan.

| De un vistazo | |
|---|---|
| **Forma** | Herramienta de consola de un solo fichero (`web.py`, clase `WebAuditor`) |
| **Estado** | Configuración en `.env-web` (se crea sola la primera vez); la sesión SSO se guarda en cookies para continuar la auditoría |
| **Interfaces** | Consola y panel de control flotante en el navegador (modo *headed*) |
| **Despliegue** | Se ejecuta en la máquina del operador; no es un servicio desplegado |

---

## 📋 Tabla de contenido

- [🌐 Posición en el ecosistema](#️-posición-en-el-ecosistema)
- [🧩 Capacidades y estado](#️-capacidades-y-estado)
- [🗂️ Mapa del repositorio](#️-mapa-del-repositorio)
- [🔒 Modelo de seguridad](#-modelo-de-seguridad)
- [🚀 Instalación y despliegue](#-instalación-y-despliegue)
- [⚙️ Configuración](#️-configuración)
- [🩺 Troubleshooting](#-troubleshooting)
- [🗺️ Límites honestos y roadmap](#️-límites-honestos-y-roadmap)
- [📝 Changelog](#-changelog)
- [👥 Créditos](#-créditos)

## 🌐 Posición en el ecosistema

Herramienta interna de auditoría de **Proteger/SEGRD** (Jeturing): produce la primera pasada funcional y de seguridad sobre un sitio — propio o de un cliente bajo encargo — antes de cualquier revisión manual.

Qué **NO** es: no es el SOC ni un escáner continuo; es una corrida bajo demanda cuyo reporte es evidencia de ese momento, y sus modos con escritura (pruebas que crean y borran registros propios marcados) son solo para *staging*, nunca para producción.

## 🧩 Capacidades y estado

- **Rastreo con pausa/reanudación** — Construido. Crawl automático sin límite de páginas por defecto (`--max-pages 0`), con panel flotante persistente para pausar y continuar.
- **Captura completa** — Construido. Peticiones de red y consola por página, con detección de errores JS, enlaces rotos y formularios.
- **Seguridad** — Construido. Comprobaciones OWASP Top 10 y de superficie de exposición, y descubrimiento y validación de API.
- **SSO** — Construido. Login manual que guarda las cookies y continúa la auditoría autenticada.
- **Reporte** — Construido. Informe HTML nombrado `{dominio}_{fecha}.html` por corrida.
- **Arranque sin fricción** — Construido. Auto-activación del entorno virtual y auto-instalación de dependencias al arrancar.

## 🗂️ Mapa del repositorio

```text
Audit-ia/
├── web.py                  # La herramienta completa: auditor, captura, panel y reporte
└── docs/                   # Documentación — índice en docs/README.md
```

La documentación completa vive en [`docs/`](docs/README.md), indexada por tema.

## 🔒 Modelo de seguridad

- La auditoría se ejecuta solo contra sitios que la casa está autorizada a auditar.
- Las cookies de sesión SSO que la herramienta guarda son credenciales de la corrida: no se suben al repositorio.
- El modo de pruebas con escritura real (crear y borrar registros propios marcados como QA) es exclusivo de *staging*; en producción se audita en solo lectura.

## 🚀 Instalación y despliegue

### Requisitos

- Python 3; la propia herramienta crea su entorno e instala sus dependencias la primera vez.

### Correr

```bash
python3 web.py https://ejemplo.com
python3 web.py --headed --max-pages 50 https://ejemplo.com
python3 web.py --headed --sso --login-url /login https://sitio.com
```

Sin argumentos, usa `.env-web` (se crea automáticamente la primera vez).

## ⚙️ Configuración

| Parámetro | Dónde vive | Notas |
|---|---|---|
| Destino y opciones por defecto | `.env-web` | Se genera en la primera corrida; editable por sitio |
| `--headed` | CLI | Muestra el navegador y el panel flotante de pausa/reanudación |
| `--max-pages` | CLI | Tope de páginas del rastreo; `0` = sin límite (defecto) |
| `--sso`, `--login-url` | CLI | Auditoría autenticada con login manual y cookies guardadas |

## 🩺 Troubleshooting

### La auditoría no pasa del login

Causa: el sitio exige SSO interactivo. Corrección: usar `--headed --sso --login-url <ruta>`, completar el login en la ventana y dejar que la herramienta guarde las cookies y continúe.

## 🗺️ Límites honestos y roadmap

- Un solo fichero y una sola versión (v4) publicada en el repo (2026-09-23): no hay suite de pruebas propia ni historial de versiones en el repositorio.
- El reporte es una foto de la corrida: no sustituye la revisión manual de los hallazgos.

## 📝 Changelog

### 2026-09-23 — Publicación de Web Audit QA v4 (`bf428c5`)

- README inicial y la herramienta completa en `web.py`: rastreo, captura, OWASP Top 10, SSO y reporte por dominio y fecha.

## 👥 Créditos

**Jeturing Inc.** — herramienta interna (Proteger/SEGRD).
