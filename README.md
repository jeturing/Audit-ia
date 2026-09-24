Web Audit QA v4
===============
Auditoría funcional + seguridad completa:
  • Auto-activación de venv + auto-instalación de dependencias
  • Crawl automático con pausa/reanudación manual (panel flotante persistente)
  • Captura COMPLETA de network requests y consola
  • Detección de errores JS, links rotos, forms
  • OWASP Top 10 checks + superficie de exposición
  • API discovery y validación
  • Panel de control flotante (headed) con Pausar/Continuar via expose_function
  • SSO: login manual → guarda cookies → continúa audit
  • Sin límite de páginas por defecto (--max-pages 0)
  • Reporte nombrado: {dominio}_{fecha}.html

Uso:
    python3 web.py https://ejemplo.com
    python3 web.py --headed --max-pages 50 https://ejemplo.com
    python3 web.py --headed --login-url /login --email u@x.com --password clave https://sitio.com
    python3 web.py --headed --sso --login-url /login https://sitio.com

Si no pasas argumentos, usa .env-web (se crea automáticamente la primera vez).
