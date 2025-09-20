# Simulador Benigno de Telemetría tipo “Ransomware” (Defensivo)

> **Propósito**  
> Este proyecto genera **telemetría inocua** en laboratorio para probar detecciones y playbooks de respuesta (SOC/DFIR). Emula fases comunes (descubrimiento, “mutaciones” de memoria simuladas, fingerprint del sistema, actividad de archivos señuelo, nota señuelo y registro detallado), **sin cifrado real, sin evasión y sin daño**.

---

## ⚠️ Ética y alcance

- **Solo laboratorio** (VMs/snapshots; nunca en producción ni sobre datos reales).
- **Uso defensivo/educativo**: validar alertas, medir MTTD/MTTR, ejercitar playbooks.
- **Prohibido** uso malicioso. Este repositorio **no** debe cifrar, exfiltrar, persistir ni evadir EDR/AV.

> **Importante**: si tu copia del código contiene funciones de cifrado (p. ej., `EncryptDirectoryAES(...)`), **elimínalas o coméntalas** antes de compilar/ejecutar. El simulador benigno **no cifra**.

---

## 🧩 Qué simula (sin daño)

- **Mutaciones y polimorfismo “mock”**: eventos de log que emulan variación en memoria.
- **Fingerprint controlado**: nombre de máquina, versión de OS, CPU y memoria (solo lectura).
- **Sondeos de API ficticios**: registro de llamadas “mock” (no requieren privilegios).
- **Descubrimiento y enumeración** de rutas **señuelo**.
- **Actividad de archivos inocua**: enumeración/copia/renombrado de **señuelos** (sin criptografía).
- **Nota señuelo**: archivo de texto benigno para disparar reglas basadas en IOC.
- **Telemetría local**: `simulation_log.txt` con timestamps para reconstruir **línea de tiempo**.

---

## 🗂️ Estructura

- **Código**: clase `RedTeamSimulator` con rutinas de simulación y logging.
- **Carpeta de trabajo (por defecto)**: `C:\TestEncrypt` *(ajústala a una ruta de laboratorio)*.
- **Log**: `C:\TestEncrypt\simulation_log.txt`.

---

## ✅ Requisitos

- Windows de laboratorio (VM recomendada).
- .NET SDK/Runtime compatible con C#.
- Permisos de escritura **solo** en la carpeta de pruebas.

---

## 🔧 Preparación segura

1. Crea una carpeta exclusiva de lab, p. ej.: `C:\Lab\Sim`.
2. (Opcional) Coloca **archivos señuelo** (TXT/PNG falsos) dentro de esa carpeta.
3. **Revisa el código** y **asegúrate** de que **NO** se invoque `EncryptDirectoryAES(...)` en `Main` ni en ninguna otra parte.
4. Compila el proyecto con tu flujo habitual de .NET/C#.

---

## ▶️ Ejecución (laboratorio)

- Con argumento (carpeta de lab):
  ```bash
  RedTeamSimulator.exe C:\Lab\Sim
  ```
- Sin argumento, usará la ruta por defecto indicada en el código (ajústala previamente a una ubicación de **laboratorio**).

**Qué observarás:**
- Entradas en `simulation_log.txt` con **mutaciones/polimorfismo mock**, **fingerprint**, **API probes**, **enumeración de archivos** y creación de una **nota señuelo**.
- Eventos que puedes monitorear en tu SIEM/EDR de pruebas para validar reglas y correlaciones.

---

## 🔍 Detecciones sugeridas (alto nivel)

- **Patrón de enumeración/renombrados** en corto intervalo dentro de la ruta de lab.
- **Presencia de “nota señuelo”** (p. ej., `README_RECOVER_FILES.txt`) en múltiples subcarpetas **del lab**.
- **Secuencia de procesos** predecible (un único binario simulado; sin LOLBins).
- **Correlación temporal** usando `simulation_log.txt` para armar el **timeline**.

> Transforma estas ideas en reglas **Sigma** o consultas en tu SIEM (KQL/ES|QL/SPL) **sin payloads dañinos**.

---

## 📏 Métricas recomendadas

- **MTTD**: tiempo desde el primer evento relevante hasta la primera alerta validada.
- **MTTR (contención/limpieza)**: tiempo hasta aplicar el playbook y estabilizar el host.
- **Calidad de señal**: VP/FP durante la simulación.
- **Eficiencia del playbook**: pasos automáticos vs. manuales, retrabajo y cuellos de botella.

---

## 🧹 Limpieza

- Elimina la carpeta de lab y `simulation_log.txt`, o revierte el **snapshot** de la VM.
- Verifica que **no existan** cambios fuera de la ruta de laboratorio.

---

## 🚫 Deliberadamente excluido

- Cifrado real, manejo de claves o manipulación in-memory.
- Técnicas de bypass de EDR/AV, AMSI, drivers o privilegios.
- Exfiltración o **persistencia real**.

---

## 📝 Licencia y responsabilidad

- Uso **educativo/defensivo**. Cualquier otro uso está prohibido.
- El autor y contribuidores **no se hacen responsables** por usos indebidos.
- Si detectas debilidades en productos de terceros durante tus pruebas, usa **coordinated disclosure** con el proveedor.

---

## 🤝 Contribuciones

Se aceptan mejoras que **mantengan** el enfoque defensivo: mejor logging, generación de artefactos para DFIR, documentación de detecciones y plantillas de reporte. No se aceptarán cambios que introduzcan cifrado real, evasión o técnicas ofensivas.
