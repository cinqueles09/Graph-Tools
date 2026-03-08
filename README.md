# 🛠️ Graph-tools: La Navaja Suiza para Microsoft Graph

![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-0078D4?style=for-the-badge&logo=microsoft-sharepoint&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-53C1DE?style=for-the-badge&logo=powershell&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen?style=for-the-badge)

**Graph-tools** es una colección de automatizaciones inteligentes diseñadas para simplificar las tareas de administración del día a día en el entorno de Microsoft 365. Desde la gestión de usuarios hasta la auditoría de seguridad, esta herramienta busca ser el aliado definitivo para administradores de sistemas y DevOps.

[**📖 Leer la Wiki de documentación**](https://github.com/cinqueles09/Graph-Tools/wiki) | [**🚩 Reportar un error**](https://github.com/tu-usuario/Graph-tools/issues)

---

## 🚀 ¿Por qué Graph-tools?

Administrar el ecosistema de Microsoft mediante peticiones manuales o scripts dispersos puede ser caótico. **Graph-tools** centraliza esas tareas en scripts robustos y fáciles de usar:

* **Automatización Inteligente:** Menos clics en el portal de Azure/Entra ID, más resultados en la terminal.
* **Simplificación:** Abstrae la complejidad de las llamadas a la API de Microsoft Graph.
* **Seguridad:** Implementación de flujos de autenticación estándar (OAuth 2.0).

## 🛠️ Herramientas Incluidas

### 1. 📂 **Sync-EntraIntuneDevices.ps1**
Este script es el núcleo actual de la herramienta. Conecta con la **Microsoft Graph API** para automatizar la higiene y el mantenimiento del inventario de dispositivos, realizando las siguientes tareas:

* **🔍 Cruce de Inventarios:** Sincronización inteligente de activos entre **Microsoft Intune** y **Microsoft Entra ID**.
* **🧹 Limpieza por Inactividad:** Identificación y borrado automático de dispositivos basados en su última fecha de inicio de sesión o contacto.
* **👻 Gestión de "Huérfanos":** Detección de dispositivos sin propietario y limpieza de registros de tipo *Workplace Join* obsoletos.
* **👯 Control de Duplicados:** Eliminación de registros redundantes en Intune mediante la validación única del **Número de Serie**.
* **📊 Reporting Automático:** Generación de reportes detallados en formato **CSV** antes de cada ejecución para garantizar la trazabilidad de los cambios.

---

*(Próximamente se añadirán más utilidades según el Roadmap con su correspondiente apartado en la wiki).*

## 🧭 Roadmap

Actualmente estamos trabajando en las siguientes funcionalidades para ampliar la "navaja suiza":

- [ ] **Sincronización de GAL a Contactos:** Automatización para exportar e hidratar la Global Address List (GAL) directamente en los contactos de Outlook de los usuarios.
- [ ] **Etiquetado Dinámico de Dispositivos:** Asignación automática de etiquetas (tags) en Intune/Entra ID basada en atributos específicos (SO, Departamento, Ubicación).
- [ ] **Módulo de Auditoría de Licencias:** Reportes detallados de uso y optimización de costes en Office 365.
- [ ] **Automatización de exportación CSV para Assessment de Intune:** Generación de informes detallados y estructurados para realizar auditorías de cumplimiento y estado de la configuración de Intune.

---
