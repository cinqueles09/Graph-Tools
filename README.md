# 🛠️ Graph-tools: La Navaja Suiza para Microsoft Graph

![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-0078D4?style=for-the-badge&logo=microsoft-sharepoint&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-53C1DE?style=for-the-badge&logo=powershell&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen?style=for-the-badge)

**Graph-tools** es una colección de automatizaciones inteligentes diseñadas para simplificar las tareas de administración del día a día en el entorno de Microsoft 365. Desde la gestión de usuarios hasta la auditoría de seguridad, esta herramienta busca ser el aliado definitivo para administradores de sistemas.

[**📖 Leer la Wiki de documentación**](https://github.com/cinqueles09/Graph-Tools/wiki) | [**🚩 Reportar un error**](https://github.com/cinqueles09/Graph-Tools/issues)

---

## 🚀 ¿Por qué Graph-tools?

Administrar el ecosistema de Microsoft mediante peticiones manuales o scripts dispersos puede ser caótico. **Graph-tools** centraliza esas tareas en scripts robustos y fáciles de usar:

* **Automatización Inteligente:** Menos clics en el portal de Azure/Entra ID, más resultados en la terminal.
* **Simplificación:** Abstrae la complejidad de las llamadas a la API de Microsoft Graph.
* **Seguridad:** Implementación de flujos de autenticación estándar (OAuth 2.0).

## 🛠️ Scripts Disponibles

### 🔄 [Sync-EntraIntuneDevices.ps1](https://github.com/cinqueles09/Graph-Tools/wiki/Sync-EntraIntuneDevices)
**Core de gestión de inventario.**
* **Higiene:** Sincronización inteligente entre Intune y Entra ID.
* **Limpieza:** Borrado automático con confirmación por inactividad y gestión de registros huérfanos.
* **Auditoría:** Generación automática de reportes CSV pre-ejecución.

### 🧹 [Intune_Duplicate_Cleanup.ps1](https://github.com/cinqueles09/Graph-Tools/wiki/Intune-Duplicate-Cleanup)
**Especialista en duplicados.**
* **Precisión:** Identificación por Número de Serie y `lastSyncDateTime`.
* **Seguridad:** Sistema de confirmación manual antes de cada borrado permanente.
* **Escalabilidad:** Optimizado para entornos de gran volumen (+999 dispositivos).

---

## 🔐 Requisitos de API (Application Permissions)

| Script | Scopes Necesarios |
| :--- | :--- |
| **Sync-EntraIntuneDevices** | `DeviceManagementManagedDevices.ReadWrite.All`, `Device.ReadWrite.All` |
| **Intune_Duplicate_Cleanup** | `DeviceManagementManagedDevices.ReadWrite.All` |

---

*(Próximamente se añadirán más utilidades según el Roadmap con su correspondiente apartado en la wiki).*

## 🧭 Roadmap

Actualmente estamos trabajando en las siguientes funcionalidades para ampliar la "navaja suiza":

- [x] **Limpieza de dispositivos duplicados en Intune:** Análisis de dispositivos inscritos en intune para identificar los duplicados y poderlos higienizar.
- [ ] **Sincronización de GAL a Contactos:** Automatización para exportar e hidratar la Global Address List (GAL) directamente en los contactos de Outlook de los usuarios.
- [ ] **Etiquetado Dinámico de Dispositivos:** Asignación automática de etiquetas (tags) en Intune/Entra ID basada en atributos específicos (ExtensionAttributes del usuario propietario, departamento, etc).
- [ ] **Módulo de Auditoría de Licencias:** Reportes detallados de uso y optimización de costes en Office 365.
- [ ] **Automatización de exportación CSV para Assessment de Intune:** Generación de informes detallados y estructurados para realizar auditorías de cumplimiento y estado de la configuración de Intune.
- [ ] **Engine de Reporting HTML**: Motor de generación de informes interactivos (filtros, búsqueda y gráficas) para el análisis de cumplimiento de dispositivos en el ecosistema M365.

---
