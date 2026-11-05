# 📦 Entrega Técnica – **[Feature] Implement Basic Anti‑Cheat Protection**  
**Proyecto:** Javelin (Plataforma Algora)  
**Responsable:** @mau16ro – Desarrollador Senior  
**Recompensa:** $10 000 USD  

---  

## 1️⃣ Resumen Ejecutivo  

| **Objetivo** | Añadir una capa de protección anti‑cheat “baseline” que impida la ejecución del cliente cuando se detecte depurador o procesos conocidos de trampa. |
|--------------|------------------------------------------------------------------------------------------------------------------------------------------|
| **Alcance**  | - Detección de depuradores (managed & native). <br> - Detección de procesos sospechosos (lista blanca configurable). <br> - Bloqueo inmediato (terminación segura) y registro de incidentes. |
| **Beneficios** | - Reduce la superficie de ataque para trampas de terceros. <br> - Mejora la confianza de la comunidad y la integridad de los rankings. <br> - Solución modular, extensible y sin impacto perceptible en la jugabilidad. |
| **Entregables** | 1. Arquitectura y diagramas de integración. <br> 2. Código fuente listo para producción (C# .NET 6, tipado estricto, comentarios y buenas prácticas). <br> 3. Suite de pruebas unitarias (xUnit). <br> 4. Guía de instalación y despliegue. |

---

## 2️⃣ Arquitectura de la Solución  

### 2.1 Visión General  

```
+-------------------+       +------------------------+       +-------------------+
|   Javelin Client  |-----> |  AntiCheatEngine (DLL) |-----> |   Log/Telemetry   |
+-------------------+       +------------------------+       +-------------------+
        ^                               |
        |                               v
        |                     +-------------------+
        |                     |  Config Provider  |
        |                     +-------------------+
        |                               |
        |                               v
        |                     +-------------------+
        |                     |  Process Scanner  |
        |                     +-------------------+
        |                               |
        |                               v
        |                     +-------------------+
        |                     |  Debugger Guard   |
        |                     +-------------------+
```

1. **AntiCheatEngine** – Biblioteca estática que se inicializa al arranque del cliente (`Program.cs`).  
2. **Debugger Guard** – Usa `System.Diagnostics.Debugger.IsAttached` y la API nativa `CheckRemoteDebuggerPresent` para detectar depuradores gestionados y no gestionados.  
3. **Process Scanner** – Recorre la tabla de procesos del OS y compara los nombres contra una lista configurable (`antiCheatConfig.json`).  
4. **Config Provider** – Lee la configuración en tiempo de ejecución; permite añadir/quitar procesos sospechosos sin recompilar.  
5. **Log/Telemetry** – Registra eventos críticos en el sistema de logs propio de Javelin (servidor central) mediante `ILogger`.  

### 2.2 Diagrama de Dependencias  

```mermaid
flowchart LR
    A[Program.cs] --> B[AntiCheatEngine.Initialize()]
    B --> C[DebuggerGuard.Check()]
    B --> D[ProcessScanner.Scan()]
    C --> E[TerminateIfDebugger()]
    D --> F[TerminateIfSuspicious()]
    E & F --> G[ILogger (JavelinLogProvider)]
    B --> H[ConfigProvider.Load()]
    H --> D
```

### 2.3 Cambios Necesarios en el Código Base  

| Archivo | Cambio | Comentario |
|--------|--------|------------|
| `Program.cs` | Llamada a `AntiCheatEngine.Initialize();` antes de cargar la UI principal. | Garantiza que la protección se ejecuta lo antes posible. |
| `antiCheatConfig.json` | Nuevo archivo con la lista de procesos sospechosos. | Editable por el equipo de ops. |
| `Javelin.Logging` | Añadir un *category* `AntiCheat`. | Facilita filtrado en producción. |
| `csproj` | Referencia a `System.Management` (solo Windows) y `Microsoft.Win32.SafeHandles`. | Necesario para enumerar procesos. |

---

## 3️⃣ Código Fuente – Implementación Completa  

> **Requisitos**: .NET 6+, C# 10, Windows 10 + (para `System.Management`).  
> **Convenciones**: `PascalCase` para tipos, `camelCase` para variables locales, `I`‑prefijo para interfaces.  

### 3.1 `antiCheatConfig.json` (raíz del proyecto)  

```json
{
  "//": "Lista de procesos que se consideran cheat / hacking tools",
  "SuspiciousProcesses": [
    "cheatengine.exe",
    "processhacker.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "reclass.exe",
    "ida64.exe",
    "dnSpy.exe",
    "wireshark.exe"
  ],
  "TerminateOnDetection": true,
  "LogLevel": "Warning"
}
```

### 3.2 `AntiCheatEngine.cs`  

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Javelin.Security.AntiCheat
{
    /// <summary>
    /// Punto de entrada de la protección anti‑cheat.
    /// </summary>
    public static class AntiCheatEngine
    {
        private static readonly ILogger Logger = Javelin.Logging.JavelinLogProvider.CreateLogger("AntiCheat");
        private static AntiCheatConfig _config = null!;

        /// <summary>
        /// Inicializa el motor de anti‑cheat. Debe llamarse al arranque de la aplicación.
        /// </summary>
        public static void Initialize()
        {
            try
            {
                LoadConfig();
                DebuggerGuard.Check();
                ProcessScanner.Scan(_config.SuspiciousProcesses);
            }
            catch (AntiCheatException ace)
            {
                Logger.LogCritical(ace, "Anti‑cheat triggered: {Reason}", ace.Reason);
                if (_config.TerminateOnDetection)
                {
                    TerminateApplication(ace.Reason);
                }
            }
            catch (Exception ex)
            {
                // No queremos que un error inesperado haga caer el juego; registramos y continuamos.
                Logger.LogError(ex, "Error inesperado en AntiCheatEngine.Initialize()");
            }
        }

        private static void LoadConfig()
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "antiCheatConfig.json");
            if (!File.Exists(configPath))
                throw new FileNotFoundException("Archivo de configuración anti‑cheat no encontrado.", configPath);

            var json = File.ReadAllText(configPath);
            _config = JsonConvert.DeserializeObject<AntiCheatConfig>(json)
                      ?? throw new InvalidDataException("No se pudo deserializar antiCheatConfig.json");
        }

        private static void TerminateApplication(string reason)
        {
            Logger.LogWarning("Terminando aplicación por detección anti‑cheat: {Reason}", reason);
            // Liberamos recursos y cerramos de forma controlada.
            Environment.Exit(0);
        }
    }

    #region Config DTO
    internal sealed class AntiCheatConfig
    {
        public List<string> SuspiciousProcesses { get; set; } = new();
        public bool TerminateOnDetection { get; set; } = true;
        public string LogLevel { get; set; } = "Warning";
    }
    #endregion

    #region Excepciones específicas
    /// <summary>
    /// Representa cualquier condición que haga fallar la protección.
    /// </summary>
    public sealed class AntiCheatException : Exception
    {
        public string Reason { get; }

        public AntiCheatException(string reason) : base($"Anti‑cheat detection: {reason}")
        {
            Reason = reason;
        }
    }
    #endregion
}
```

### 3.3 `DebuggerGuard.cs`  

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Javelin.Security.AntiCheat
{
    internal static class DebuggerGuard
    {
        private static readonly ILogger Logger = Javelin.Logging.JavelinLogProvider.CreateLogger("AntiCheat.Debugger");

        // API nativa de Windows para detección de depuradores externos.
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        public static void Check()
        {
            // 1️⃣ Managed debugger (Visual Studio, Rider, etc.)
            if (Debugger.IsAttached)
            {
                Logger.LogWarning("Debugger gestionado detectado.");
                throw new AntiCheatException("Debugger attached (managed).");
            }

            // 2️⃣ Native debugger (OllyDbg, x64dbg, etc.) usando la API de Windows.
            bool nativeDebugger = false;
            try
            {
                var handle = Process.GetCurrentProcess().Handle;
                if (!CheckRemoteDebuggerPresent(handle, ref nativeDebugger))
                {
                    var err = Marshal.GetLastWin32Error();
                    Logger.LogError("CheckRemoteDebuggerPresent failed, Win32 error {Error}", err);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error al invocar CheckRemoteDebuggerPresent");
            }

            if (nativeDebugger)
            {
                Logger.LogWarning("Debugger nativo detectado.");
                throw new AntiCheatException("Debugger attached (native).");
            }
        }
    }
}
```

### 3.4 `ProcessScanner.cs`  

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace Javelin.Security.AntiCheat
{
    internal static class ProcessScanner
    {
        private static readonly ILogger Logger = Javelin.Logging.JavelinLogProvider.CreateLogger("AntiCheat.Scanner");

        /// <summary>
        /// Busca procesos cuyo nombre coincida con la lista de sospechosos.
        /// </summary>
        /// <param name="suspiciousProcessNames">Nombres en minúscula sin ruta.</param>
        public static void Scan(IEnumerable<string> suspiciousProcessNames)
        {
            var suspectSet = new HashSet<string>(suspiciousProcessNames.Select(p => p.Trim().ToLowerInvariant()));

            foreach (var proc in Process.GetProcesses())
            {
                string procName;
                try { procName = proc.ProcessName.ToLowerInvariant(); }
                catch
                {
                    // Algunas veces el proceso ya no está accesible; lo ignoramos.
                    continue;
                }

                if (suspectSet.Contains($"{procName}.exe"))
                {
                    Logger.LogWarning("Proceso sospechoso detectado: {ProcessId}/{Name}", proc.Id, proc.ProcessName);
                    throw new AntiCheatException($"Suspicious process detected: {proc.ProcessName} (PID {proc.Id})");
                }
            }
        }
    }
}
```

### 3.5 Modificación en `Program.cs`  

```csharp
using Javelin.Security.AntiCheat;

namespace Javelin
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            // 1️⃣ Anti‑cheat se ejecuta antes que cualquier lógica del juego.
            AntiCheatEngine.Initialize();

            // 2️⃣ Arranque normal del cliente.
            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
        }
    }
}
```

### 3.6 Registro Central (`Javelin.Logging`) – (solo referencia)  

```csharp
// Archivo: Javelin.Logging/JavelinLogProvider.cs
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace Javelin.Logging
{
    public static class JavelinLogProvider
    {
        private static readonly ILoggerFactory Factory = LoggerFactory.Create(builder =>
        {
            builder.AddSimpleConsole(options =>
            {
                options.IncludeScopes = true;
                options.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
            });
            // Aquí se pueden agregar sinks (file, telemetry, etc.)
        });

        public static ILogger CreateLogger(string category) => Factory.CreateLogger(category);
    }
}
```

---

## 4️⃣ Pruebas Unitarias  

> **Framework**: xUnit 2.4, **Mocking**: Moq 4.18  

### 4.1 Proyecto de pruebas (`Javelin.Security.AntiCheat.Tests`)  

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Javelin.Security.AntiCheat;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Javelin.Security.AntiCheat.Tests
{
    public class DebuggerGuardTests
    {
        [Fact]
        public void DetectsManagedDebugger()
        {
            // Simulamos un debugger adjunto mediante la API de .NET
            var original = Debugger.IsAttached;
            try
            {
                // No podemos cambiar Debugger.IsAttached, pero verificamos que la excepción se lanza
                // cuando el método está llamado bajo un debugger real.
                if (!original) // si no hay debugger, el test no debería lanzar
                {
                    Assert.Throws<AntiCheatException>(() => DebuggerGuard.Check());
                }
                else
                {
                    var ex = Assert.Throws<AntiCheatException>(() => DebuggerGuard.Check());
                    Assert.Contains("managed", ex.Reason);
                }
            }
            finally { /*