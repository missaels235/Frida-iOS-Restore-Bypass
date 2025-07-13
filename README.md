# Frida iOS Restore Bypass 🛡️

Un script de Frida avanzado y resiliente para iOS, diseñado para el análisis de seguridad de compras In-App (IAP). Su estrategia principal se enfoca en **simular una restauración de compras exitosa mediante el bloqueo selectivo de las notificaciones de fallo**, en lugar de inyectar transacciones falsas, lo que lo hace más estable y compatible con una mayor cantidad de aplicaciones.

---

##  filozofia Central

A diferencia de otros scripts que intentan crear y notificar transacciones falsas (un método que a menudo falla o es detectado), este script adopta un enfoque más sutil y efectivo:

1.  **Fuerza el Estado de Éxito:** Toda transacción consultada por la app se reporta como `Purchased` (Comprada).
2.  **Elimina Errores:** Cualquier error asociado a una transacción es anulado.
3.  **Bloquea la Señal de Fallo:** El hook más importante intercepta y **bloquea** la llamada al delegado `paymentQueue:restoreCompletedTransactionsFailedWithError:`. La aplicación nunca recibe la notificación de que el proceso de restauración ha fallado, llevándola a proceder como si todo hubiera funcionado correctamente.

Este método ha demostrado ser mucho más robusto y menos propenso a causar cierres inesperados.

---

## ✨ Características Principales

* **🛡️ Bypass de Restauración Robusto:** Simula con éxito la restauración de compras bloqueando las devoluciones de llamada (callbacks) de error.
* **🛒 Detección de Compras y Restauraciones:** Registra en consola cada vez que se intenta una nueva compra (`addPayment:`) o una restauración (`restoreCompletedTransactions`).
* **🌐 Inspección de Red Detallada:** Intercepta `NSURLSession` y `NSURLConnection` para registrar las solicitudes de red, incluyendo el método HTTP, la URL y el cuerpo (body) de la petición, decodificándolo de forma segura.
* **🔧 Hooking Seguro y Resiliente:** Utiliza funciones `safeHook` para aplicar hooks solo si los métodos existen, evitando crasheos en la aplicación.
* **📝 Logging Estructurado:** Proporciona una salida de consola limpia y organizada con prefijos (`[STOREKIT]`, `[NETWORK]`, `[ERROR]`) para una fácil depuración.
* **⚙️ Decodificación Avanzada:** Incluye un decodificador de `NSData` mejorado que intenta convertir los datos a UTF-8 y, si falla, muestra un `hexdump`, evitando errores con datos binarios.

⚠️ Descargo de Responsabilidad
Este script ha sido creado con fines educativos y de investigación de seguridad únicamente. Su propósito es ayudar a los desarrolladores y pentesters a entender y probar la seguridad de los flujos de IAP. No debe ser utilizado para la piratería o para obtener acceso no autorizado a contenido de pago. El mal uso de esta herramienta es responsabilidad exclusiva del usuario.

El autor no se hace responsable de ninguna acción ilegal o daño que pueda ser causado por el uso de este software. Úsalo bajo tu propio riesgo.

📄 Licencia MIT
Copyright (c) 2025 [Tu Nombre o Nickname]

Por la presente se concede permiso, libre de cargos, a cualquier persona que obtenga una copia de este software y de los archivos de documentación asociados (el "Software"), para comerciar con el Software sin restricción, incluyendo sin limitación los derechos de usar, copiar, modificar, fusionar, publicar, distribuir, sublicenciar, y/o vender copias del Software, y para permitir a las personas a las que se les proporcione el Software que lo hagan, sujeto a las siguientes condiciones:

El aviso de copyright anterior y este aviso de permiso se incluirán en todas las copias o porciones sustanciales del Software.

EL SOFTWARE SE PROPORCIONA "COMO ESTÁ", SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O IMPLÍCITA, INCLUYENDO PERO NO LIMITADO A GARANTÍAS DE COMERCIABILIDAD, IDONEIDAD PARA UN PROPÓSITO PARTICULAR Y NO INFRACCIÓN. EN NINGÚN CASO LOS AUTORES O TITULARES DEL COPYRIGHT SERÁN RESPONSABLES DE NINGUNA RECLAMACIÓN, DAÑO U OTRA RESPONSABILIDAD, YA SEA EN UNA ACCIÓN DE CONTRATO, AGRAVIO O CUALQUIER OTRO MOTIVO, QUE SURJA DE O EN CONEXIÓN CON EL SOFTWARE O EL USO U OTROS TRATOS EN EL SOFTWARE.
















---

## 🔧 Requisitos

* Un dispositivo iOS con **Jailbreak**.
* **Frida** instalado en tu computadora y el servidor `frida-server` ejecutándose en el dispositivo.
* El **Bundle ID** de la aplicación que deseas analizar.

---

## ▶️ Modo de Uso

1.  **Obtén el Bundle ID** de la aplicación objetivo. Puedes usar `frida-ps -Uai` para listar las aplicaciones instaladas.

2.  **Guarda el script** en un archivo, por ejemplo, `restore_bypass.js`.

3.  **Ejecuta el script** con Frida, adjuntándolo a la aplicación. Se recomienda iniciar la aplicación desde cero para asegurar que todos los hooks se apliquen a tiempo.

    ```bash
    frida -U -f com.ejemplo.bundleid -l restore_bypass.js --no-pause
    ```
    * Reemplaza `com.ejemplo.bundleid` con el Bundle ID de tu app.
    * El flag `--no-pause` es útil para que la app inicie inmediatamente.

4.  Dentro de la aplicación, navega a la sección de compras y **utiliza la opción "Restaurar Compras"**. Observa la consola de Frida.

---

## 📄 Ejemplo de Salida en la Consola

Al presionar "Restaurar Compras", deberías ver algo similar a esto:

```log
[INFO] Objective-C Runtime detectado.
[STOREKIT] 🚀 StoreKit Detectado y Clases Principales Cargadas. Iniciando hooks...
[INFO] [🛠️] Hook REEMPLAZADO: SKPaymentTransaction.- transactionState
[INFO] [🛠️] Hook REEMPLAZADO: SKPaymentTransaction.- error
[INFO] [👂] Hook ATTACHED: SKPaymentQueue.- addPayment:
[INFO] [👂] Hook ATTACHED: SKPaymentQueue.- restoreCompletedTransactions
...
[INFO] ✅ Hooks de finalización/fallo de restauración configurados. 0 hook(s) de éxito, 1 hook(s) de fallo.
...

// El usuario presiona "Restaurar Compras"
[STOREKIT] [🔄] Llamada a restoreCompletedTransactions detectada.

// La app intenta notificar al delegado que la restauración falló, pero el script lo bloquea.
[STOREKIT] [❌] Interceptado AppDelegate.-paymentQueue:restoreCompletedTransactionsFailedWithError: (Señal de Fallo). BLOQUEANDO ejecución original.
[STOREKIT]     -> Error detectado: Dominio='SKErrorDomain', Código=2
[STOREKIT] [❌] Bloqueo de señal de fallo completado.

// La app, al no recibir el fallo, procede a verificar el estado de las transacciones,
// las cuales ahora siempre devuelven "Purchased" gracias al primer hook.
