/*

 * Script Mejorado v9 para Hooking de StoreKit y Red en iOS con Frida

 * ===================================================================

 *

 * Objetivo: Monitorear compras In-App, simular restauración (simplificada

 * y reforzada), registrar red, y depurar. Estrategia basada en hooks

 * de transacción y bloqueo de fallo de restauración.


 * Mejoras v9.2:

 * - CORREGIDO: Reemplazado el hook problemático restoreCompletedTransactionsWithApplicationUsername:

 * con una implementación vacía para evitar fallos.

 * - SIMPLIFICADO: Eliminada la búsqueda y hook del método delegado de éxito

 * restoreCompletedTransactionsFinished:, ya que no se encontró en logs previos.

 * - REFORZADO: Se basa en forzar SKPaymentTransactionState a Purchased y bloquear

 * la señal de fallo de restauración (- paymentQueue:restoreCompletedTransactionsFailedWithError:).

 * - Mantenidos otros hooks (detección restore simple, detección addPayment,

 * forzar error = nil, hooks de red).

 */



(function() {

    "use strict"; // Habilita el modo estricto de JavaScript



    // --- Constantes y Configuración ---

    const LOG_PREFIX = {

        INFO: "[INFO]",

        STOREKIT: "[STOREKIT]",

        NETWORK: "[NETWORK]",

        ERROR: "[ERROR]",

        WARN: "[WARN]",

        DEBUG: "[DEBUG]"

    };



    const SKPaymentTransactionState = {

        Purchasing: 0,

        Purchased: 1, // Estado que forzamos

        Failed: 2,

        Restored: 3, // Estado original en restauraciones

        Deferred: 4

    };



    // SKNotification ya no es necesario

    // const SKNotification = { ... };



    // Configuración General

    const ENABLE_POLLING = false; // Monitoreo activo (polling) - Deshabilitado

    const POLLING_INTERVAL_MS = 3000; // Intervalo para polling (si está activado)

    const NSUTF8StringEncoding = 4; // Constante ObjC para codificación UTF-8



    // --- Funciones Helper de Hooking ---



    /**

     * Aplica un hook de reemplazo de forma segura a un método Objective-C.

     * Verifica existencia y previene errores si el método no se encuentra.

     * @param {ObjC.Object | null} cls La clase Objective-C. Puede ser null.

     * @param {string} methodSelector El selector del método (ej: '- myMethod:').

     * @param {NativeCallback} replacementCallback El NativeCallback que reemplazará la implementación.

     */

    function safeReplaceHook(cls, methodSelector, replacementCallback) {

        if (!cls || typeof cls !== 'object') { // Verificación más estricta

            console.warn(`${LOG_PREFIX.WARN} Clase inválida (tipo: ${typeof cls}) pasada a safeReplaceHook para ${methodSelector}`);

            return;

        }

        try {

            const method = cls[methodSelector];

            if (method && method.implementation) {

                Interceptor.replace(method.implementation, replacementCallback);

                console.log(`${LOG_PREFIX.INFO} [🛠️] Hook REEMPLAZADO: ${cls.$className}.${methodSelector}`);

            } else {

                console.warn(`${LOG_PREFIX.WARN} [🚫] Método no encontrado o sin impl. para REEMPLAZAR: ${cls.$className}.${methodSelector}`);

            }

        } catch (e) {

            console.error(`${LOG_PREFIX.ERROR} Error en safeReplaceHook (${cls.$className}.${methodSelector}): ${e.message}\nStack: ${e.stack}`);

        }

    }



    /**

     * Aplica un hook de intercepción (attach) de forma segura a un método Objective-C.

     * Verifica existencia y previene errores si el método no se encuentra.

     * @param {ObjC.Object | null} cls La clase Objective-C. Puede ser null.

     * @param {string} methodSelector El selector del método.

     * @param {Object} callbacks Objeto con onEnter y/o onLeave.

     */

    function safeAttachHook(cls, methodSelector, callbacks) {

          if (!cls || typeof cls !== 'object') { // Verificación más estricta

            console.warn(`${LOG_PREFIX.WARN} Clase inválida (tipo: ${typeof cls}) pasada a safeAttachHook para ${methodSelector}`);

            return;

        }

        try {

            const method = cls[methodSelector];

            if (method && method.implementation) {

                Interceptor.attach(method.implementation, callbacks);

                console.log(`${LOG_PREFIX.INFO} [👂] Hook ATTACHED: ${cls.$className}.${methodSelector}`);

            } else {

                console.warn(`${LOG_PREFIX.WARN} [🚫] Método no encontrado o sin impl. para ATTACH: ${cls.$className}.${methodSelector}`);

            }

        } catch (e) {

             console.error(`${LOG_PREFIX.ERROR} Error en safeAttachHook (${cls.$className}.${methodSelector}): ${e.message}\nStack: ${e.stack}`);

        }

    }



    // --- Helper para Decodificar NSData (MEJORADA v3) ---

    /**

     * *** VERSIÓN MEJORADA v3: Intenta decodificar o hexdump. ***

     * @param {ObjC.Object | NativePointer | null} nsData El objeto NSData, puntero o null.

     * @returns {string} String decodificada, hexdump, placeholder o información de error/nulo.

     */

    function decodeNSData(nsData) {

        let dataObj = null;

        let isValidClass = false;

        let bodyLength = BigInt(0); // Usar BigInt para uint64

        let lengthCheckError = null;

        let classCheckError = null;



        try {

            // 1. Obtener Clase NSData (asumimos que ya se cargó globalmente)

            if (!NSData || typeof NSData !== 'object') {

                 return "<Clase NSData no disponible globalmente>";

            }



            // 2. Obtener Objeto ObjC.Object desde Puntero o verificar si ya es Objeto

            if (nsData instanceof NativePointer) {

                if (!nsData.isNull()) {

                    try {

                        dataObj = new ObjC.Object(nsData);

                    } catch (wrapError){

                        return `<Error al envolver puntero NSData: ${wrapError.message}>`;

                    }

                } else {

                    return "<Input nulo o puntero inválido para decodeNSData>"; // Manejar puntero nulo explícitamente aquí

                }

            } else if (nsData instanceof ObjC.Object) {

                 dataObj = nsData;

            } else {

                 return "<Input no es NSData ni puntero para decodeNSData>"; // Manejar otros tipos de input

            }



            // 3. Si tenemos un objeto ObjC pero es nulo (ej: nil), salir

             if (dataObj.isNull()) {

                return "<Objeto NSData nulo/nil para decodeNSData>";

             }



            // 4. Verificar Clase (con try/catch)

            try {

                 isValidClass = dataObj.isKindOfClass_(NSData);

            } catch (e) {

                 classCheckError = e.message;

                 isValidClass = false;

                 console.error(`${LOG_PREFIX.ERROR} decodeNSData: Error en isKindOfClass_(NSData): ${e.message}`);

            }



            if (!isValidClass) {

                 const className = dataObj.$className || typeof dataObj;

                 return `<Input no es NSData (Error Check: ${classCheckError || 'Ninguno'}) Tipo: ${className}>`;

            }



            // 5. Obtener Longitud (con try/catch)

            try {

                // La propiedad length en NSData devuelve uint64, que Frida maneja como BigInt

                bodyLength = dataObj.length();

            } catch (e) {

                lengthCheckError = e.message;

                bodyLength = BigInt(-1); // Indicar error con BigInt negativo

                 console.error(`${LOG_PREFIX.ERROR} decodeNSData: Error en dataObj.length(): ${e.message}`);

            }



            // 6. Procesar cuerpo basado en la longitud

            if (lengthCheckError) {

                return `<Error al obtener longitud: ${lengthCheckError}>`;

            } else if (bodyLength === BigInt(0)) {

                 return "(Cuerpo Vacío)";

            } else if (bodyLength > BigInt(MAX_BODY_LOG_LEN)) {

                 return `(Cuerpo Grande: ${bodyLength.toString()} bytes - Decodificación omitida)`;

            } else {

                // Longitud manejable, intentar decodificar o hexdump

                const dataPtr = dataObj.bytes();

                if (dataPtr.isNull()) {

                    return `(NSData de ${bodyLength.toString()} bytes, pero puntero a datos es nulo)`;

                }

                const byteLength = bodyLength.valueOf(); // Convertir BigInt a number para Memory.read...



                try {

                    // Intentar decodificar como UTF-8

                    const utf8String = Memory.readUtf8String(dataPtr, byteLength);

                    // Verificar si parece texto legible (evitar cadenas binarias largas que se decodifican 'mal')

                    // O simplemente devolver la cadena UTF8 si no lanza un error.

                     return utf8String;



                } catch (utf8Error) {

                    // Falló la decodificación UTF-8, intentar Hexdump si no es muy largo

                    console.warn(`${LOG_PREFIX.WARN} decodeNSData: Falló decodificación UTF8 (${utf8Error.message}). Intentando hexdump...`);

                    if (byteLength <= MAX_HEXDUMP_LEN) {

                         try {

                            const bytes = Memory.readByteArray(dataPtr, byteLength);

                             return bytes.hexDump();

                         } catch(hexError) {

                            console.error(`${LOG_PREFIX.ERROR} decodeNSData: Falló hexdump (${hexError.message})`);

                             return `(Datos de ${bodyLength.toString()} bytes - Falló UTF8 y Hexdump)`;

                         }

                    } else {

                         return `(Datos Binarios de ${bodyLength.toString()} bytes - Falló UTF8)`;

                    }

                }

            }



        } catch (e) {

             // Error general inesperado en la función

             console.error(`${LOG_PREFIX.ERROR} Error GENERAL en decodeNSData: ${e.message}\nStack: ${e.stack}`);

             return `<Error GRAL en decodeNSData: ${e.message}>`;

        }

    }





    // --- Verificación Principal e Inicialización ---

    if (!ObjC.available) {

        console.error("Objective-C Runtime no disponible.");

        return;

    }

    console.log(`${LOG_PREFIX.INFO} Objective-C Runtime detectado.`);



    // --- Definiciones de Clases Objective-C ---

    // Declarar con var para hoisting. Simplificamos a las necesarias para los hooks restantes.

    var SKPaymentQueue, SKPaymentTransaction, NSURLSession, NSURLConnection,

        NSNotificationCenter, NSString, NSURLRequest, NSMutableURLRequest,

        NSData, NSError, NSObject, NSArray, NSNumber; // Eliminamos NSMutableArray, NSMutableDictionary, SKPayment

    try {

          // Carga global de clases

          SKPaymentQueue = ObjC.classes.SKPaymentQueue;

          SKPaymentTransaction = ObjC.classes.SKPaymentTransaction;

          NSURLSession = ObjC.classes.NSURLSession;

          NSURLConnection = ObjC.classes.NSURLConnection;

          NSNotificationCenter = ObjC.classes.NSNotificationCenter;

          NSString = ObjC.classes.NSString;

          NSURLRequest = ObjC.classes.NSURLRequest;

          NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

          NSData = ObjC.classes.NSData;

          NSError = ObjC.classes.NSError;

          NSObject = ObjC.classes.NSObject;

          NSArray = ObjC.classes.NSArray; // Necesario para la verificación de clases

          NSNumber = ObjC.classes.NSNumber; // Necesario para el hook de transactionState

          // Eliminamos: NSMutableArray, NSMutableDictionary, SKPayment

          console.log(`${LOG_PREFIX.DEBUG} Clases Objective-C básicas cargadas.`);

    } catch(e) {

          console.error(`${LOG_PREFIX.ERROR} Error crítico al cargar clases ObjC: ${e.message}. El script no puede continuar.`);

          return;

    }



    // --- Verificación de Clases Críticas ---

     // Simplificamos la verificación a las clases que SÍ usamos en esta versión.

     if (!NSString || !NSArray || !NSNumber || !NSData || !NSError || !NSObject || !SKPaymentQueue || !SKPaymentTransaction || !NSURLSession || !NSURLConnection || !NSURLRequest || !NSMutableURLRequest) {

          // Verificamos las principales usadas

          let missing = [];

          if (!NSString) missing.push("NSString"); if (!NSArray) missing.push("NSArray"); if (!NSNumber) missing.push("NSNumber");

          if (!NSData) missing.push("NSData"); if (!NSError) missing.push("NSError"); if (!NSObject) missing.push("NSObject");

          if (!SKPaymentQueue) missing.push("SKPaymentQueue"); if (!SKPaymentTransaction) missing.push("SKPaymentTransaction");

          if (!NSURLSession) missing.push("NSURLSession"); if (!NSURLConnection) missing.push("NSURLConnection");

          if (!NSURLRequest) missing.push("NSURLRequest"); if (!NSMutableURLRequest) missing.push("NSMutableURLRequest");



          console.error(`${LOG_PREFIX.ERROR} ¡ERROR CRÍTICO! No se pudieron cargar todas las clases Objective-C necesarias. Faltan: ${missing.join(', ')}. El script no puede garantizar su funcionamiento.`);

          // Continuamos, pero con advertencia. Los safeHooks manejarán las que falten individualmente.

     }





    // --- Bloque Principal del Script ---

    try {

        // Solo aplicar hooks de StoreKit si las clases principales están disponibles

        if (SKPaymentQueue && typeof SKPaymentQueue === 'object' && SKPaymentTransaction && typeof SKPaymentTransaction === 'object') {

            console.log(`${LOG_PREFIX.STOREKIT} 🚀 StoreKit Detectado y Clases Principales Cargadas. Iniciando hooks...`);



            // --- 1. Hooks SKPaymentTransaction ---

            console.log(`${LOG_PREFIX.STOREKIT} Aplicando hooks a SKPaymentTransaction...`);

            // Mantenemos este hook para que CUALQUIER transacción (incluso las originales) aparezca como Purchased si la app las consulta.

            safeReplaceHook(SKPaymentTransaction, '- transactionState', new NativeCallback(() => SKPaymentTransactionState.Purchased, 'int', ['pointer']));

            // Hook para eliminar errores asociados a transacciones.

            safeReplaceHook(SKPaymentTransaction, '- error', new NativeCallback(() => NULL, 'pointer', ['pointer']));





            // --- 2. Hook SKPaymentQueue addPayment ---

            console.log(`${LOG_PREFIX.STOREKIT} Aplicando hook a SKPaymentQueue addPayment...`);

            safeAttachHook(SKPaymentQueue, '- addPayment:', {

                 onEnter: function(args) {

                     try {

                          const payment = new ObjC.Object(args[2]);

                          if (!payment || payment.isNull()) {

                              console.warn(`${LOG_PREFIX.STOREKIT} [🛒] addPayment: llamado con payment nulo.`);

                              return;

                          }

                          // Intentar obtener productIdentifier de la payment si el método existe

                          const productIdentifierObj = payment.productIdentifier ? payment.productIdentifier() : null;

                          const productIdentifier = (productIdentifierObj && !productIdentifierObj.isNull()) ? productIdentifierObj.toString() : 'N/A';



                          console.log(`${LOG_PREFIX.STOREKIT} [🛒] Intento de compra detectado. Payment Product ID: ${productIdentifier}`);



                          // Opcional: Loguear otros detalles del payment si son accesibles

                          // const quantity = payment.quantity ? payment.quantity() : 0;

                          // console.log(`${LOG_PREFIX.STOREKIT}    -> Quantity: ${quantity}`);



                     } catch (e) { console.error(`${LOG_PREFIX.ERROR} Error en onEnter de addPayment: ${e.message}\nStack: ${e.stack}`); }

                 }

             });



            // --- 3. Hook SKPaymentQueue restoreCompletedTransactions ---

            console.log(`${LOG_PREFIX.STOREKIT} Aplicando hooks a SKPaymentQueue restoreCompletedTransactions...`);

            safeAttachHook(SKPaymentQueue, '- restoreCompletedTransactions', {

                 onEnter: function(args) {

                     console.log(`${LOG_PREFIX.STOREKIT} [🔄] Llamada a restoreCompletedTransactions detectada.`);

                     // Solo detección del inicio.

                 }

             });

            if (SKPaymentQueue['- restoreCompletedTransactionsWithApplicationUsername:']) {

                 // Reemplazamos el hook problemático con una implementación vacía

                 console.log(`${LOG_PREFIX.STOREKIT} [🔄] REEMPLAZANDO restoreCompletedTransactionsWithApplicationUsername: para evitar fallo.`);

                 safeReplaceHook(SKPaymentQueue, '- restoreCompletedTransactionsWithApplicationUsername:', new NativeCallback(() => {

                     // Implementación vacía: simplemente loguea y retorna

                     console.log(`${LOG_PREFIX.STOREKIT} [🔄] Llamada a restoreCompletedTransactionsWithApplicationUsername: (REEMPLAZADA) detectada. Ignorando argumentos.`);

                 }, 'void', ['pointer', 'pointer', 'pointer'])); // self, _cmd, username

                 console.log(`${LOG_PREFIX.DEBUG} Hook para restore...WithUsername REEMPLAZADO.`);

            } else {

                 console.log(`${LOG_PREFIX.DEBUG} Método restore...WithUsername no encontrado.`);

            }



            // --- 4. Polling (Desactivado) ---

            if (ENABLE_POLLING) { /* ... */ }

            else { console.log(`${LOG_PREFIX.WARN} Monitoreo activo (polling) está DESHABILITADO.`); }





            // --- SECCIÓN: Simulación de Restauración (Forzar Éxito) ---

            console.log(`${LOG_PREFIX.STOREKIT} [✅] Configurando hooks para FORZAR ÉXITO de restauración...`);



            const finishedSelector = '- paymentQueue:restoreCompletedTransactionsFinished:';

            const failedSelector = '- paymentQueue:restoreCompletedTransactionsFailedWithError:';

            let finishHookCount = 0;

            let failHookCount = 0;



            ObjC.enumerateLoadedClasses({

                onMatch: function(className, base) {

                    const cls = ObjC.classes[className];



                    // Hook para la finalización EXITOSA

                    // Basado en tus logs, no parece que la app llame este método o que nuestra heurística lo encuentre

                    // Dejamos la búsqueda por si acaso, pero no nos basamos en ella.

                    if (cls && typeof cls === 'object' && cls[finishedSelector]) {

                         // Omitir clases del sistema o que probablemente no sean el delegado principal de StoreKit

                         // Nombres comunes vistos en logs que pueden no ser relevantes:

                         if (className.startsWith("UIKeyboardCandidate") || className.startsWith("REM") || className.startsWith("APMAnalytics") || className.startsWith("_") || className.startsWith("Satella")) {

                             console.log(`${LOG_PREFIX.DEBUG} [✅] Saltando clase de sistema/analytics/etc no relevante '${className}' para hook de finish.`);

                             return;

                         }

                        console.log(`${LOG_PREFIX.DEBUG} Encontrada clase '${className}' implementando ${finishedSelector}`);

                        finishHookCount++;



                        // Simplemente permitimos que la implementación original se ejecute

                        safeAttachHook(cls, finishedSelector, {

                            onEnter: function(args) {

                                console.log(`${LOG_PREFIX.STOREKIT} [✅] Interceptado ${className}.${finishedSelector} (Señal de Éxito). Permitiendo ejecución original.`);

                            }

                        });

                    }



                    // Hook para la finalización CON FALLO

                    // Este es el hook CRUCIAL para esta estrategia simplificada: BLOQUEAR el fallo.

                    if (cls && typeof cls === 'object' && cls[failedSelector]) {

                          // Omitir clases del sistema o que probablemente no sean el delegado principal de StoreKit

                         if (className.startsWith("UIKeyboardCandidate") || className.startsWith("REM") || className.startsWith("APMAnalytics") || className.startsWith("_") || className.startsWith("Satella")) {

                             console.log(`${LOG_PREFIX.DEBUG} [❌] Saltando clase de sistema/analytics/etc no relevante '${className}' para hook de failed.`);

                             return;

                         }

                        console.log(`${LOG_PREFIX.DEBUG} Encontrada clase '${className}' implementando ${failedSelector}`);

                        failHookCount++;



                        // Interceptamos y BLOQUEAMOS la llamada

                        safeAttachHook(cls, failedSelector, {

                            onEnter: function(args) {

                                try {

                                    console.log(`${LOG_PREFIX.STOREKIT} [❌] Interceptado ${className}.${failedSelector} (Señal de Fallo). BLOQUEANDO ejecución original.`);

                                    let errorDetails = 'N/A';

                                    if (args[2] && !new NativePointer(args[2]).isNull()) {

                                         try {

                                            const error = new ObjC.Object(args[2]);

                                            const errorCode = error.code ? error.code() : 'N/A';

                                            const errorDomain = error.domain ? error.domain().toString() : 'N/A';

                                            errorDetails = `Dominio='${errorDomain}', Código=${errorCode}`;

                                         } catch(e) {

                                             errorDetails = `Error procesando NSError: ${e.message}`;

                                             console.error(`${LOG_PREFIX.ERROR} Error al procesar NSError en failed hook: ${e.message}\nStack: ${e.stack}`);

                                         }

                                    } else {

                                         errorDetails = 'NSError nulo/nil';

                                    }



                                    console.log(`${LOG_PREFIX.STOREKIT}    -> Error detectado: ${errorDetails}`);

                                } catch(e) {

                                    console.error(`${LOG_PREFIX.ERROR} Error general en onEnter de failed hook: ${e.message}\nStack: ${e.stack}`);

                                    console.log(`${LOG_PREFIX.STOREKIT} [❌] Interceptado fallo con error general.`);

                                }

                                // NO LLAMAR this.originalMethod(args);

                                // Simplemente retornamos, impidiendo que la app reciba la señal de fallo.

                                console.log(`${LOG_PREFIX.STOREKIT} [❌] Bloqueo de señal de fallo completado.`);

                            }

                        });

                    }

                },

                onComplete: function() {

                    console.log(`${LOG_PREFIX.INFO} ✅ Hooks de finalización/fallo de restauración configurados. ${finishHookCount} hook(s) de éxito, ${failHookCount} hook(s) de fallo.`);

                    console.warn(`${LOG_PREFIX.WARN} 🚫 La inyección de transacciones falsas en 'updatedTransactions:' ha sido ELIMINADA. La simulación solo se basa en forzar el estado Purchased en transacciones y bloquear la señal de fallo del proceso de restauración.`);

                }

            });





            // --- 5. Observación de Notificaciones (DESHABILITADO) ---

            console.warn(`${LOG_PREFIX.WARN} [🚫] La observación de notificaciones StoreKit está DESHABILITADA permanentemente en este script debido a errores irresolubles con ObjC.registerClass en este entorno.`);



              console.log(`${LOG_PREFIX.INFO} ✅ Hooks de StoreKit (simplificados sin inyección) configurados.`);



        } else {

            console.warn(`${LOG_PREFIX.WARN} ❌ SKPaymentQueue o SKPaymentTransaction no disponibles. Hooks de StoreKit no aplicados.`);

        } // Fin if (SKPaymentQueue && SKPaymentTransaction)





        // === Bloque de Hooks de Red ===

        console.log(`${LOG_PREFIX.NETWORK} Configurando hooks de red...`);



        // Hook genérico para capturar la creación de cualquier NSURLRequest/NSMutableURLRequest

         if (NSURLRequest && typeof NSURLRequest === 'object') {

            safeAttachHook(NSURLRequest, '- initWithURL:', {

                onEnter: function(args) {

                    try {

                        const urlObj = new ObjC.Object(args[2]);

                        const url = (urlObj && !urlObj.isNull() && urlObj.absoluteString) ? urlObj.absoluteString().toString() : 'N/A URL';

                        console.log(`${LOG_PREFIX.NETWORK} [🌐 URLRequest Creada] ${url}`);

                    } catch(e) { console.error(`${LOG_PREFIX.ERROR} [URLRequest init (-initWithURL:)] Error: ${e.message}\nStack: ${e.stack}`); }

                }

            });

             if (NSURLRequest['- initWithURL:cachePolicy:timeoutInterval:']) {

                 safeAttachHook(NSURLRequest, '- initWithURL:cachePolicy:timeoutInterval:', {

                    onEnter: function(args) {

                        try {

                            const urlObj = new ObjC.Object(args[2]);

                            const url = (urlObj && !urlObj.isNull() && urlObj.absoluteString) ? urlObj.absoluteString().toString() : 'N/A URL';

                            console.log(`${LOG_PREFIX.NETWORK} [🌐 URLRequest Creada] ${url}`);

                        } catch(e) { console.error(`${LOG_PREFIX.ERROR} [URLRequest init (-initWithURL:cachePolicy:timeoutInterval:)] Error: ${e.message}\nStack: ${e.stack}`); }

                    }

                });

             }

         } else { console.log(`${LOG_PREFIX.DEBUG} NSURLRequest no encontrado o inválido.`); }





        // a) NSURLSession dataTaskWithRequest

          if (NSURLSession && typeof NSURLSession === 'object' && NSURLSession['- dataTaskWithRequest:completionHandler:']) {

              safeAttachHook(NSURLSession, '- dataTaskWithRequest:completionHandler:', {

                  onEnter: function(args) {

                       try {

                             const request = new ObjC.Object(args[2]);

                             if (!request || request.isNull()) {

                                 console.warn(`${LOG_PREFIX.NETWORK} [🌐 NSURLSession Req] dataTaskWithRequest: llamado con request nulo.`);

                                 return;

                             }

                             const urlObj = request.URL();

                             const url = (urlObj && !urlObj.isNull()) ? urlObj.absoluteString().toString() : 'N/A';

                             const methodObj = request.HTTPMethod();

                             const method = (methodObj && !methodObj.isNull()) ? methodObj.toString() : 'N/A';

                             console.log(`${LOG_PREFIX.NETWORK} [🌐 NSURLSession Req] ${method} ${url}`);

                             // const headers = request.allHTTPHeaderFields();

                             // if (headers && !headers.isNull()) { /* ... log headers ... */ }





                            const httpBody = request.HTTPBody();

                            if (httpBody && !httpBody.isNull()) {

                                 const bodyString = decodeNSData(httpBody);

                                 console.log(`${LOG_PREFIX.NETWORK}   -> Body: ${bodyString}`);

                            } else {

                                console.log(`${LOG_PREFIX.NETWORK}   -> Body: (Nulo/Vacío)`);

                            }



                       } catch (e) { console.error(`${LOG_PREFIX.ERROR} [NSURLSession] Error: ${e.message}\nStack: ${e.stack}`); }

                  }

              });

          } else { console.log(`${LOG_PREFIX.DEBUG} NSURLSession dataTask... no encontrado o inválido.`); }



        // b) NSURLConnection initWithRequest

        if (NSURLConnection && typeof NSURLConnection === 'object' && NSURLConnection['- initWithRequest:delegate:startImmediately:']) {

             safeAttachHook(NSURLConnection, '- initWithRequest:delegate:startImmediately:', {

                 onEnter: function(args) {

                     try {

                         const request = new ObjC.Object(args[2]);

                          if (!request || request.isNull()) {

                             console.warn(`${LOG_PREFIX.NETWORK} [🌐 NSURLConnection Req] initWithRequest: llamado con request nulo.`);

                             return;

                          }

                         const urlObj = request.URL();

                         const url = (urlObj && !urlObj.isNull()) ? urlObj.absoluteString().toString() : 'N/A';

                         const methodObj = request.HTTPMethod();

                         const method = (methodObj && !methodObj.isNull()) ? methodObj.toString() : 'N/A';

                         console.log(`${LOG_PREFIX.NETWORK} [🌐 NSURLConnection Req] ${method} ${url}`);

                         // const headers = request.allHTTPHeaderFields();

                         // if (headers && !headers.isNull()) { /* ... log headers ... */ }





                         const httpBody = request.HTTPBody();

                          if (httpBody && !httpBody.isNull()) {

                              const bodyString = decodeNSData(httpBody);

                              console.log(`${LOG_PREFIX.NETWORK}   -> Body: ${bodyString}`);

                          } else {

                             console.log(`${LOG_PREFIX.NETWORK}   -> Body: (Nulo/Vacío)`);

                          }



                     } catch (e) { console.error(`${LOG_PREFIX.ERROR} [NSURLConnection] Error: ${e.message}\n${e.stack}`); }

                 }

             });

        } else { console.log(`${LOG_PREFIX.DEBUG} NSURLConnection initWithRequest... no encontrado o inválido.`); }





        // c) NSMutableURLRequest setHTTPBody (Usando decodeNSData MEJORADA v3)

        if (NSMutableURLRequest && typeof NSMutableURLRequest === 'object' && NSMutableURLRequest['- setHTTPBody:']) {

            safeAttachHook(NSMutableURLRequest, '- setHTTPBody:', {

                onEnter: function(args) {

                    let bodyString = "<Error procesando cuerpo>";

                    let bodyLengthText = "?"; // Texto para longitud

                    try {

                        const bodyDataPtr = args[2];



                        if (bodyDataPtr.isNull()) {

                             console.log(`${LOG_PREFIX.NETWORK} [📦 setHTTPBody] Estableciendo cuerpo (Nulo/Vacío).`);

                             return;

                        }



                        bodyString = decodeNSData(bodyDataPtr);



                        const match = bodyString.match(/(\d+)\sbytes/);

                        if (match) { bodyLengthText = match[1]; }

                        else if (bodyString === "(Cuerpo Vacío)") { bodyLengthText = "0"; }



                        console.log(`${LOG_PREFIX.NETWORK} [📦 setHTTPBody] Estableciendo cuerpo (${bodyLengthText} bytes): ${bodyString}`);



                    } catch (e) {

                         console.error(`${LOG_PREFIX.ERROR} [NSMutableURLRequest] Error en setHTTPBody hook: ${e.message}\n${e.stack}`);

                         console.log(`${LOG_PREFIX.NETWORK} [📦 setHTTPBody] Falló el procesamiento del cuerpo (error externo).`);

                    }

                    return;

                }

            });

        } else { console.log(`${LOG_PREFIX.DEBUG} NSMutableURLRequest setHTTPBody: no encontrado o inválido.`); }

        // Fin Hooks de Red



        console.log(`${LOG_PREFIX.INFO} ✅ Configuración general de hooks completada.`);



    } catch (globalError) {

        console.error(`${LOG_PREFIX.ERROR} ¡Error global en el script!: ${globalError}\nStack: ${globalError.stack}`);

    }



})(); // Fin del script IIFE
