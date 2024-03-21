using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Zlib;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace NetCorePGP
{
    /// <summary>
    /// ////////////////////////////////////////////////////////// DEBUG
    /// </summary>

    public class PgpContext
    {
        // Excepciniones del objeto
        public class KeyNotFoundException : Exception
        {
            public KeyNotFoundException(string message) : base(message) { }
        }
        public class IlegalKeyDeleteException : Exception
        {
            public IlegalKeyDeleteException(string message) : base(message) { }
        }
        public class NoneImportKeyException : Exception
        {
            public NoneImportKeyException(string message) : base(message) { }
        }


        /// <summary>
        /// Enumerado que define la frecuencia con la que el sistema debe volcar a disco los datos de los keyrings
        /// </summary>
        public enum PgpKeyRingDumpFrequency
        {
            Hourly
            , Daily
            , Weekely
            , Inmediately
        }

        /// <summary>
        /// Enumerado que los algoritmos de Hash disponibles
        /// </summary>
        public enum HashAlgorithms
        {
            MD5
            , SHA1
            , SHA256
            , SHA384
            , SHA512
        }

        /// <summary>
        /// Enumerado que define los modos de trabajo disponibles para el objeto
        /// </summary>
        public enum PgpContextMode
        {
            Volatile
            , Persistent
        }

        /// <summary>
        /// Enumerado de políticas de severidad en relación a algoritmos de encriptación simetricos. Las opciones son: 
        /// <list type="bullet">
        /// <item><strong>Compatibilty</strong>: Acepta AES-128, AES-192 y AES-256</item>
        /// <item><strong>Medium</strong>: Acepta AES-192 y AES-256</item>
        /// <item><strong>Secure</strong>: Solo acepta AES-256</item>
        /// </list>
        /// </summary>
        public enum SymmetricalAlgorithmSeverityDirectives
        {
            Compatibility
            , Medium
            , Secure
        }

        /// <summary>
        /// Enumerado de políticas de severidad en relación a algoritmos de hashing. Las opciones son: 
        /// <list type="bullet">
        /// <item><strong>Compatibilty</strong>: Todos</item>
        /// <item><strong>Minimal</strong>: Solo acepta SHA-1</item>
        /// <item><strong>Medium</strong>: Acepta SHA-224 y SHA-256</item>
        /// <item><strong>Secure</strong>: Acepta SHA-256, SHA-384 y SHA-512</item>
        /// <item><strong>Maximum</strong>: Solo acepta SHA-512</item>
        /// </list>
        /// </summary>
        public enum HashAlgorithmSeverityDirectives
        {
            Compatibility
            , Minimal
            , Medium
            , Secure
            , Maximum
        }

        /// <summary>
        /// Enumerado de algoritmos de encriptación asimétrica disponibles
        /// </summary>
        public enum AsymmetricalEncryptionAlgorithms
        {
            DH
            , DSA
            , EC
            , ECDH
            , ECDHC
            , ECDSA
            , ECGOST3410
            , ECMQV
            , Ed25519
            , Ed448
            , ELGAMAL
            , GOST3410
            , RSA
            , RSASSA_PSS
            , X25519
            , X448
        }

        /// <summary>
        /// Enumerado de fortaleza de criptografica desde Bajo a
        /// </summary>
        public enum RsaStrengthPriority
        {
            Speed = 1024
            , Balanced = 2048
            , Security = 4096
        }

        /// <summary>
        /// Constantes del objeto
        /// </summary>
        private const string PUBLIC_KEYRING_EXTENSION = "pkrb";
        private const string SECRET_KEYRING_EXTENSION = "skrb";

        /// <summary>
        /// Atributos de acceso privado del objeto
        /// </summary>
        private string publicKeyRingPath;
        private string secretKeyRingPath;
        private string publicKeyRingName;
        private string secretKeyRingName;
        private BackgroundWorker asyncLoop;

        /// <summary>
        /// Atributos de acceso público del objeto
        /// </summary>
        protected PgpContextMode WorkMode;

        /// <summary>
        /// Atributos heredables del objecto
        /// </summary>
        protected PgpPublicKeyRingBundle PublicKeyRingBundle;
        protected PgpSecretKeyRingBundle SecretKeyRingBundle;

        /// <summary>
        /// Propiedades de acceso público del objeto
        /// </summary>
        public string PublicKeyRingPath { get { return publicKeyRingPath; } set { publicKeyRingPath = value.Replace(string.Concat(".", PUBLIC_KEYRING_EXTENSION), "") ?? throw new ArgumentNullException(nameof(value)); } }
        public string SecretKeyRingPath { get { return secretKeyRingPath; } set { secretKeyRingPath = value.Replace(string.Concat(".", PUBLIC_KEYRING_EXTENSION), "") ?? throw new ArgumentNullException(nameof(value)); } }
        public string PublicKeyRingName { get { return publicKeyRingName; } set { publicKeyRingName = value ?? throw new ArgumentNullException(nameof(value)); } }
        public string SecretKeyRingName { get { return secretKeyRingName; } set { secretKeyRingName = value ?? throw new ArgumentNullException(nameof(value)); } }
        public string PublicKeyRingFQDN => Path.Combine(PublicKeyRingPath, string.Concat(PublicKeyRingName, ".", PUBLIC_KEYRING_EXTENSION));
        public string SecretKeyRingFQDN => Path.Combine(SecretKeyRingPath, string.Concat(SecretKeyRingName, ".", SECRET_KEYRING_EXTENSION));
        public PgpKeyRingDumpFrequency SecretKeyRingDumpFrequency { get; private set; }
        public PgpKeyRingDumpFrequency PublicKeyRingDumpFrequency { get; private set; }


        /// <summary>
        /// Inicializa una nueva instancia de la clase de <see cref="Leviathan.Lib.PgpContext"/>.
        /// </summary>
        /// <param name="pubRingName">Nombre del keyring público.</param>
        /// <param name="secRingName">Nombre del keyring secreto.</param>
        /// <param name="pubringPath">Ruta hacia el fichero del keyring público.</param>
        /// <param name="secRingPath">Ruta hacia el fichero del keyring secreto.</param>
        /// <param name="mode">Volatile: Los keyrings solo se almacenarán en RAM. Persistent: Los keyrings se volcarán a disco.</param>
        /// <param name="secretDumpFrequency">Si el modo persistente está activado, determinará la frecuencia con la quedebe volcar datos del keyring secreto a disco.</param>
        /// <param name="publicDumpFrequency">Si el modo persistente está activado, determinará la frecuencia con la quedebe volcar datos del keyring público a disco.</param>
        /// 
        protected PgpContext(string pubRingName, string secRingName, string pubringPath, string secRingPath, PgpContextMode mode, PgpKeyRingDumpFrequency secretDumpFrequency, PgpKeyRingDumpFrequency publicDumpFrequency)
        {
            // Memoriza los path
            PublicKeyRingPath = pubringPath;
            SecretKeyRingPath = secRingPath;

            // Memoriza los nombres de los keyrings
            PublicKeyRingName = pubRingName;
            SecretKeyRingName = secRingName;

            // Fija el modo de trabajo del objeto
            WorkMode = mode;

            // Fija la frecuencia con la que se debe hacer el dump de datos
            SecretKeyRingDumpFrequency = secretDumpFrequency;
            PublicKeyRingDumpFrequency = publicDumpFrequency;

            // Inicializa los KeyRings
            KeyRingsInit();
        }

        /// <summary>
        /// Método que cambia el modo de trabajo del PgpContext, creará los ficheros si no existen y si los ficheros existen los cargará en memoria sobreescribiendo los existentes
        /// </summary>
        /// <param name="newWorkMode">Nuevo modo de trabajo <see cref="PgpContextMode"/></param>
        public void SwapWorkMode(PgpContextMode newWorkMode)
        {
            // Si el modo de trabajo actual es el que se intenta fijar, no se hace nada
            if (newWorkMode == WorkMode) { Debug.WriteLine("Nothing to do", "Information"); return; }

            // Cambia el modo de trabajo
            WorkMode = newWorkMode;

            // Si el nuevo modo de trabajo es Persistent, vuelca la información a disco
            if (WorkMode == PgpContextMode.Persistent) 
            {
                // Carga o crea los keyring en función de si existen o no
                LoadKeyRingFromFile(out PublicKeyRingBundle);
                LoadKeyRingFromFile(out SecretKeyRingBundle);
            }

            // Escribe en el log
            Debug.WriteLine($"Workmode of the PGP Engine swapped to {WorkMode}", "Information");
        }

        /// <summary>
        /// Método estático que inicializa una nueva instancia de la clase <see cref="Leviathan.Lib.NetCorePGP"/>
        /// </summary>
        /// <param name="mode">Modo de trabajo en el que se ejecutará el objeto</param>
        /// <param name="path">Ubicación de los keyrings en el sistema</param>
        /// <returns>Una nueva instancia de la clase de <see cref="Leviathan.Lib.PgpContext"/>.</returns>
        public static PgpContext Make(PgpContextMode mode, string path)
        {
            // Retorna una instanc ia de NetCorePGP
            return new("public", "secret", path, path, mode, PgpKeyRingDumpFrequency.Hourly, PgpKeyRingDumpFrequency.Daily);
        }

        /// <summary>
        /// Método estático que inicializa una nueva instancia de la clase <see cref="Leviathan.Lib.NetCorePGP"/>
        /// </summary>
        /// <param name="mode">Modo de trabajo en el que se ejecutará el objeto</param>
        /// <param name="dumpFrequency">Frecuencia con la que se debe volcar datos de los keyring a disco</param>
        /// <param name="path">Ubicación de los keyrings en el sistema</param>
        /// <param name="name">Nombre de los keyrings</param>
        /// <returns>Una nueva instancia de la clase de <see cref="Leviathan.Lib.PgpContext"/>.</returns>
        public static PgpContext Make(PgpContextMode mode = PgpContextMode.Volatile, PgpKeyRingDumpFrequency dumpFrequency = PgpKeyRingDumpFrequency.Hourly, string? path = null, string? name = null)
        {
            // Retorna una instanc ia de NetCorePGP
            return new(
                name ?? "public"
                , name ?? "secret"
                , path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetCorePGP\\")
                , path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetCorePGP\\")
                , mode
                , dumpFrequency
                , dumpFrequency);
        }

        /// <summary>
        /// Método estático que inicializa una nueva instancia de la clase <see cref="Leviathan.Lib.NetCorePGP"/>
        /// </summary>
        /// <param name="mode">Modo de trabajo en el que se ejecutará el objeto</param>
        /// <param name="secretDumpFrequency">Frecuencia con la que se debe volcar datos del SecretKeyRing a disco</param>
        /// <param name="publicDumpFrequency">Frecuencia con la que se debe volcar datos del PublicKeyRing a disco</param>
        /// <param name="path">Ubicación de los keyrings en el sistema</param>
        /// <param name="name">Nombre de los keyrings</param>
        /// <returns>Una nueva instancia de la clase de <see cref="Leviathan.Lib.PgpContext"/>.</returns>
        public static PgpContext Make(PgpContextMode mode = PgpContextMode.Volatile, PgpKeyRingDumpFrequency secretDumpFrequency = PgpKeyRingDumpFrequency.Hourly, PgpKeyRingDumpFrequency publicDumpFrequency = PgpKeyRingDumpFrequency.Daily, string? path = null, string? name = null)
        {
            // Retorna una instanc ia de NetCorePGP
            return new(
                name ?? "public"
                , name ?? "secret"
                , path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetCorePGP\\")
                , path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetCorePGP\\")
                , mode
                , secretDumpFrequency
                , publicDumpFrequency);
        }

        /// <summary>
        /// Método que fija el nivel máximo o mínimo de solidez que debe tener una contraseña
        /// </summary>
        /// <param name="characterSolidyLevel">Nivel de solidez a asignar</param>
        /// <param name="isMaximumAllowed"><b>False</b> Fijará el nivel mínimo de solidez requerido. <b>True</b> Fijará el nivel máximo de solidez permitido.</param>
        public static void SetPassprhaseCharacterSolidity(Passphrase.CharSolidity characterSolidyLevel, bool isMaximumAllowed = false)
        {
            // Si la baliza de 'isMaximumAllowed' esta marcada como 'True', fija el nivel maximo de solidez permitido
            if (isMaximumAllowed) { Passphrase.MaximumCharacterSolidityAllowed = characterSolidyLevel; }
            // Si la baliza 'isMaximumAllowed' esta marcada como 'False', fija entonces el nivel mínimo de solidez requerido
            else { Passphrase.MinimumCharacterSolidityRequired = characterSolidyLevel; }
        }

        /// <summary>
        /// Méto que fija el nivel de solidez en relación longitud de contraseñas
        /// </summary>
        /// <param name="lengthSolidityLevel">Longitud de contraseña que se desea asignar. Use <see cref="Passphrase.LengthSolidity"/> options if you want.</param>
        /// <param name="isMaximumAllowed"><b>False</b>: Fijará el nivel mínimo de solidez requerido. <b>True</b>: Fijará el nivel máximo de solidez permitido.</param>
        public static void SetPassphraseLengthSolidity(int lengthSolidityLevel, bool isMaximumAllowed = false)
        {
            // Si la baliza de 'isMaximumAllowed' esta marcada como 'True', fija el nivel maximo de solidez permitido
            if (isMaximumAllowed) { Passphrase.MaximumLengthSolidityAllowed = lengthSolidityLevel; }
            // Si la baliza 'isMaximumAllowed' esta marcada como 'False', fija entonces el nivel mínimo de solidez requerido
            else { Passphrase.MinimumLengthSolidityRequired = lengthSolidityLevel; }
        }

        /// <summary>
        /// Método que fija el nivel de robustez que debe tener una contraseña frente a patrones
        /// </summary>
        /// <param name="patternSolidityLevel">Combinación de excepciones que una contraseña puede tolerar. Use <see cref="Passphrase.PatternSolidity"/> values concatenated with '|' as you want.</param>
        public static void SetPassphrasePatternSolidity(int patternSolidityLevel)
        {
            // Fija el nivel de solidez en relación longitud de contraseñas
            Passphrase.PatternSolidityLevel = patternSolidityLevel;
        }

        /// <summary>
        /// Método que crea instancias de los para PublicKeyRingBundle y SecredKeyRingBundle basandose en los path
        /// </summary>
        private void KeyRingsInit()
        {
            // Si ya se han inicializado los keyring
            if (PublicKeyRingBundle != null && SecretKeyRingBundle != null) { throw new InvalidOperationException("Keyrings is already initialized!"); }

            // Carga el Public KeyRing 
            LoadKeyRingFromFile(out PublicKeyRingBundle, true);

            // Carga el Secret KeyRing
            LoadKeyRingFromFile(out SecretKeyRingBundle, true);
        }

        /// <summary>
        /// Método deja vacío un Secret Keyring Bundle
        /// </summary>
        /// <param name="pskrb">El PgpSecretKeyRingBundle a vaciar</param>
        public static void Clear(out PgpSecretKeyRingBundle pskrb)
        {
            // Vacía el keyring bundle
            pskrb = new PgpSecretKeyRingBundle(Array.Empty<byte>());
        }

        /// <summary>
        /// Método deja vacío un Public Keyring Bundle
        /// </summary>
        /// <param name="ppkrb">El PgpPublicKeyRingBundle a vaciar</param>
        public static void Clear(out PgpPublicKeyRingBundle ppkrb)
        {
            // Vacía el keyring bundle
            ppkrb = new PgpPublicKeyRingBundle(Array.Empty<byte>());
        }

        /// <summary>
        /// Método deja vacío el Secret Keyring Bundle
        /// </summary>
        public void ClearSecrets()
        {
            // Vacía el keyring bundle
            Clear(out SecretKeyRingBundle);

            // SI el volcado de dtaos inmediato está configurado
            if (SecretKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
            {
                // Vuelca los datos en local
                DumpKeyRingBundle(SecretKeyRingBundle);
            }
        }
        
        /// <summary>
        /// Método deja vacío el Public Keyring Bundle
        /// </summary>
        public void ClearPublics()
        {
            // Vacía el keyring bundle
            Clear(out PublicKeyRingBundle);

            // SI el volcado de dtaos inmediato está configurado
            if (PublicKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
            {
                // Vuelca los datos en local
                DumpKeyRingBundle(PublicKeyRingBundle);
            }
        }

        /// <summary>
        /// Método vacía los keyrings
        /// </summary>
        public void ClearKeyrings()
        {
            // Elimina los secret keyrings
            ClearSecrets();

            // Elimina los public keyrings
            ClearPublics();
        }


        /// <summary>
        /// Método de acceso público que elimina los ficheros de datos de los keyring pùblico o secreto
        /// </summary>
        /// <param name="purgePublic">True: Si se desea purgar el fichero de datos del keyring público</param>
        /// <param name="purgeSecret">True: Si se desea purgar el fichero de datos del keyring secreto</param>
        public void PurgeKeyRings(bool purgePublic = false, bool purgeSecret = false)
        {
            // Purga el keyring público si así lo mandan los argumentos
            if (purgePublic) { PurgePublicKeyRing(); }

            // Purga el keyring secreto si así lo mandan los argumentos
            if (purgeSecret) { PurgeSecretKeyRing(); }
        }

        /// <summary>
        /// Método privado que elimina el fichero de datos del keyring secreto
        /// </summary>
        private void PurgeSecretKeyRing()
        {
            // Si existe el fichero del keyring secreto
            if (SecretKeyRingFileExists())
            {
                // Elimina el fichero del keyring secreto
                File.Delete(SecretKeyRingFQDN);
            }
        }

        /// <summary>
        /// Método privado que elimina el fichero de datos del keyring público
        /// </summary>
        private void PurgePublicKeyRing()
        {
            // Si existe el fichero del keyring secreto
            if (PublicKeyRingFileExists())
            {
                // Elimina el fichero del keyring secreto
                File.Delete(PublicKeyRingFQDN);
            }
        }

        /// <summary>
        /// Método que comprueba si el fichero del keyring secreto existe
        /// </summary>
        /// <returns>True: si el fichero existe</returns>
        public bool SecretKeyRingFileExists()
        {
            return File.Exists(SecretKeyRingFQDN);
        }

        /// <summary>
        /// Método que comprueba si el fichero del keyring público existe
        /// </summary>
        /// <returns>True: si el fichero existe</returns>
        public bool PublicKeyRingFileExists()
        {
            return File.Exists(PublicKeyRingFQDN);
        }

        /// <summary>
        /// Método que carga un PgpSecretKeyRingBundle desde fichero
        /// </summary>
        /// <param name="output">Referencia donde se desea depositar la instancia del PgpSecretKeyRingBundle</param>
        private void LoadKeyRingFromFile(out PgpSecretKeyRingBundle output, bool rewriteExistent = false)
        {
            // Si el fichero no existe, procede a crear uno nuevo y sale del método
            if (!SecretKeyRingFileExists() || WorkMode == PgpContextMode.Volatile) { MakeKeyRing(out output, rewriteExistent); return; }

            // Declaramos un tamaño de archivo
            long filesize;

            // Preparamos un filestream
            FileStream fs = new(SecretKeyRingFQDN, FileMode.Open);

            // Fija el tamaño del archivo
            filesize = fs.Length;

            // Instancia el KeyRing
            PgpSecretKeyRingBundle pskrbFromFile = new(PgpUtilities.GetDecoderStream(fs));

            // Cierra el stream de datos
            fs.Close();

            // Si el rewrite está activo
            if (rewriteExistent) { output = pskrbFromFile; }
            // Si el rewrite no está activo
            else
            {
                // Fusiona el keyring recuperado desde disco con el que está en memoria
                output = MergeKeyringBundle(pskrbFromFile, SecretKeyRingBundle);
            }

            // Escribe en el log de Debug la acción realizada
            Debug.WriteLine(string.Format("Secret Key Ring loaded from file '{0}'. {1} has been loaded.", PublicKeyRingFQDN, Utilities.File.GetSizeFormatted(filesize)), "Information");
        }

        /// <summary>
        /// Método que carga un PgpPublicKeyRingBundle desde fichero
        /// </summary>
        /// <param name="output">Referencia donde se desea depositar la instancia del PgpPublicKeyRingBundle</param>
        private void LoadKeyRingFromFile(out PgpPublicKeyRingBundle output, bool rewriteExistent = false)
        {
            // Si el fichero no existe o se está trabajando en modo Volatile, procede a crear uno nuevo y sale del método
            if (!PublicKeyRingFileExists() || WorkMode == PgpContextMode.Volatile) { MakeKeyRing(out output, rewriteExistent); return; }

            // Declaramos un tamaño de archivo
            long filesize;

            // Preparamos un filestream
            FileStream fs = new(PublicKeyRingFQDN, FileMode.Open);

            // Fija el tamaño del archivo
            filesize = fs.Length;

            // Instancia el KeyRing
            PgpPublicKeyRingBundle ppkrbFromFile = new(PgpUtilities.GetDecoderStream(fs));

            // Cierra el stream de datos
            fs.Close();

            // Si el rewrite está activo
            if (rewriteExistent) { output = ppkrbFromFile; }
            // Si el rewrite no está activo
            else
            {
                // Fusiona el keyring recuperado desde disco con el que está en memoria
                output = MergeKeyringBundle(ppkrbFromFile, PublicKeyRingBundle);
            }

            // Escribe en el log de Debug la acción realizada
            Debug.WriteLine(string.Format("Public Key Ring loaded from file '{0}'. {1} has been loaded.", PublicKeyRingFQDN, Utilities.File.GetSizeFormatted(filesize)), "Information");
        }

        /// <summary>
        /// Método que fusiona dos PgpSecretKeyRingBundle en uno
        /// </summary>
        /// <param name="input">PgpSecretKeyRingBundle de origen</param>
        /// <param name="output">PgpSecretKeyRingBundle de destino</param>
        /// <returns>PgpSecretKeyRingBundle de output con los datos del input fusionados</returns>
        /// <exception cref="InvalidOperationException">Cuando alguno de los PgpSecretKeyRingBundle input o output vienen como nulo</exception>
        public static PgpSecretKeyRingBundle MergeKeyringBundle(PgpSecretKeyRingBundle input, PgpSecretKeyRingBundle output)
        {
            // Comprueba que el keyring de origen no sea nulo
            if (input == null) { throw new InvalidOperationException("Input keyring cannot be null"); }

            // Comprueba que el keyring de destino no sea nulo
            if (output == null) { throw new InvalidOperationException("Output keyring cannot be null"); }

            // Recorre los keyring del input
            foreach (PgpSecretKeyRing pskr in input.GetKeyRings())
            {
                // Si el output no contiene, el keyring recorrido
                if (output.GetSecretKeyRing(pskr.GetPublicKey().KeyId) == null)
                {
                    // Añade el keyring recorrido al output
                    output = PgpSecretKeyRingBundle.AddSecretKeyRing(output, pskr);
                }
            }

            // Retorna el output
            return output;
        }

        /// <summary>
        /// Método que fusiona dos PgpPublicKeyRingBundle en uno
        /// </summary>
        /// <param name="input">PgpPublicKeyRingBundle de origen</param>
        /// <param name="output">PgpPublicKeyRingBundle de destino</param>
        /// <returns>PgpPublicKeyRingBundle de output con los datos del input fusionados</returns>
        /// <exception cref="InvalidOperationException">Cuando alguno de los PgpPublicKeyRingBundle input o output vienen como nulo</exception>
        public static PgpPublicKeyRingBundle MergeKeyringBundle(PgpPublicKeyRingBundle input, PgpPublicKeyRingBundle output)
        {
            // Comprueba que el keyring de origen no sea nulo
            if (input == null) { throw new InvalidOperationException("Input keyring cannot be null"); }

            // Comprueba que el keyring de destino no sea nulo
            if (output == null) { throw new InvalidOperationException("Output keyring cannot be null"); }

            // Recorre los keyring del input
            foreach (PgpPublicKeyRing ppkr in input.GetKeyRings())
            {
                // Si el output no contiene, el keyring recorrido
                if (output.GetPublicKeyRing(ppkr.GetPublicKey().KeyId) == null)
                {
                    // Añade el keyring recorrido al output
                    output = PgpPublicKeyRingBundle.AddPublicKeyRing(output, ppkr);
                }
            }

            // Retorna el output
            return output;
        }

        /// <summary>
        /// Método que crea una instancia de PgpSecretKeyRingBundle en una referencia
        /// </summary>
        /// <param name="output">Referencia donde se desea depositar la instancia del PgpSecretKeyRingBundle</param>
        private void MakeKeyRing(out PgpSecretKeyRingBundle output, bool rewriteExistent = false)
        {
            // Instancia un KeyRingBundleVacío
            output = rewriteExistent || SecretKeyRingBundle == null ? new(Array.Empty<byte>()) : SecretKeyRingBundle;

            // Si el modo de trabajo es persistente realiza un dump del KeyRing
            if (WorkMode == PgpContextMode.Persistent)
            {
                // Escribe en el log de Debug la acción realizada
                Debug.WriteLine(string.Format("{1}Secret Key Ring created. Secret Key Ring file saved on '{0}'.", SecretKeyRingPath, output.Count == 0 ? "Empty " : ""), "Information");

                // Vuelca los datos en disco
                DumpKeyRingBundle(in output);

                // Sale del método
                return;
            }

            // Añade salto de línea
            Debug.WriteLine("Empty Secret Key Ring created.", "Information");
        }

        /// <summary>
        /// Método que crea una instancia de PgpPublicKeyRingBundle en una referencia
        /// </summary>
        /// <param name="output">Referencia donde se desea depositar la instancia del PgpPublicKeyRingBundle</param>
        private void MakeKeyRing(out PgpPublicKeyRingBundle output, bool rewriteExistent = false)
        {
            // Instancia un KeyRingBundleVacío
            output = rewriteExistent || PublicKeyRingBundle == null ? new(Array.Empty<byte>()) : PublicKeyRingBundle;

            // Si el modo de trabajo es persistente realiza un dump del KeyRing
            if (WorkMode == PgpContextMode.Persistent)
            {
                // Escribe en el log de Debug la acción realizada
                Debug.WriteLine(string.Format("{1}Public Key Ring created. Public Key Ring file saved on '{0}'.", PublicKeyRingPath, output.Count == 0 ?"Empty " : ""), "Information");

                // Vuelca los datos en disco
                DumpKeyRingBundle(in output);

                // Sale del método
                return;
            }

            // Añade salto de línea
            Debug.WriteLine("Empty Public Key Ring created.", "Information");
        }

        /// <summary>
        /// Método que vuelca en disco los datos de una instancia de PgpPublicKeyRingBundle desde su referencia
        /// </summary>
        /// <param name="output">Referencia donde se desea depositar la instancia del PgpPublicKeyRingBundle</param>
        protected void DumpKeyRingBundle(in PgpPublicKeyRingBundle input)
        {
            // Si el modo de trabajo no es Persistent, sale del método
            if (WorkMode != PgpContextMode.Persistent) { return; }

            // Si el directorio no existe, lo crea
            if (!Directory.Exists(PublicKeyRingPath)) { Directory.CreateDirectory(PublicKeyRingPath); }
            // Si el directorio ya existe
            else
            {
                // Si el fichero ya existe
                if (File.Exists(PublicKeyRingFQDN))
                {
                    // Si el archivo .old ya existe, lo elimina
                    if (File.Exists(string.Concat(PublicKeyRingFQDN, ".old"))) { File.Delete(string.Concat(PublicKeyRingFQDN, ".old")); }

                    // Renombra el fichero existente
                    File.Move(PublicKeyRingFQDN, string.Concat(PublicKeyRingFQDN, ".old"));
                }
            }

            // Instanciamos un BufferedStream para escribir los datos en disco a mayor velocidad
            BufferedStream secout = new(new FileStream(PublicKeyRingFQDN, FileMode.CreateNew));

            // Vuelca el PublicKeyRingBundle en el BufferedStream
            input.Encode(secout);

            // Hace un flush de datos
            secout.Flush();

            // Cierra el BufferedStream y con ello crea el fichero
            secout.Close();
        }

        /// <summary>
        /// Método que vuelca en disco los datos de una instancia de PgpSecretKeyRingBundle desde su referencia
        /// </summary>
        /// <param name="output">Referencia donde se desea depositar la instancia del PgpSecretKeyRingBundle</param>
        protected void DumpKeyRingBundle(in PgpSecretKeyRingBundle input)
        {
            // Si el modo de trabajo no es Persistent, sale del método
            if (WorkMode != PgpContextMode.Persistent) { return; }

            // Si el directorio no existe, lo crea
            if (!Directory.Exists(SecretKeyRingPath)) { Directory.CreateDirectory(SecretKeyRingPath); }
            // Si el directorio ya existe
            else
            {
                // Si el fichero ya existe
                if (File.Exists(SecretKeyRingFQDN))
                {
                    // Si el archivo .old ya existe, lo elimina
                    if (File.Exists(string.Concat(SecretKeyRingFQDN, ".old"))) { File.Delete(string.Concat(SecretKeyRingFQDN, ".old")); }

                    // Renombra el fichero existente
                    File.Move(SecretKeyRingFQDN, string.Concat(SecretKeyRingFQDN, ".old"));
                }
            }

            // Instanciamos un BufferedStream para escribir los datos en disco a mayor velocidad
            BufferedStream secout = new(new FileStream(SecretKeyRingFQDN, FileMode.CreateNew));

            // Vuelca el PublicKeyRingBundle en el BufferedStream
            input.Encode(secout);

            // Hace un flush de datos
            secout.Flush();

            // Cierra el BufferedStream y con ello crea el fichero
            secout.Close();
        }

        /// <summary>
        /// Método maestro que inserta un PgpPublicKeyRing al PgpPublicKeyRingBundle del objeto
        /// </summary>
        /// <param name="publicKeyring">PgpPublicKeyRing a insertar</param>
        public void InsertPublicKeyRing(PgpPublicKeyRing publicKeyring)
        {
            // Añade el keyring publico a la colección de keyrings publicos del objeto
            PublicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(PublicKeyRingBundle, publicKeyring);

            // Si el modo de volcado de datos es Inmediately
            if (PublicKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
            {
                // Vuelca los datos del KeyRing público
                DumpKeyRingBundle(in PublicKeyRingBundle);
            }
        }

        /// <summary>
        /// Método que inserta un PgpPublicKeyRing al PgpPublicKeyRingBundle del objeto
        /// </summary>
        /// <param name="publicKeyringStream">Stream que contine los datos del PgpPublicKeyRing a insertar</param>
        public void InsertPublicKeyRing(Stream publicKeyringStream)
        {
            // Decodifica el stream
            publicKeyringStream = PgpUtilities.GetDecoderStream(publicKeyringStream);
            
            // Invoca al método mestro
            InsertPublicKeyRing(new PgpPublicKeyRing(publicKeyringStream));
        }

        /// <summary>
        /// Método que inserta un PgpPublicKeyRing al PgpPublicKeyRingBundle del objeto
        /// </summary>
        /// <param name="encodedPublicKeyring">Matríz de bytes que contine los datos codificados del PgpPublicKeyRing a insertar</param>
        public void InsertPublicKeyRing(byte[] encodedPublicKeyring)
        {
            // Inicializamos un memory stream desde array
            MemoryStream ms = new(encodedPublicKeyring);

            // Invoca al método mestro
            InsertPublicKeyRing(ms);
        }

        /// <summary>
        /// Método estático que conviernte un array de bytes en una instancia de PgpPublicKeyRing
        /// </summary>
        /// <param name="expectedKeyRing">Array de bytes que contienen los datos codificados del PgpPublicKeyRing</param>
        /// <returns>NULL si no es posible instanciar un PgpPublicKeyRing con los datos facilitados</returns>
        public static PgpPublicKeyRing? ParsePublicKeyRing(byte[] expectedKeyRing)
        {
            // Instanciamos un nuevo MemoryStream
            MemoryStream ms = new(expectedKeyRing);

            // Decodifica los bytes y los almacena en la referencia decodedBytes
            Stream decodedBytes = PgpUtilities.GetDecoderStream(ms);

            try
            {
                // Retorna la nueva instancia del keyring creado desde el stream de datos
                return new PgpPublicKeyRing(decodedBytes);
            }
            catch (Exception e)
            {
                // Escribe en log el error
                Debug.WriteLine(e.Message, "Public Keyring Parse Exception");

                // Retorna nulo
                return null;
            }
        }

        /// <summary>
        /// Método estático que conviernte un array de bytes en una instancia de PgpSecretKeyRing
        /// </summary>
        /// <param name="expectedKeyRing">Array de bytes que contienen los datos codificados del PgpSecretKeyRing</param>
        /// <returns>NULL si no es posible instanciar un PgpSecretKeyRing con los datos facilitados</returns>
        public static PgpSecretKeyRing? ParseSecretKeyRing(byte[] expectedKeyRing)
        {
            // Instanciamos un nuevo MemoryStream
            MemoryStream ms = new(expectedKeyRing);

            // Decodifica los bytes y los almacena en la referencia decodedBytes
            Stream decodedBytes = PgpUtilities.GetDecoderStream(ms);

            try
            {
                // Retorna la nueva instancia del keyring creado desde el stream de datos
                return new PgpSecretKeyRing(decodedBytes);
            }
            catch (Exception e)
            {
                // Escribe en log el error
                Debug.WriteLine(e.Message, "Secret Keyring Parse Exception");

                // Retorna nulo
                return null;
            }
        }

        /// <summary>
        /// Método que inserta un PgpSecretKeyRing al PgpSecretKeyRingBundle del objeto
        /// </summary>
        /// <param name="secretKeyring">PgpSecretKeyRing a insertar</param>
        public void InsertSecretKeyRing(PgpSecretKeyRing secretKeyring)
        {
            // Añade el keyring privado a la colección de keyrings privados del objeto
            SecretKeyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(SecretKeyRingBundle, secretKeyring);

            // Si el modo de volcado de datos es Inmediately
            if (SecretKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
            {
                // Vuelca los datos del KeyRing público
                DumpKeyRingBundle(in SecretKeyRingBundle);
            }
        }
        
        /// <summary>
        /// Método que inserta un PgpSecretKeyRing al PgpSecretKeyRingBundle del objeto
        /// </summary>
        /// <param name="secretKeyring">Stream que contine los datos del PgpSecretKeyRing a insertar</param>
        public void InsertSecretKeyRing(Stream secretKeyringStream)
        {
            // Instancia un nuevo PgpSecretKeyRing desde Stream y lo inserta al keyRing
            InsertSecretKeyRing(new PgpSecretKeyRing(secretKeyringStream));
        }
        
        /// <summary>
        /// Método que inserta un PgpSecretKeyRing al PgpSecretKeyRingBundle del objeto
        /// </summary>
        /// <param name="secretKeyring">Matríz de bytes que contine los datos codificados del PgpSecretKeyRing a insertar</param>
        public void InsertSecretKeyRing(byte[] encodedSecretKeyring)
        {
            // Instancia un nuevo PgpSecretKeyRing desde Array de Bytes y lo inserta al keyRing
            InsertSecretKeyRing(new PgpSecretKeyRing(encodedSecretKeyring));
        }

        /// <summary>
        /// Método estático que cambia el passphrase de un PgpSecretKeyRing
        /// </summary>
        /// <param name="oldKeyRing">PgpSecretKeyRing al que cambiar la contraseña</param>
        /// <param name="oldPassphrase">Passphrasae antiguo del PgpSecretKeyRing</param>
        /// <param name="newPassphrase">Nuevo passphrase a aplicar</param>
        /// <exception cref="ArgumentException">Cuando no se ecuentra una PgpSecretKey con capacidad para firmar en el PgpSecretKeyRing</exception>
        /// <returns>PgpSecretKeyRing con el passphrase actualizado</returns>
        public static PgpSecretKeyRing ChangeSecretKeyPassphrase(PgpSecretKeyRing oldKeyRing, char[] oldPassphrase, char[] newPassphrase)
        {
            // Preparamos una instancia de PgpSecretKey almacenada en la referencia oldKey
            PgpSecretKey oldKey = null;

            // Encontrar la clave privada dentro del anillo con la contraseña antigua
            foreach (PgpSecretKey key in oldKeyRing.GetSecretKeys())
            {
                // Si la clave iterada tiene capacidad para realizar firmas
                if (key.IsSigningKey)
                {
                    // Fija el oldKey como la clave iterada
                    oldKey = key;

                    // Sale del bucle
                    break;
                }
            }

            // Si no se recupera una key validad
            if (oldKey == null)
            {
                // Retorna excepción
                throw new ArgumentException("No se encontró una clave privada válida en el anillo.");
            }

            // Comprueba que el oldPassphrase sea correcto
            oldKey.ExtractPrivateKey(oldPassphrase); // Retornará excepción si el passphrase no es correcto

            // Crear una nueva clave privada con la nueva contraseña
            PgpSecretKey newKey = PgpSecretKey.CopyWithNewPassword(oldKey, oldPassphrase, newPassphrase, oldKey.KeyEncryptionAlgorithm, new SecureRandom());

            // Crear un nuevo anillo con la nueva clave privada
            PgpSecretKeyRing newKeyRing = new(Array.Empty<byte>());
            
            // Recorre todos los SecretKey del KeyRing original
            foreach (PgpSecretKey key in oldKeyRing.GetSecretKeys())
            {
                // Si la SecretKey iterada es la marcada como oldKey
                if (key == oldKey)
                {
                    // Inserta la SecretKey con la nueva contraseña
                    newKeyRing = PgpSecretKeyRing.InsertSecretKey(newKeyRing, newKey);

                    // Pasa de ciclo
                    continue;
                }

                // Inserta la SecretKey con la nueva contraseña
                newKeyRing = PgpSecretKeyRing.InsertSecretKey(newKeyRing, key);
            }

            // Retorna el SecretKeyRing
            return newKeyRing;
        }

        /// <summary>
        /// Método que cambia el passphrase de un PgpSecretKeyRing y lo actualiza en el PgpSecretKeyRingBundle
        /// </summary>
        /// <param name="oldKeyRing">PgpSecretKeyRing al que cambiar la contraseña</param>
        /// <param name="oldPassphrase">Passphrasae antiguo del PgpSecretKeyRing</param>
        /// <param name="newPassphrase">Nuevo passphrase a aplicar</param>
        /// <exception cref="ArgumentException">Cuando no se ecuentra una PgpSecretKey con capacidad para firmar en el PgpSecretKeyRing</exception>
        /// <returns>PgpSecretKeyRing con el passphrase actualizado</returns>
        public PgpSecretKeyRing ChangePassphrase(PgpSecretKeyRing oldKeyRing, char[] oldPassphrase, char[] newPassphrase)
        {
            // Preparamos una instancia de PgpSecretKey almacenada en la referencia oldKey
            PgpSecretKey oldKey = null;

            // Encontrar la clave privada dentro del anillo con la contraseña antigua
            foreach (PgpSecretKey key in oldKeyRing.GetSecretKeys())
            {
                // Si la clave iterada tiene capacidad para realizar firmas
                if (key.IsSigningKey)
                {
                    // Fija el oldKey como la clave iterada
                    oldKey = key;

                    // Sale del bucle
                    break;
                }
            }

            // Si no se recupera una key validad
            if (oldKey == null)
            {
                // Retorna excepción
                throw new ArgumentException("No se encontró una clave privada válida en el anillo.");
            }

            // Comprueba que el oldPassphrase sea correcto
            oldKey.ExtractPrivateKey(oldPassphrase); // Retornará excepción si el passphrase no es correcto

            // Crear una nueva clave privada con la nueva contraseña
            PgpSecretKey newKey = PgpSecretKey.CopyWithNewPassword(oldKey, oldPassphrase, newPassphrase, oldKey.KeyEncryptionAlgorithm, new SecureRandom());

            // Crear un nuevo anillo con la nueva clave privada
            PgpSecretKeyRing newKeyRing = new(Array.Empty<byte>());

            // Recorre todos los SecretKey del KeyRing original
            foreach (PgpSecretKey key in oldKeyRing.GetSecretKeys())
            {
                // Si la SecretKey iterada es la marcada como oldKey
                if (key == oldKey)
                {
                    // Inserta la SecretKey con la nueva contraseña
                    newKeyRing = PgpSecretKeyRing.InsertSecretKey(newKeyRing, newKey);

                    // Pasa de ciclo
                    continue;
                }

                // Inserta la SecretKey con la nueva contraseña
                newKeyRing = PgpSecretKeyRing.InsertSecretKey(newKeyRing, key);
            }

            // Actualiza el keyringBundle
            UpdateKeyRing(newKeyRing);

            // Retorna el SecretKeyRing
            return newKeyRing;
        }

        /// <summary>
        /// Método que actualiza un PgpSecretKeyRing en el bundle del objeto
        /// </summary>
        /// <param name="pskr">PgpSecretKeyRing a actualizar</param>
        private void UpdateKeyRing(PgpSecretKeyRing pskr)
        {
            // Valida el PgpSecretKeyRing
            ValidateKeyRing(pskr);

            // Elimina el PgpSecretKeyRing del bundle
            SecretKeyRingBundle = PgpSecretKeyRingBundle.RemoveSecretKeyRing(SecretKeyRingBundle, SecretKeyRingBundle.GetSecretKeyRing(pskr.GetPublicKey().KeyId));

            // Añade el PgpSecretKeyRing actualizado al bundle
            SecretKeyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(SecretKeyRingBundle, pskr);

            // Si el volcado de datos inmediato está activado
            if (SecretKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
            {
                // Realiza el volcado de datos a disco
                DumpKeyRingBundle(in SecretKeyRingBundle);
            }
        }

        /// <summary>
        /// Método que actualiza un PgpPublicKeyRing en el bundle del objeto
        /// </summary>
        /// <param name="ppkr">PgpPublicKeyRing a actualizar</param>
        private void UpdateKeyRing(PgpPublicKeyRing ppkr)
        {
            // Valida el PgpSecretKeyRing
            ValidateKeyRing(ppkr);

            // Elimina el PgpSecretKeyRing del bundle
            PublicKeyRingBundle = PgpPublicKeyRingBundle.RemovePublicKeyRing(PublicKeyRingBundle, PublicKeyRingBundle.GetPublicKeyRing(ppkr.GetPublicKey().KeyId));

            // Añade el PgpSecretKeyRing actualizado al bundle
            PublicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(PublicKeyRingBundle, ppkr);

            // Si el volcado de datos inmediato está activado
            if (PublicKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
            {
                // Realiza el volcado de datos a disco
                DumpKeyRingBundle(in PublicKeyRingBundle);
            }
        }

        /// <summary>
        /// Método que actualiza un PgpSecretKeyRing y su respectivo PgpPublicKeyRing en el bundle del objeto
        /// </summary>
        /// <param name="pskr">PgpSecretKeyRing a actualizar en el bundle</param>
        /// <param name="ppkr">PgpPublicKeyRing a actualizar en el bundle</param>
        private void UpdateKeyRing(PgpSecretKeyRing pskr, PgpPublicKeyRing ppkr)
        {
            // Si el ID de las claves maestras no coincide retornará error
            if (pskr.GetPublicKey().KeyId != ppkr.GetPublicKey().KeyId) { throw new InvalidKeyException("Las claves maestras no coinciden"); }

            // Actualiza el SecretKeyRing
            UpdateKeyRing(pskr);

            // Actualiza el PublicKeyRing
            UpdateKeyRing(ppkr);
        }

        /// <summary>
        /// Método que valida la composición de un PgpSecretKeyRing
        /// </summary>
        /// <param name="pskr">PgpSecretKeyRing que se desea validar</param>
        /// <exception cref="InvalidKeyException">Excepción producida cuando el PgpSecretKeyRing no cumple los requisitos de composición</exception>
        private static void ValidateKeyRing(PgpSecretKeyRing pskr)
        {
            // Contadore de iteraciones
            int iterations = 0;

            // Recorre los PgpSecretKey del key ring
            foreach(PgpSecretKey psk in pskr.GetSecretKeys())
            {
                // Si es la primera PgpSecretKey, debe ser una clave maestra
                if (!psk.IsMasterKey && iterations == 0) { throw new InvalidKeyException("La primera clave de un keyring siempre de ser clave maestra.");  }
                else if (psk.IsMasterKey && iterations > 0) { throw new InvalidKeyException("Solo puede existir una sola clave maestra por cada keyring."); }

                // Incrementa el contador
                iterations++;
            }
        }

        /// <summary>
        /// Método que valida la composición de un PgpPublicKeyRing
        /// </summary>
        /// <param name="ppkr">PgpPublicKeyRing que se desea validar</param>
        /// <exception cref="InvalidKeyException">Excepción producida cuando el PgpPublicKeyRing no cumple los requisitos de composición</exception>
        private static void ValidateKeyRing(PgpPublicKeyRing ppkr)
        {
            // Contadore de iteraciones
            int iterations = 0;

            // Recorre los PgpSecretKey del key ring
            foreach (PgpPublicKey ppk in ppkr.GetPublicKeys())
            {
                // Si es la primera PgpSecretKey, debe ser una clave maestra
                if (!ppk.IsMasterKey && iterations == 0) { throw new InvalidKeyException("La primera clave de un keyring siempre de ser clave maestra."); }
                else if (ppk.IsMasterKey && iterations > 0) { throw new InvalidKeyException("Solo puede existir una sola clave maestra por cada keyring."); }

                // Incrementa el contador
                iterations++;
            }
        }

        /// <summary>
        /// Método maestro que añade una pareja de claves como subclave a un keyring pgp
        /// </summary>
        /// <param name="pskr">PgpSecretKeyRing al que añadir una subclave</param>
        /// <param name="subkeyAlgorithmTag">Algoritmo general de la subclave</param>
        /// <param name="subKeyFlags">Propiedades de la subclave</param>
        /// <param name="identity">Indentificador asociado a la subclave</param>
        /// <param name="subkeyPassphrase">Contraseña de la subclave</param>
        /// <param name="passphrases">Diccionario de contraseñas continente de la clave maestra y el resto de subclaves</param>
        /// <param name="expiry">Fecha de caducidez de la clave</param>
        /// <param name="secretKeyEncryptionAlgorithm">Algoritmo de encriptación siméticra de la clave secreta. Usa las opciones de <see cref="SymmetricKeyAlgorithmTag"/> a tu elección.</param>
        /// <param name="symmetricalAlgorithmDirective">Directiva que la sublcave debe seguir en relación a algoritmos de clave simétrica. Usa las opciones de <see cref="SymmetricalAlgorithmSeverityDirectives"/> a tu elección.</param>
        /// <param name="hashAlgorithmDirective">Directiva que la subclave debe seguir en relacion a algoritmos de hash. Usa las opciones de <see cref="HashAlgorithmSeverityDirectives"/> a tu elección.</param>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de clave asimétrica. Usa las opciones de <see cref="AsymmetricalEncryptionAlgorithms"/> a tu elección.</param>
        /// <param name="rsaStrengthPriority">Robustez de la encriptación RSA. Usa las opciones de <see cref="RsaStrengthPriority"/> a tu elección.</param>
        /// <returns>Los keyrings actualzados, la pareja de claves de la subclave y el id de la subclave</returns>
        private (PgpSecretKeyRing pskr, PgpPublicKeyRing ppkr, AsymmetricCipherKeyPair ackp, long ki) DoAddSubKey(PgpSecretKeyRing pskr
            , PublicKeyAlgorithmTag subkeyAlgorithmTag
            , int subKeyFlags
            , string identity
            , string passphrase
            , DateTime expiry
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {

            // Declaramos una lista de pareja de claves
            List<PgpKeyPair> pgpKeyPairs = new();

            // Valida el SecretKeyRing
            ValidateKeyRing(pskr);

            // Recorre las claves secretas del SecretKeyRing
            foreach (PgpSecretKey skey in pskr.GetSecretKeys())
            {
                // Genera una pareja de claves con la clave públicay  privada
                pgpKeyPairs.Add(new PgpKeyPair(skey.PublicKey, skey.ExtractPrivateKey(passphrase.ToArray())));
            }

            // Instanciamos un KeyRingParams para configurar datos de cifrado y establecemos una referencia a la instancia en keyRingParams
            KeyRingParams keyRingParams = new(rsaStrengthPriority)
            {
                Password = passphrase,
                Identity = identity,
                PrivateKeyEncryptionAlgorithm = pskr.GetSecretKey().KeyEncryptionAlgorithm,
                SymmetricAlgorithms = ParseSeverityDirectiveInSymetricalAlgorithmTagArray(symmetricalAlgorithmDirective),
                HashAlgorithms = ParseSeverityDirectiveInHashAlgorithmTagArray(hashAlgorithmDirective)
            };

            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Genera una nueva pareja de claves
            AsymmetricCipherKeyPair ackp = GenerateAsymmetricalKeyPair(asymmetricalEncryptionAlgorithm, rsaStrengthPriority);

            // Instanciamos un PgpKeyPair
            PgpKeyPair subKeyPair = new(
                subkeyAlgorithmTag,
                ackp, 
                DateTime.UtcNow);

            // Mensaje de debug
            Debug.WriteLine(string.Format("Generated a new subkey '{0}' identified as '{4}' and Fingerprint: '{1}' for master key: '{2}' in {3}", subKeyPair.KeyId.ToString("X"), HashedFingerprint(subKeyPair, uppercase: true), pskr.GetPublicKey().KeyId.ToString("X"), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Seconds), keyRingParams.Identity), "Information");

            // Instanciamos un PgpSignatureSubpacketGenerator
            PgpSignatureSubpacketGenerator subpckGen = new();

            // Fijamos las utilidades del certificado
            subpckGen.SetKeyFlags(false, subKeyFlags);

            // Fija los algoritmos de encriptación simetrica preferida
            subpckGen.SetPreferredSymmetricAlgorithms(false, ParseSeverityDirectivesInIntArray(symmetricalAlgorithmDirective));

            // Fija los algoritmos de hash prefereidos
            subpckGen.SetPreferredHashAlgorithms(false, ParseSeverityDirectivesInIntArray(hashAlgorithmDirective));

            // Instancia un PgpKeyRingGenerator
            PgpKeyRingGenerator keyRingGen = new(
                PgpSignature.DefaultCertification,
                pgpKeyPairs[0],
                GetKeyUid(pgpKeyPairs[0].PublicKey, 0),
                pskr.GetSecretKey().KeyEncryptionAlgorithm,
                keyRingParams.HashAlgorithms.Last(),
                keyRingParams.GetPassword(),
                hashAlgorithmDirective == HashAlgorithmSeverityDirectives.Compatibility || hashAlgorithmDirective == HashAlgorithmSeverityDirectives.Minimal,
                subpckGen.Generate(),
                null,
                new SecureRandom());


            // Recorre las sublaves ya existentes en el keyring y las añade al keyring generator
            for (int i = 1; i < pgpKeyPairs.Count; i++)
            {
                // Añade la subclave al keyring generator
                keyRingGen.AddSubKey(pgpKeyPairs[i]);
            }

            // Añade la añade el subkey al generador
            keyRingGen.AddSubKey(subKeyPair, subpckGen.Generate(), null);

            // Instanciamos los keyrings de salida
            PgpSecretKeyRing _pskr = keyRingGen.GenerateSecretKeyRing();
            PgpPublicKeyRing _ppkr = keyRingGen.GeneratePublicKeyRing();

            // Actualiza los KeyRings
            UpdateKeyRing(_pskr, _ppkr);

            // Retorna el identificador de la subclave
            return (_pskr, _ppkr, ackp, subKeyPair.KeyId);
        }

        /// <summary>
        /// Método que añade una pareja de claves como subclave a un keyring pgp
        /// </summary>
        /// <param name="pskr">PgpSecretKeyRing al que añadir una subclave</param>
        /// <param name="subkeyAlgorithmTag">Algoritmo general de la subclave</param>
        /// <param name="subKeyFlags">Propiedades de la subclave</param>
        /// <param name="identity">Indentificador asociado a la subclave</param>
        /// <param name="subkeyPassphrase">Contraseña de la subclave</param>
        /// <param name="passphrases">Diccionario de contraseñas continente de la clave maestra y el resto de subclaves</param>
        /// <param name="expiry">Fecha de caducidez de la clave</param>
        /// <param name="secretKeyEncryptionAlgorithm">Algoritmo de encriptación siméticra de la clave secreta. Usa las opciones de <see cref="SymmetricKeyAlgorithmTag"/> a tu elección.</param>
        /// <param name="symmetricalAlgorithmDirective">Directiva que la sublcave debe seguir en relación a algoritmos de clave simétrica. Usa las opciones de <see cref="SymmetricalAlgorithmSeverityDirectives"/> a tu elección.</param>
        /// <param name="hashAlgorithmDirective">Directiva que la subclave debe seguir en relacion a algoritmos de hash. Usa las opciones de <see cref="HashAlgorithmSeverityDirectives"/> a tu elección.</param>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de clave asimétrica. Usa las opciones de <see cref="AsymmetricalEncryptionAlgorithms"/> a tu elección.</param>
        /// <param name="rsaStrengthPriority">Robustez de la encriptación RSA. Usa las opciones de <see cref="RsaStrengthPriority"/> a tu elección.</param>
        /// <returns>Los keyrings actualzados y la pareja de claves de la subclave</returns>
        public (PgpSecretKeyRing pskr, PgpPublicKeyRing ppkr, AsymmetricCipherKeyPair ackp) AddSubKeyComposed(PgpSecretKeyRing pskr
            , PublicKeyAlgorithmTag subkeyAlgorithmTag
            , int subKeyFlags
            , string identity
            , string passphrase
            , DateTime expiry
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Invoca al método principal
            (PgpSecretKeyRing _pskr, PgpPublicKeyRing _ppkr,  AsymmetricCipherKeyPair _ackp, _) = DoAddSubKey(pskr, subkeyAlgorithmTag, subKeyFlags, identity, passphrase, expiry, symmetricalAlgorithmDirective, hashAlgorithmDirective, asymmetricalEncryptionAlgorithm, rsaStrengthPriority);

            // Retorna los keyring y la parega de claves de la subclave
            return (_pskr,  _ppkr, _ackp);
        }

        /// <summary>
        /// Método que añade una pareja de claves como subclave a un keyring pgp
        /// </summary>
        /// <param name="masterKeyId">Id de la clave maestra</param>
        /// <param name="subkeyAlgorithmTag">Algoritmo general de la subclave</param>
        /// <param name="subKeyFlags">Propiedades de la subclave</param>
        /// <param name="identity">Indentificador asociado a la subclave</param>
        /// <param name="subkeyPassphrase">Contraseña de la subclave</param>
        /// <param name="passphrases">Diccionario de contraseñas continente de la clave maestra y el resto de subclaves</param>
        /// <param name="expiry">Fecha de caducidez de la clave</param>
        /// <param name="secretKeyEncryptionAlgorithm">Algoritmo de encriptación siméticra de la clave secreta. Usa las opciones de <see cref="SymmetricKeyAlgorithmTag"/> a tu elección.</param>
        /// <param name="symmetricalAlgorithmDirective">Directiva que la sublcave debe seguir en relación a algoritmos de clave simétrica. Usa las opciones de <see cref="SymmetricalAlgorithmSeverityDirectives"/> a tu elección.</param>
        /// <param name="hashAlgorithmDirective">Directiva que la subclave debe seguir en relacion a algoritmos de hash. Usa las opciones de <see cref="HashAlgorithmSeverityDirectives"/> a tu elección.</param>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de clave asimétrica. Usa las opciones de <see cref="AsymmetricalEncryptionAlgorithms"/> a tu elección.</param>
        /// <param name="rsaStrengthPriority">Robustez de la encriptación RSA. Usa las opciones de <see cref="RsaStrengthPriority"/> a tu elección.</param>
        /// <returns>Id de la subclave generada</returns>
        public long AddSubKey(long masterKeyId
            , PublicKeyAlgorithmTag subkeyAlgorithmTag
            , int subKeyFlags
            , string identity
            , string passphrase
            , DateTime expiry
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Recupera el keyring desde búsqueda
            PgpSecretKeyRing? pskr = GetPgpSecretKeyRing(masterKeyId);

            // Si no se ha recuperado el keyring
            if (pskr == null) { throw new InvalidOperationException(string.Format("No keyring found with id '{0}'", masterKeyId.ToString("X"))); }

            // Invoca al método principal
            (_, _, _, long _ki) = DoAddSubKey(pskr, subkeyAlgorithmTag, subKeyFlags, identity, passphrase, expiry, symmetricalAlgorithmDirective, hashAlgorithmDirective, asymmetricalEncryptionAlgorithm, rsaStrengthPriority);

            // Retorna el Id de la subclave
            return _ki;
        }

        /// <summary>
        /// Método que añade una pareja de claves como subclave a un keyring pgp
        /// </summary>
        /// <param name="masterKeyIdentifier">Cadena de búsqueda para encontrar la clave maestra</param>
        /// <param name="subkeyAlgorithmTag">Algoritmo general de la subclave</param>
        /// <param name="subKeyFlags">Propiedades de la subclave</param>
        /// <param name="identity">Indentificador asociado a la subclave</param>
        /// <param name="subkeyPassphrase">Contraseña de la subclave</param>
        /// <param name="passphrases">Diccionario de contraseñas continente de la clave maestra y el resto de subclaves</param>
        /// <param name="expiry">Fecha de caducidez de la clave</param>
        /// <param name="secretKeyEncryptionAlgorithm">Algoritmo de encriptación siméticra de la clave secreta. Usa las opciones de <see cref="SymmetricKeyAlgorithmTag"/> a tu elección.</param>
        /// <param name="symmetricalAlgorithmDirective">Directiva que la sublcave debe seguir en relación a algoritmos de clave simétrica. Usa las opciones de <see cref="SymmetricalAlgorithmSeverityDirectives"/> a tu elección.</param>
        /// <param name="hashAlgorithmDirective">Directiva que la subclave debe seguir en relacion a algoritmos de hash. Usa las opciones de <see cref="HashAlgorithmSeverityDirectives"/> a tu elección.</param>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de clave asimétrica. Usa las opciones de <see cref="AsymmetricalEncryptionAlgorithms"/> a tu elección.</param>
        /// <param name="rsaStrengthPriority">Robustez de la encriptación RSA. Usa las opciones de <see cref="RsaStrengthPriority"/> a tu elección.</param>
        /// <returns>Id de la subclave generada</returns>
        public long AddSubKey(string masterKeyIdentifier
            , PublicKeyAlgorithmTag subkeyAlgorithmTag
            , int subKeyFlags
            , string identity
            , string passphrase
            , DateTime expiry
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Recupera el keyring desde búsqueda
            PgpSecretKeyRing? pskr = GetPgpSecretKeyRing(masterKeyIdentifier);

            // Si no se ha recuperado el keyring
            if (pskr == null) { throw new InvalidOperationException($"No keyring found with identifier '{identity}'");  }

            // Invoca al método principal
            (_, _, _, long _ki) = DoAddSubKey(pskr, subkeyAlgorithmTag, subKeyFlags, identity, passphrase, expiry, symmetricalAlgorithmDirective, hashAlgorithmDirective, asymmetricalEncryptionAlgorithm, rsaStrengthPriority);

            // Retorna el Id de la subclave
            return _ki;
        }


        /// <summary>
        /// Método maestro que elimina un PgpPublicKeyRing del bundle
        /// </summary>
        /// <param name="ppkr">PgpPublicKeyRing a elimnar</param>
        public void RemoveKeyRing(PgpPublicKeyRing? ppkr)
        {
            // Si el keyring viene como nulo, sale del método
            if (ppkr == null) { return; }

            // Añade el PgpSecretKeyRing actualizado al bundle
            PublicKeyRingBundle = PgpPublicKeyRingBundle.RemovePublicKeyRing(PublicKeyRingBundle, ppkr);

            // Si el volcado de datos inmediato está activado
            if (PublicKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
            {
                // Realiza el volcado de datos a disco
                DumpKeyRingBundle(in PublicKeyRingBundle);
            }
        }

        /// <summary>
        /// Método maestro que elimina un PgpSecretKeyRing del bundle
        /// </summary>
        /// <param name="pskr">PgpSecretKeyRing a elimnar</param>
        public void RemoveKeyRing(PgpSecretKeyRing? pskr)
        {
            // Si el keyring viene como nulo, sale del método
            if (pskr == null) { return; }

            // Añade el PgpSecretKeyRing actualizado al bundle
            SecretKeyRingBundle = PgpSecretKeyRingBundle.RemoveSecretKeyRing(SecretKeyRingBundle, pskr);

            // Si el volcado de datos inmediato está activado
            if (SecretKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
            {
                // Realiza el volcado de datos a disco
                DumpKeyRingBundle(in SecretKeyRingBundle);
            }
        }

        /// <summary>
        /// Método que elimina un keyring público y secreto del bundle
        /// </summary>
        /// <param name="keyringId">Id de clave de los keyring a eliminar</param>
        public void RemoveKeyRing(long keyringId)
        {
            // Elimina el keyring secreto
            RemoveSecretKeyRing(keyringId);

            // Elimina el keyring publico
            RemovePublicKeyRing(keyringId);
        }

        /// <summary>
        /// Método que elimina un keyring público y secreto del bundle
        /// </summary>
        /// <param name="fingerprint">Indentificador fingerprint de los keyring a eliminar</param>
        public void RemoveKeyRing(string fingerprint)
        {
            // Elimina el keyring secreto
            RemoveSecretKeyRing(fingerprint);

            // Elimina el keyring publico
            RemovePublicKeyRing(fingerprint);
        }

        /// <summary>
        /// Método que elimina un keyring público del bundle
        /// </summary>
        /// <param name="keyringId">Id del keyring a eliminar</param>
        public void RemovePublicKeyRing(long keyringId)
        {
            // Busca el keyring en el bundle y lo manda eliminar
            RemoveKeyRing(PublicKeyRingBundle.GetPublicKeyRing(keyringId));
        }
        
        /// <summary>
        /// Método que elimina un keyring secreto del bundle
        /// </summary>
        /// <param name="fingerprint">Fingerprint identificativo del keyring a eliminar</param>
        public void RemovePublicKeyRing(string fingerprint)
        {
            // Busca el PublicKey que concuerda con el fingerprint
            PgpPublicKey? ppk = GetPgpPublicKey(fingerprint);

            // Si no se recupera la llave, sale del método
            if (ppk == null) { throw new InvalidOperationException(string.Format("Not found any keyring with identifier: '{0}'", fingerprint)); }

            // Si esta llave pública tiene una llave secreta vinculada, lanzará error de eliminación ilegal
            if (GetPgpSecretKey(fingerprint) != null) { throw new IlegalKeyDeleteException("This public key has a private key. Please delete the private key previously."); }

            // Busca el keyring en el bundle y lo manda eliminar
            RemoveKeyRing(PublicKeyRingBundle.GetPublicKeyRing(ppk.KeyId));
        }

        /// <summary>
        /// Método que elimina un keyring secreto del bundle
        /// </summary>
        /// <param name="keyringId">Id del keyring a eliminar</param>
        public void RemoveSecretKeyRing(long keyringId)
        {
            // Busca el keyring en el bundle y lo manda eliminar
            RemoveKeyRing(SecretKeyRingBundle.GetSecretKeyRing(keyringId));
        }

        /// <summary>
        /// Método que elimina un keyring secreto del bundle
        /// </summary>
        /// <param name="fingerprint">Fingerprint identificativo del keyring a eliminar</param>
        public void RemoveSecretKeyRing(string fingerprint)
        {
            // Busca el SecretKey que concuerda con el fingerprint
            PgpSecretKey? psk = GetPgpSecretKey(fingerprint);
            
            // Si no se recupera la llave, sale del método
            if (psk == null) { throw new InvalidOperationException(string.Format("Not found any keyring with identifier: '{0}'", fingerprint)); }

            // Busca el keyring en el bundle y lo manda eliminar
            RemoveKeyRing(SecretKeyRingBundle.GetSecretKeyRing(psk.KeyId));
        }

        /// <summary>
        /// Método maestro que importa un keyring público desde stream de datos
        /// </summary>
        /// <param name="pgpPub">PgpPublicKeyRing a importar</param>
        /// <exception cref="NoneImportKeyException">Excepción producida cuando ocurre algún problema con el keyring a importar</exception>
        /// <exception cref="InvalidOperationException">Excepción producida cunado ocurre un error no controlado en el proceso de importación</exception>
        public PgpPublicKeyRing ImportPublicKeyRing(PgpPublicKeyRing pgpPub, bool rewriteIfExists = false)
        {
            try
            {
                // Valida el keyring
                ValidateKeyRing(pgpPub);

                // Si el keyring ya existe en bundle, lo sobreescribe
                if (PublicKeyRingBundle.GetPublicKeyRing(pgpPub.GetPublicKey().KeyId) != null)
                {
                    // Si la opción de sobreescribir si existe no esta marcada como True
                    if (!rewriteIfExists) { throw new NoneImportKeyException("The keyring already exists!"); }

                    // Actualiza el keyring en el bundle
                    UpdateKeyRing(pgpPub);

                    // Sale del método
                    return pgpPub;
                }

                // Recupera el publicKey maestro del keyring a importar
                PgpPublicKey ppk2 = pgpPub.GetPublicKey();

                // Recorre el bundle
                foreach (PgpPublicKeyRing ppkr in PublicKeyRingBundle.GetKeyRings())
                {
                    // Instancia los publicKeys
                    PgpPublicKey ppk = ppkr.GetPublicKey();

                    // Si no es clave maesrta, salta el ciclo
                    if (!ppk.IsMasterKey)
                    { continue; }

                    // Si el ID ya esta de alta
                    if (GetKeyUid(ppk, 0) == GetKeyUid(ppk2, 0))
                    {
                        // Si la opción de sobreescribir si existe no esta marcada como True
                        if (!rewriteIfExists) { throw new NoneImportKeyException("The keyring already exists!"); }

                        // Actualiza el keyring en el bundle
                        UpdateKeyRing(pgpPub);

                        // Sale del método
                        return pgpPub;
                    }
                }

                // Añade el nuevo keyring al bundle
                PublicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(PublicKeyRingBundle, pgpPub);

                // Si el volcado de datos inmediato está activado
                if (PublicKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
                {
                    // Realiza el volcado de datos a disco
                    DumpKeyRingBundle(in PublicKeyRingBundle);
                }

                // Sale sin errores
                return pgpPub;
            }
            catch (IOException)
            {
                // Lanza excepción personalizada
                throw new NoneImportKeyException("No keyring data found in stream");
            }
            catch (InvalidKeyException)
            {
                // Lanza excepción personalizada
                throw new NoneImportKeyException("The keyring does not meet the validity requirements");
            }

            // Lanza error desconocido
            throw new InvalidOperationException("Unknown error ocurred trying to import key ring from stream.");
        }

        /// <summary>
        /// Método maestro que reemplaza un keyring público existente por otro nuevo
        /// </summary>
        /// <param name="newPgpPub">PgpPublicKeyRing a que remplazará al existente</param>
        /// <param name="oldPgpPub">PgpPublicKeyRing a que será reemplazado</param>
        /// <exception cref="NoneImportKeyException">Excepción producida cuando ocurre algún problema con el keyring a importar</exception>
        /// <exception cref="InvalidOperationException">Excepción producida cunado ocurre un error no controlado en el proceso de importación</exception>
        public PgpPublicKeyRing ReplacePublicKeyRing(PgpPublicKeyRing newPgpPub, PgpPublicKeyRing oldPgpPub)
        {
            try
            {
                // Valida ambos keyring
                ValidateKeyRing(newPgpPub);
                ValidateKeyRing(oldPgpPub);

                // Si el keyring ya existe en bundle, lo sobreescribe
                if (PublicKeyRingBundle.GetPublicKeyRing(newPgpPub.GetPublicKey().KeyId) != null)
                {
                    // Lanza excepción
                    throw new NoneImportKeyException("The keyring already exists!");
                }

                // Elimina el viejo keyring
                RemoveKeyRing(oldPgpPub);

                // Añade el nuevo keyring al bundle
                PublicKeyRingBundle = PgpPublicKeyRingBundle.AddPublicKeyRing(PublicKeyRingBundle, newPgpPub);

                // Si el volcado de datos inmediato está activado
                if (PublicKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
                {
                    // Realiza el volcado de datos a disco
                    DumpKeyRingBundle(in PublicKeyRingBundle);
                }

                // Sale sin errores
                return newPgpPub;
            }
            catch (IOException)
            {
                // Lanza excepción personalizada
                throw new NoneImportKeyException("No keyring data found in stream");
            }
            catch (InvalidKeyException)
            {
                // Lanza excepción personalizada
                throw new NoneImportKeyException("The stream has keyring but this does not meet the validity requirements");
            }

            // Lanza error desconocido
            throw new InvalidOperationException("Unknown error ocurred trying to import key ring from stream.");
        }

        /// <summary>
        /// Método maestro que importa un keyring público desde stream de datos
        /// </summary>
        /// <param name="inputStream">Stream de datos desde los que importar el keyring público</param>
        /// <exception cref="NoneImportKeyException">Excepción producida cuando ocurre algún problema con el keyring a importar</exception>
        /// <exception cref="InvalidOperationException">Excepción producida cunado ocurre un error no controlado en el proceso de importación</exception>
        public PgpPublicKeyRing ImportPublicKeyRing(Stream inputStream, bool rewriteIfExists = false)
        {
            // Decodifica el stream
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            // Invoca al método maestro
            return ImportPublicKeyRing(new PgpPublicKeyRing(inputStream), rewriteIfExists);
        }

        /// <summary>
        /// Método maestro que importa un keyring público desde array de bytes
        /// </summary>
        /// <param name="inputBytes">Array de bytes desde el que importar el keyring público</param>
        /// <exception cref="NoneImportKeyException">Excepción producida cuando ocurre algún problema con el keyring a importar</exception>
        /// <exception cref="Exception">Excepción producida cunado ocurre un error no controlado en el proceso de importación</exception>
        public PgpPublicKeyRing ImportPublicKeyRing(byte[] inputBytes, bool rewriteIfExists = false) 
        {
            // Invoca al método de importación maestro
            return ImportPublicKeyRing(new MemoryStream(inputBytes), rewriteIfExists);
        }

        /// <summary>
        /// Método que importa un keyring secreto desde stream de datos
        /// </summary>
        /// <param name="inputStream">Stream de datos desde los que importar el keyring secreto</param>
        /// <exception cref="NoneImportKeyException">Excepción producida cuando ocurre algún problema con el keyring a importar</exception>
        /// <exception cref="InvalidOperationException">Excepción producida cunado ocurre un error no controlado en el proceso de importación</exception>
        public PgpSecretKeyRing ImportSecretKeyRing(Stream inputStream, bool rewriteIfExists = false)
        {
            // Decodifica el stream
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            // Invoca al método maestro
            return ImportSecretKeyRing(new PgpSecretKeyRing(inputStream), rewriteIfExists);
        }

        /// <summary>
        /// Método maestro que importa un keyring secreto
        /// </summary>
        /// <param name="pgpSec">PgpSecretKeyRing a importar</param>
        /// <exception cref="NoneImportKeyException">Excepción producida cuando ocurre algún problema con el keyring a importar</exception>
        /// <exception cref="InvalidOperationException">Excepción producida cunado ocurre un error no controlado en el proceso de importación</exception>
        public PgpSecretKeyRing ImportSecretKeyRing(PgpSecretKeyRing pgpSec, bool rewriteIfExists = false)
        {
            try
            {
                // Valida el keyring
                ValidateKeyRing(pgpSec);

                // Si el keyring ya existe en bundle, lo sobreescribe
                if (SecretKeyRingBundle.GetSecretKeyRing(pgpSec.GetPublicKey().KeyId) != null)
                {
                    // Si la opción de sobreescribir si existe no esta marcada como True
                    if (!rewriteIfExists) { throw new NoneImportKeyException("The keyring already exists!"); }

                    // Actualiza el keyring en el bundle
                    UpdateKeyRing(pgpSec);

                    // Sale del método
                    return pgpSec;
                }

                // Añade el nuevo keyring al bundle
                SecretKeyRingBundle = PgpSecretKeyRingBundle.AddSecretKeyRing(SecretKeyRingBundle, pgpSec);

                // Si el volcado de datos inmediato está activado
                if (SecretKeyRingDumpFrequency == PgpKeyRingDumpFrequency.Inmediately)
                {
                    // Realiza el volcado de datos a disco
                    DumpKeyRingBundle(in SecretKeyRingBundle);
                }

                // Sale sin errores
                return pgpSec;
            }
            catch (IOException)
            {
                // Lanza excepción personalizada
                throw new NoneImportKeyException("No keyring data found in stream");
            }
            catch (InvalidKeyException)
            {
                // Lanza excepción personalizada
                throw new NoneImportKeyException("The stream has keyring but this does not meet the validity requirements");
            }

            // Lanza error desconocido
            throw new InvalidOperationException("Unknown error ocurred trying to import key ring from stream.");
        }

        /// <summary>
        /// Método maestro que importa un keyring secreto desde array de bytes
        /// </summary>
        /// <param name="inputBytes">Array de bytes desde el que importar el keyring secreto</param>
        /// <exception cref="NoneImportKeyException">Excepción producida cuando ocurre algún problema con el keyring a importar</exception>
        /// <exception cref="Exception">Excepción producida cunado ocurre un error no controlado en el proceso de importación</exception>
        public PgpSecretKeyRing ImportSecretKeyRing(byte[] inputBytes, bool rewriteIfExists = false)
        {
            // Invoca al método de importación maestro
            return ImportSecretKeyRing(new MemoryStream(inputBytes), rewriteIfExists);
        }

        /// <summary>
        /// Método maestro que exporta un PgpPublicKeyRing a stream
        /// </summary>
        /// <param name="ppkr">PgpPublicKeyRing a exportar</param>
        /// <param name="armor">True: Exportará los datos del keyring en caracteres ASCII para facilitar su transporte como texto plano</param>
        /// <returns>Retorna Stream con los datos del kering exportado</returns>
        /// <exception cref="ArgumentException">Excepción producida cuando PgpPublicKeyRing viene como nulo</exception>
        public Stream ExportPublicKeyRing(PgpPublicKeyRing ppkr, bool armor = false)
        {
            // Si el PublicKeyRing le viene como nulo
            if (ppkr == null) { throw new ArgumentException("No public keys found"); }

            // Valida el keyring primero
            ValidateKeyRing(ppkr);

            // Instancia Streams para trabajar con los datos
            MemoryStream bOut = new();
            Stream output = bOut;

            // Si se ha decidido armar los datos en ASCII para que puedan enviarse facilmente como texto, instancia un ArmoredOutputStream
            if (armor) { output = new ArmoredOutputStream(bOut); }

            // Codifica los datos del keyring en el memoryStream
            ppkr.Encode(output);

            // Si se ha decidido armar los datos en ASCII para que puedan enviarse facilmente como texto, cierra el ArmoredOutputStream
            if (armor) { output.Close(); }

            // Fija el Stream en la posición 0
            bOut.Seek(0, SeekOrigin.Begin);

            // Retorna el MemoryStream
            return bOut;
        }

        /// <summary>
        ///  Método que exporta un PgpPublicKeyRing a stream desde key id
        /// </summary>
        /// <param name="keyringId">Id de la clave a exportar (exportará todo el keyring al que pertenece la clave)</param>
        /// <param name="armor">True: Exportará los datos del keyring en caracteres ASCII para facilitar su transporte como texto plano</param>
        /// <returns>Retorna Stream con los datos del kering exportado</returns>
        public Stream ExportPublicKeyRing(long keyringId, bool armor = false)
        {
            // Busca el keyring por id de clave y lo manda exportar
            return ExportPublicKeyRing(PublicKeyRingBundle.GetPublicKeyRing(keyringId), armor);
        }

        /// <summary>
        /// Método que exporta un PgpPublicKeyRing a stream desde key fingerprint
        /// </summary>
        /// <param name="fingerprint">Fingerprint de la llave a exportar ( Exportará todo el keyring al que pertenece la llave )</param>
        /// <param name="armor">True: Exportará los datos del keyring en caracteres ASCII para facilitar su transporte como texto plano</param>
        /// <returns>Retorna Stream con los datos del kering exportado</returns>
        /// <exception cref="ArgumentException">Excepción producida si no se encuentra ningún public key con el fingerprint pasado por argumento</exception>
        public Stream ExportPublicKeyRing(string fingerprint, bool armor = false)
        {
            // Busca el key desde el indentificador fingerprint
            PgpPublicKey? ppk = GetPgpPublicKey(fingerprint);

            // Si el PublicKey le viene como nulo
            if (ppk == null) { throw new ArgumentException(string.Format("No public keys found with fingerptint '{0}'", fingerprint)); }

            // Exporta el keyring al que pertenece el publick key desde su keyId
            return ExportPublicKeyRing(ppk.KeyId, armor);
        }

        /// <summary>
        /// Método maestro que exporta un PgpSecretKeyRing a stream
        /// </summary>
        /// <param name="ppkr">PgpPublicKeyRing a exportar</param>
        /// <param name="armor">True: Exportará los datos del keyring en caracteres ASCII para facilitar su transporte como texto plano</param>
        /// <returns>Retorna Stream con los datos del kering exportado</returns>
        /// <exception cref="ArgumentException">Excepción producida cuando PgpPublicKeyRing viene como nulo</exception>
        public Stream ExportSecretKeyRing(PgpSecretKeyRing pskr, bool armor = false)
        {
            // Si el PublicKeyRing le viene como nulo
            if (pskr == null) { throw new ArgumentException("No secret keys found"); }

            // Valida el keyring primero
            ValidateKeyRing(pskr);

            // Instancia Streams para trabajar con los datos
            MemoryStream bOut = new();
            Stream output = bOut;

            // Si se ha decidido armar los datos en ASCII para que puedan enviarse facilmente como texto, instancia un ArmoredOutputStream
            if (armor) { output = new ArmoredOutputStream(bOut); }

            // Codifica los datos del keyring en el memoryStream
            pskr.Encode(output);

            // Si se ha decidido armar los datos en ASCII para que puedan enviarse facilmente como texto, cierra el ArmoredOutputStream
            if (armor) { output.Close(); }

            // Fija el Stream en la posición 0
            bOut.Seek(0, SeekOrigin.Begin);

            // Retorna el MemoryStream
            return bOut;
        }

        /// <summary>
        ///  Método que exporta un PgpSecretKeyRing a stream desde key id
        /// </summary>
        /// <param name="keyringId">Id de la clave a exportar (exportará todo el keyring al que pertenece la clave)</param>
        /// <param name="armor">True: Exportará los datos del keyring en caracteres ASCII para facilitar su transporte como texto plano</param>
        /// <returns>Retorna Stream con los datos del kering exportado</returns>
        public Stream ExportSecretKeyRing(long keyringId, bool armor = false)
        {
            // Busca el keyring por id de clave y lo manda exportar
            return ExportSecretKeyRing(SecretKeyRingBundle.GetSecretKeyRing(keyringId), armor);
        }

        /// <summary>
        /// Método que exporta un PgpSecretKeyRing a stream desde key fingerprint
        /// </summary>
        /// <param name="fingerprint">Fingerprint de la llave a exportar ( Exportará todo el keyring al que pertenece la llave )</param>
        /// <param name="armor">True: Exportará los datos del keyring en caracteres ASCII para facilitar su transporte como texto plano</param>
        /// <returns>Retorna Stream con los datos del kering exportado</returns>
        /// <exception cref="ArgumentException">Excepción producida si no se encuentra ningún public key con el fingerprint pasado por argumento</exception>
        public Stream ExportSecretKeyRing(string fingerprint, bool armor = false)
        {
            // Busca el key desde el indentificador fingerprint
            PgpSecretKey? psk = GetPgpSecretKey(fingerprint);

            // Si el PublicKey le viene como nulo
            if (psk == null) { throw new ArgumentException(string.Format("No secret keys found with fingerptint '{0}'", fingerprint)); }

            // Exporta el keyring al que pertenece el publick key desde su keyId
            return ExportSecretKeyRing(psk.KeyId, armor);
        }

        /// <summary>
        /// Método que recupera el PgpPublicKey maestro de un keyring desde cualquier id de clave del keyring
        /// </summary>
        /// <param name="keyId">Id de clave que pertenece al keyring donde buscar</param>
        /// <returns>El master PgpPublicKey del keyring</returns>
        public PgpPublicKey GetMasterPublicKey(long keyId)
        {
            // Recupera el key ring público al que pertenece el keyId
            PgpPublicKeyRing ppkr = PublicKeyRingBundle.GetPublicKeyRing(keyId);

            // Valida el key ring
            ValidateKeyRing(ppkr);

            // Devuelve el master key del keyring público
            return ppkr.GetPublicKey();
        }

        /// <summary>
        /// Método que recupera el PgpPublicKey maestro de un keyring desde cualquier id de clave del keyring
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>El master PgpPublicKey del keyring</returns>
        public PgpPublicKey? GetMasterPublicKey(string search, bool matchPartial = false, bool ignoreCase = false)
        {
            // Recupera el key ring público al que pertenece el keyId
            PgpPublicKeyRing? ppkr = GetPgpPublicKeyRing(search, matchPartial, ignoreCase);

            // Si la busqueda retorna nulo, sale con nulo
            if (ppkr == null) { return null; }

            // Valida el key ring
            ValidateKeyRing(ppkr);

            // Devuelve el master key del keyring público
            return ppkr.GetPublicKey();
        }

        /// <summary>
        /// Método que recupera el PgpSecretKey maestro de un keyring desde cualquier id de clave del keyring
        /// </summary>
        /// <param name="keyId">Id de clave que pertenece al keyring donde buscar</param>
        /// <returns>El master PgpSecretKey del keyring</returns>
        public PgpSecretKey GetMasterSecretKey(long keyId)
        {
            // Recupera el key ring público al que pertenece el keyId
            PgpSecretKeyRing pskr = SecretKeyRingBundle.GetSecretKeyRing(keyId);

            // Valida el key ring
            ValidateKeyRing(pskr);

            // Devuelve el master key del keyring secreto
            return pskr.GetSecretKey();
        }

        /// <summary>
        /// Método que recupera el PgpSecretKey maestro de un keyring desde cualquier id de clave del keyring
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>El master PgpSecretKey del keyring</returns>
        public PgpSecretKey? GetMasterSecretKey(string search, bool matchPartial = false, bool ignoreCase = false)
        {
            // Recupera el key ring público al que pertenece el keyId
            PgpSecretKeyRing? pskr = GetPgpSecretKeyRing(search, matchPartial, ignoreCase);

            // Si la busqueda retorna nulo, sale con nulo
            if (pskr == null) { return null; }

            // Valida el key ring
            ValidateKeyRing(pskr);

            // Devuelve el master key del keyring público
            return pskr.GetSecretKey();
        }

        /// <summary>
        /// Método que recupera un identicador UID de un PgpSecretKey sin necesidad de instancia
        /// </summary>
        /// <param name="psk">PgpSecretKey donde extraer el identificador UID</param>
        /// <param name="identifierIndex">Identificador del UID</param>
        /// <returns>El UID de la clave</returns>
        public static string? ShowKeyUid(PgpSecretKey psk, int identifierIndex)
        {
            // Si el key obtenido no es llave maestra, recupera el master key asociado
            if (!psk.IsMasterKey) { return null; }

            try
            {
                // Intenta retornar el identificador indicado por argumento
                return psk.UserIds.Cast<string>().ToArray()[identifierIndex];
            }
            catch (IndexOutOfRangeException)
            {
                // Retorna el identificador principal
                return psk.UserIds.Cast<string>().ToArray()[0];
            }
        }

        /// <summary>
        /// Método que recupera un identicador UID de un PgpSecretKey
        /// </summary>
        /// <param name="psk">PgpSecretKey donde extraer el identificador UID</param>
        /// <param name="identifierIndex">Identificador del UID</param>
        /// <returns>El UID de la clave</returns>
        public string GetKeyUid(PgpSecretKey psk, int identifierIndex)
        {
            // Si el key obtenido no es llave maestra, recupera el master key asociado
            if (!psk.IsMasterKey) { psk = GetMasterSecretKey(psk.KeyId); }

            try
            {
                // Intenta retornal el identificador indicado por argumento
                return psk.UserIds.Cast<string>().ToArray()[identifierIndex];
            }
            catch (IndexOutOfRangeException)
            {
                // Retorna el identificador principal
                return psk.UserIds.Cast<string>().ToArray()[0];
            }
        }

        /// <summary>
        /// Método que recupera un identicador UID de un PgpPublicKey sin necesidad de instancia
        /// </summary>
        /// <param name="ppk">PgpPublicKey donde extraer el identificador UID</param>
        /// <param name="identifierIndex">Identificador del UID</param>
        /// <returns>El UID de la clave</returns>
        public static string? ShowKeyUid(PgpPublicKey ppk, int identifierIndex)
        {
            // Si el key obtenido no es llave maestra, recupera el master key asociado
            if (!ppk.IsMasterKey) { return null; }

            try
            {
                // Intenta retornar el identificador indicado por argumento
                return ppk.GetUserIds().Cast<string>().ToArray()[identifierIndex];
            }
            catch (IndexOutOfRangeException)
            {
                // Retorna el identificador principal
                return ppk.GetUserIds().Cast<string>().ToArray()[0];
            }
        }

        /// <summary>
        /// Método que recupera un identicador UID de un PgpPublicKey
        /// </summary>
        /// <param name="ppk">PgpPublicKey donde extraer el identificador UID</param>
        /// <param name="identifierIndex">Identificador del UID</param>
        /// <returns>El UID de la clave</returns>
        public string GetKeyUid(PgpPublicKey ppk, int identifierIndex)
        {
            // Si el key obtenido no es llave maestra, recupera el master key asociado
            if (!ppk.IsMasterKey) { ppk = GetMasterPublicKey(ppk.KeyId); }

            try
            {
                // Intenta retornar el identificador indicado por argumento
                return ppk.GetUserIds().Cast<string>().ToArray()[identifierIndex];
            }
            catch (IndexOutOfRangeException)
            {
                // Retorna el identificador principal
                return ppk.GetUserIds().Cast<string>().ToArray()[0];
            }
        }

        /// <summary>
        /// Método que recupera un identicador UID de un PgpPublicKey sin necesidad de instancia
        /// </summary>
        /// <param name="keyId">Identificador de clave de la que extraer el identificador UID</param>
        /// <param name="identifierIndex">Identificador del UID</param>
        /// <returns>El UID de la clave</returns>
        public string GetKeyUid(long keyId, int identifierIndex)
        {
            // Recupera el master key
            PgpPublicKey ppk = GetMasterPublicKey(keyId);

            try
            {
                // Intenta retornar el identificador indicado por argumento
                return ppk.GetUserIds().Cast<string>().ToArray()[identifierIndex];
            }
            catch (IndexOutOfRangeException)
            {
                // Retorna el identificador principal
                return ppk.GetUserIds().Cast<string>().ToArray()[0];
            }
        }
        
        /// <summary>
        /// Método que busca una clave pública en el KeyRing
        /// </summary>
        /// <param name="keyId">Id de la clave pública que se desea obtener del keyring</param>
        /// <returns>Nulo si no encuentra la clave pública</returns>
        public PgpPublicKey GetPgpPublicKey(long keyId)
        {
            // Retorna la busqueda
            return PublicKeyRingBundle.GetPublicKey(keyId);
        }

        /// <summary>
        /// Método que busca un keyring público en el bundle desde coincidencias de texto
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>Nulo si no encuentra un keyring coincidente</returns>
        public PgpPublicKeyRing? GetPgpPublicKeyRing(string search, bool matchPartial = false, bool ignoreCase = false)
        {
            // Recupera todos los keyrings publicos en un array
            //PgpPublicKeyRing[] publicKeyRings = PublicKeyRingBundle.GetKeyRings(search, matchPartial, ignoreCase).Cast<PgpPublicKeyRing>().ToArray();
            PgpPublicKeyRing[] publicKeyRings = PublicKeyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().ToArray();

            // Recorre los anillos que contienen
            foreach (PgpPublicKeyRing ppkr in publicKeyRings)
            {
                // Recorre las claves públicas del anillo
                foreach (PgpPublicKey ppk in ppkr.GetPublicKeys())
                {
                    // Si el fingerprint de la clave pública concuerda con el search
                    if (HashedFingerprint(ppk, true) == search.ToUpper()) { return ppkr; }

                    // Recorre la lista de Ids del ppk
                    foreach (string uid in ppk.GetUserIds())
                    {
                        // Si se ha marcado la baliza de emparejar parcialmente
                        if (matchPartial)
                        {
                            // Modo ignorativo
                            if (ignoreCase) { if (uid.ToUpper() == search.ToUpper()) { return ppkr; } }
                            // Modo sensitivo
                            else { if (uid == search) { return ppkr; } }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si se ha marcado la baliza de ignorar mayusculas/minusculas
                        if (ignoreCase)
                        {
                            // Hace la comparativa en mayusculas
                            if (uid.ToUpper() == search.ToUpper()) { return ppkr; }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si el uid coincide con la busqueda
                        if (uid == search) { return ppkr; }
                    }
                }
            }

            // Retorna nulo
            return null;
        }

        /// <summary>
        /// Método que busca un keyring público en el bundle desde key id
        /// </summary>
        /// <param name="keyid">Id de la llave a buscar</param>
        /// <returns>El PgpPublicKeyRing encontrado</returns>
        public PgpPublicKeyRing? GetPgpPublicKeyRing(long keyid)
        {
            // Retrona la busqueda del keyring en el bundle
            return PublicKeyRingBundle.GetPublicKeyRing(keyid);
        }

        /// <summary>
        /// Método que busca una clave pública en el KeyRing
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>Nulo si no encuentra la clave pública</returns>
        public PgpPublicKey? GetPgpPublicKey(string search, bool onlyMasterKeys = false, bool matchPartial = false, bool ignoreCase = false)
        {
            // Si el texto de busqueda ya viene como nulo, retorna nulo directamente
            if (search == null) { return null; }

            // Recupera todos los keyrings publicos en un array
            //PgpPublicKeyRing[] publicKeyRings = PublicKeyRingBundle.GetKeyRings(search, matchPartial, ignoreCase).Cast<PgpPublicKeyRing>().ToArray();
            PgpPublicKeyRing[] publicKeyRings = PublicKeyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().ToArray();

            // Si recupera mas de un keyring
            //if (publicKeyRings.Length > 1) { throw new InvalidOperationException("Multiple posible results founded. Use GetPgpPublicKeys instead."); }

            // Recorre los anillos que contienen
            foreach (PgpPublicKeyRing ppkr in publicKeyRings)
            {
                // Recorre las claves públicas del anillo
                foreach(PgpPublicKey ppk in ppkr.GetPublicKeys())
                {
                    // Si la baliza de buscar solo master keys esta activa y el PgpPublicKey no es un masterKey, pasa del método
                    if (onlyMasterKeys && !ppk.IsMasterKey) { continue; }

                    // Si el fingerprint de la clave pública concuerda con el search
                    if (HashedFingerprint(ppk, true) == search.ToUpper()) 
                    { 
                        return ppk; 
                    }
                    
                    // Recorre la lista de Ids del ppk
                    foreach (string uid in ppk.GetUserIds())
                    {
                        // Si se ha marcado la baliza de emparejar parcialmente
                        if (matchPartial)
                        {
                            // Modo ignorativo
                            if (ignoreCase) { if (uid.ToUpper() == search.ToUpper()) { return ppk; } }
                            // Modo sensitivo
                            else { if (uid == search) { return ppk; } }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si se ha marcado la baliza de ignorar mayusculas/minusculas
                        if (ignoreCase)
                        {
                            // Hace la comparativa en mayusculas
                            if (uid.ToUpper() == search.ToUpper()) { return ppk; }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si el uid coincide con la busqueda
                        if (uid == search) { return ppk; }
                    }
                }
            }

            // Retorna nulo
            return null;
        }

        /// <summary>
        /// Método que busca claves públicas en el KeyRing
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>Nulo si no encuentra ninguna concidencia</returns>
        public PgpPublicKey[]? GetPgpPublicKeys(string search, bool matchPartial = false, bool ignoreCase = false, bool onlyMasterKeys = false)
        {
            // Si el texto de busqueda ya viene como nulo, retorna nulo directamente
            if (search == null) { return null; }

            // Instanciamos una lista de claves públicas a retornar
            List<PgpPublicKey> _return = new();

            // Recupera todos los keyrings publicos en un array
            PgpPublicKeyRing[] publicKeyRings = search.Length > 0 ? PublicKeyRingBundle.GetKeyRings(search, matchPartial, ignoreCase).Cast<PgpPublicKeyRing>().ToArray() : PublicKeyRingBundle.GetKeyRings().Cast<PgpPublicKeyRing>().ToArray();

            // Recorre los anillos que contienen
            foreach (PgpPublicKeyRing ppkr in publicKeyRings)
            {
                // Recorre las claves públicas del anillo
                foreach (PgpPublicKey ppk in ppkr.GetPublicKeys())
                {
                    // Si se desea revisar solo claves maestras y la clave que se está iterando no es maestra, pasa de ciclo
                    if (onlyMasterKeys && !ppk.IsMasterKey) { continue; }

                    // Si el search viene vacío, lo añade al output y pasa de ciclo
                    if (search.Length == 0) { _return.Add(ppk); continue; }

                    // Si el fingerprint de la clave pública concuerda con el search
                    if (HashedFingerprint(ppk, true) == search.ToUpper()) 
                    { 
                        // Añade el public key a la lista
                        _return.Add(ppk);

                        // Pasa de ciclo
                        continue;
                    }

                    // Recorre la lista de Ids del ppk
                    foreach (string uid in ppk.GetUserIds())
                    {
                        // Si se ha marcado la baliza de emparejar parcialmente
                        if (matchPartial)
                        {
                            // Modo ignorativo
                            if (ignoreCase) { if (uid.ToUpper() == search.ToUpper()) { _return.Add(ppk); } }
                            // Modo sensitivo
                            else { if (uid == search) { _return.Add(ppk); } }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si se ha marcado la baliza de ignorar mayusculas/minusculas
                        if (ignoreCase)
                        {
                            // Hace la comparativa en mayusculas
                            if (uid.ToUpper() == search.ToUpper()) { _return.Add(ppk); }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si el uid coincide con la busqueda
                        if (uid == search) { _return.Add(ppk); }
                    }
                }
            }

            // Retorna el array de retorno o nulo si precede
            return _return.ToArray();
        }

        /// <summary>
        /// Método que busca una clave privada en el KeyRing
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>Nulo si no encuentra la clave privada</returns>
        public PgpPrivateKey? GetPgpPrivateKey(string search, string passphrase, bool matchPartial = false, bool ignoreCase = false)
        {
            // Si el texto de busqueda ya viene como nulo, retorna nulo directamente
            if (search == null) { return null; }

            // Recupera todos los keyrings publicos en un array
            PgpSecretKeyRing[] secretKeyRings = SecretKeyRingBundle.GetKeyRings(search, matchPartial, ignoreCase).Cast<PgpSecretKeyRing>().ToArray();

            // Si recupera mas de un keyring
            if (secretKeyRings.Length > 1) { throw new InvalidOperationException("Multiple posible results founded. Use a more specified search parameters."); }

            // Recorre los anillos que contienen
            foreach (PgpSecretKeyRing pskr in secretKeyRings)
            {
                // Recorre las claves públicas del anillo
                foreach (PgpSecretKey psk in pskr.GetSecretKeys())
                {
                    // Si el fingerprint de la clave pública concuerda con el search
                    if (HashedFingerprint(psk.PublicKey, true) == search.ToUpper()) { return psk.ExtractPrivateKey(passphrase.ToCharArray()); }

                    // Recorre la lista de Ids del ppk
                    foreach (string uid in psk.UserIds)
                    {
                        // Si se ha marcado la baliza de emparejar parcialmente
                        if (matchPartial)
                        {
                            // Modo ignorativo
                            if (ignoreCase) { if (uid.ToUpper() == search.ToUpper()) { return psk.ExtractPrivateKey(passphrase.ToCharArray()); } }
                            // Modo sensitivo
                            else { if (uid == search) { return psk.ExtractPrivateKey(passphrase.ToCharArray()); } }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si se ha marcado la baliza de ignorar mayusculas/minusculas
                        if (ignoreCase)
                        {
                            // Hace la comparativa en mayusculas
                            if (uid.ToUpper() == search.ToUpper()) { return psk.ExtractPrivateKey(passphrase.ToCharArray()); }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si el uid coincide con la busqueda
                        if (uid == search) { return psk.ExtractPrivateKey(passphrase.ToCharArray()); }
                    }
                }
            }

            // Retorna nulo
            return null;
        }

        /// <summary>
        /// Método que busca una clave secreta en el KeyRing
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>Nulo si no encuentra la clave secreta</returns>
        public PgpSecretKey? GetPgpSecretKey(string search, bool matchPartial = false, bool ignoreCase = false)
        {
            // Si el texto de busqueda ya viene como nulo, retorna nulo directamente
            if (search == null) { return null; }

            // Recupera todos los keyrings publicos en un array
            PgpSecretKeyRing[] secretKeyRings = SecretKeyRingBundle.GetKeyRings().Cast<PgpSecretKeyRing>().ToArray(); //SecretKeyRingBundle.GetKeyRings(search, matchPartial, ignoreCase).Cast<PgpSecretKeyRing>().ToArray();

            // Si recupera mas de un keyring
            // if (secretKeyRings.Length > 1) { throw new InvalidOperationException("Multiple posible results founded. Use GetPgpSecretKeys instead."); }

            // Recorre los anillos que contienen
            foreach (PgpSecretKeyRing pskr in secretKeyRings)
            {
                // Recorre las claves públicas del anillo
                foreach (PgpSecretKey psk in pskr.GetSecretKeys())
                {
                    // Si el fingerprint de la clave pública concuerda con el search
                    if (HashedFingerprint(psk, true) == search.ToUpper()) { return psk; }

                    // Recorre la lista de Ids del ppk
                    foreach (string uid in psk.UserIds)
                    {
                        // Si se ha marcado la baliza de emparejar parcialmente
                        if (matchPartial)
                        {
                            // Modo ignorativo
                            if (ignoreCase) { if (uid.ToUpper() == search.ToUpper()) { return psk; } }
                            // Modo sensitivo
                            else { if (uid == search) { return psk; } }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si se ha marcado la baliza de ignorar mayusculas/minusculas
                        if (ignoreCase)
                        {
                            // Hace la comparativa en mayusculas
                            if (uid.ToUpper() == search.ToUpper()) { return psk; }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si el uid coincide con la busqueda
                        if (uid == search) { return psk; }
                    }
                }
            }

            // Retorna nulo
            return null;
        }

        /// <summary>
        /// Método que busca una clave secreta en el KeyRing
        /// </summary>
        /// <param name="keyId">Id de la clave secreta que se desea obtener del keyring</param>
        /// <returns>Nulo si no encuentra la clave secreta</returns>
        public PgpSecretKey GetPgpSecretKey(long keyId)
        {
            // Retorna la busqueda
            return SecretKeyRingBundle.GetSecretKey(keyId);
        }
        
        /// <summary>
        /// Método que busca una clave secreta en el KeyRing
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>Nulo si no encuentra la clave secreta</returns>
        public PgpSecretKeyRing? GetPgpSecretKeyRing(string search, bool matchPartial = false, bool ignoreCase = false)
        {
            // Si el texto de busqueda ya viene como nulo, retorna nulo directamente
            if (search == null) { return null; }

            // Recupera todos los keyrings publicos en un array
            PgpSecretKeyRing[] secretKeyRings = SecretKeyRingBundle.GetKeyRings(search, matchPartial, ignoreCase).Cast<PgpSecretKeyRing>().ToArray();

            // Recorre los anillos que contienen
            foreach (PgpSecretKeyRing pskr in secretKeyRings)
            {
                // Recorre las claves públicas del anillo
                foreach (PgpSecretKey psk in pskr.GetSecretKeys())
                {
                    // Si el fingerprint de la clave pública concuerda con el search
                    if (HashedFingerprint(psk, true) == search.ToUpper()) { return pskr; }

                    // Recorre la lista de Ids del ppk
                    foreach (string uid in psk.UserIds)
                    {
                        // Si se ha marcado la baliza de emparejar parcialmente
                        if (matchPartial)
                        {
                            // Modo ignorativo
                            if (ignoreCase) { if (uid.ToUpper() == search.ToUpper()) { return pskr; } }
                            // Modo sensitivo
                            else { if (uid == search) { return pskr; } }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si se ha marcado la baliza de ignorar mayusculas/minusculas
                        if (ignoreCase)
                        {
                            // Hace la comparativa en mayusculas
                            if (uid.ToUpper() == search.ToUpper()) { return pskr; }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si el uid coincide con la busqueda
                        if (uid == search) { return pskr; }
                    }
                }
            }

            // Retorna nulo
            return null;
        }

        /// <summary>
        /// Método que busca un keyring secreto en el bundle desde key id
        /// </summary>
        /// <param name="keyid">Id de la llave a buscar</param>
        /// <returns>El PgpSecretKeyRing encontrado</returns>
        public PgpSecretKeyRing? GetPgpSecretKeyRing(long keyid)
        {
            // Retrona la busqueda del keyring en el bundle
            return SecretKeyRingBundle.GetSecretKeyRing(keyid);
        }

        /// <summary>
        /// Método que busca claves secretas en el KeyRing
        /// </summary>
        /// <param name="search">Cadena de búsqueda</param>
        /// <param name="matchPartial">True: Realizará búsquedas parciales en lugar de exactas</param>
        /// <param name="ignoreCase">True: Ignorará mayúsculas y minúsculas en la búsqueda</param>
        /// <returns>Nulo si no encuentra ninguna concidencia</returns>
        public PgpSecretKey[]? GetPgpSecretKeys(string search, bool matchPartial = false, bool ignoreCase = false, bool onlyMasterKeys = false)
        {
            // Si el texto de busqueda ya viene como nulo, retorna nulo directamente
            if (search == null) { return null; }

            // Instanciamos una lista de claves públicas a retornar
            List<PgpSecretKey> _return = new();

            // Recupera todos los keyrings publicos en un array
            PgpSecretKeyRing[] secretKeyRings = search.Length > 0 ? SecretKeyRingBundle.GetKeyRings(search, matchPartial, ignoreCase).Cast<PgpSecretKeyRing>().ToArray() : SecretKeyRingBundle.GetKeyRings().Cast<PgpSecretKeyRing>().ToArray();

            // Recorre los anillos que contienen
            foreach (PgpSecretKeyRing ppkr in secretKeyRings)
            {
                // Recorre las claves públicas del anillo
                foreach (PgpSecretKey psk in ppkr.GetSecretKeys())
                {
                    // Si se desea revisar solo claves maestras y la clave que se está iterando no es maestra, pasa de ciclo
                    if (onlyMasterKeys && !psk.IsMasterKey) { continue; }

                    // Si el search viene vacío, lo añade al output y pasa de ciclo
                    if (search.Length == 0) { _return.Add(psk); continue; }

                    // Si el fingerprint de la clave pública concuerda con el search
                    if (HashedFingerprint(psk, true) == search.ToUpper())
                    {
                        // Añade el public key a la lista
                        _return.Add(psk);

                        // Pasa de ciclo
                        continue;
                    }

                    // Recorre la lista de Ids del ppk
                    foreach (string uid in psk.UserIds)
                    {
                        // Si se ha marcado la baliza de emparejar parcialmente
                        if (matchPartial)
                        {
                            // Modo ignorativo
                            if (ignoreCase) { if (uid.ToUpper() == search.ToUpper()) { _return.Add(psk); } }
                            // Modo sensitivo
                            else { if (uid == search) { _return.Add(psk); } }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si se ha marcado la baliza de ignorar mayusculas/minusculas
                        if (ignoreCase)
                        {
                            // Hace la comparativa en mayusculas
                            if (uid.ToUpper() == search.ToUpper()) { _return.Add(psk); }

                            // Pasa de ciclo
                            continue;
                        }

                        // Si el uid coincide con la busqueda
                        if (uid == search) { _return.Add(psk); }
                    }
                }
            }

            // Retorna el array de retorno o nulo si precede
            return _return.ToArray();
        }

        /// <summary>
        /// Método que genera una nueva pareja de claves y las añade al keyring
        /// </summary>
        /// <param name="identity">Identificador de la clave maestra</param>
        /// <param name="passphrase">Contraseña de la clave maestra</param>
        /// <param name="secretKeyEncryptionAlgorithm">Algoritmo de encriptación simétrica que usará esta clave</param>
        /// <param name="symmetricalAlgorithmDirective">Algoritmos de encriptación simétrica que tolerará esta clave</param>
        /// <param name="hashAlgorithmDirective">Algoritmos de hash que tolerará esta clave</param>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de encriptación asimétrica que usará esta clave</param>
        /// <param name="rsaStrengthPriority">Solidez de la encriptación de la clave. Usa las opciones de <see cref="RsaStrengthPriority"/> como consideres.</param>
        /// <returns>Identificador de la clave maestra generada</returns>
        public long GenerateMasterKeyPair(
            string identity
            , string passphrase
            , int pubkey_flags = PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign
            , SymmetricKeyAlgorithmTag secretKeyEncryptionAlgorithm = SymmetricKeyAlgorithmTag.Aes256
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Valida el passphrase
            Passphrase.Validate(passphrase.ToCharArray());

            // Se instancia un generador de claves
            PgpKeyRingGenerator generator = CreateKeyRingGenerator(identity, passphrase, pubkey_flags, secretKeyEncryptionAlgorithm, symmetricalAlgorithmDirective, hashAlgorithmDirective, asymmetricalEncryptionAlgorithm, rsaStrengthPriority);

            // Genera una llave pública basada en el generador de claves y lo añade al KeyRing público
            InsertPublicKeyRing(generator.GeneratePublicKeyRing());

            // Genera una llave secreta basada en el generador de claves y lo añade al KeyRing secreta
            InsertSecretKeyRing(generator.GenerateSecretKeyRing());

            // Retorna el id de la clave maestra generada
            return generator.GeneratePublicKeyRing().GetPublicKey().KeyId;
        }

        /// <summary>
        /// Método estático que genera un nuevo keyring público y secreto sin necesedidad de instancia
        /// </summary>
        /// <param name="identity">Identificador de la clave maestra</param>
        /// <param name="passphrase">Contraseña de la clave maestra</param>
        /// <param name="secretKeyEncryptionAlgorithm">Algoritmo de encriptación simétrica que usará esta clave</param>
        /// <param name="symmetricalAlgorithmDirective">Algoritmos de encriptación simétrica que tolerará esta clave</param>
        /// <param name="hashAlgorithmDirective">Algoritmos de hash que tolerará esta clave</param>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de encriptación asimétrica que usará esta clave</param>
        /// <param name="rsaStrengthPriority">Solidez de la encriptación de la clave. Usa las opciones de <see cref="RsaStrengthPriority"/> como consideres.</param>
        /// <returns>Identificador de la clave maestra generada</returns>
        public static (PgpSecretKeyRing pskr, PgpPublicKeyRing ppkr) GeneratePgpMasterKeyRings(
            string identity
            , string passphrase
            , PublicKeyAlgorithmTag pubkeyAlgorithm = PublicKeyAlgorithmTag.RsaSign
            , int pubkey_flags = PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign
            , SymmetricKeyAlgorithmTag secretKeyEncryptionAlgorithm = SymmetricKeyAlgorithmTag.Aes256
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Valida el passphrase
            Passphrase.Validate(passphrase.ToCharArray());


            // Resetea el contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Generamos una pareja de claves
            AsymmetricCipherKeyPair ackp = DoGenerateAsymmetricalKeyPair(asymmetricalEncryptionAlgorithm, rsaStrengthPriority);

            // Se instancia un generador de claves
            PgpKeyRingGenerator generator = DoCreateKeyRingGenerator(ackp, identity, passphrase, pubkeyAlgorithm, pubkey_flags, secretKeyEncryptionAlgorithm, symmetricalAlgorithmDirective, hashAlgorithmDirective, rsaStrengthPriority);

            // Generamos los keyrings
            PgpSecretKeyRing pskr = generator.GenerateSecretKeyRing();
            PgpPublicKeyRing ppkr = generator.GeneratePublicKeyRing();

            // Mensaje de debug
            Debug.WriteLine(string.Format("Generated master key '{0}' identified as '{3}' with Fingerprint: '{1}' in {2}", ppkr.GetPublicKey().KeyId.ToString("X"), HashedFingerprint(ppkr.GetPublicKey(), uppercase: true), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds, true), identity), "Information");

            // Retorna el id de la clave maestra generada
            return (pskr, ppkr);
        }

        /// <summary>
        /// Método estático que genera un nuevo keyring público y secreto y la pareja de claves asímetricas por separado sin necesedidad de instancia
        /// </summary>
        /// <param name="identity">Identificador de la clave maestra</param>
        /// <param name="passphrase">Contraseña de la clave maestra</param>
        /// <param name="pubkey_flags">Flags de característas de la clave <see cref="PgpKeyFlags"/></param>
        /// <param name="secretKeyEncryptionAlgorithm">Algoritmo de encriptación simétrica que usará esta clave</param>
        /// <param name="symmetricalAlgorithmDirective">Algoritmos de encriptación simétrica que tolerará esta clave</param>
        /// <param name="hashAlgorithmDirective">Algoritmos de hash que tolerará esta clave</param>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de encriptación asimétrica que usará esta clave</param>
        /// <param name="rsaStrengthPriority">Solidez de la encriptación de la clave. Usa las opciones de <see cref="RsaStrengthPriority"/> como consideres.</param>
        /// <returns>Identificador de la clave maestra generada</returns>
        public static (PgpSecretKeyRing secretKeyRing, PgpPublicKeyRing publcKeyRing, AsymmetricCipherKeyPair keyPair) GeneratePgpMasterKeyRingsComposed(
            string identity
            , string passphrase
            , PublicKeyAlgorithmTag pubkeyAlgorithm = PublicKeyAlgorithmTag.RsaSign
            , int pubkey_flags = PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign
            , SymmetricKeyAlgorithmTag secretKeyEncryptionAlgorithm = SymmetricKeyAlgorithmTag.Aes256
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Valida el passphrase
            Passphrase.Validate(passphrase.ToCharArray());

            // Resetea el contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Generamos una pareja de claves
            AsymmetricCipherKeyPair ackp = DoGenerateAsymmetricalKeyPair(asymmetricalEncryptionAlgorithm, rsaStrengthPriority);

            // Se instancia un generador de claves
            PgpKeyRingGenerator generator = DoCreateKeyRingGenerator(ackp, identity, passphrase, pubkeyAlgorithm, pubkey_flags, secretKeyEncryptionAlgorithm, symmetricalAlgorithmDirective, hashAlgorithmDirective, rsaStrengthPriority);

            // Generamos los keyrings
            PgpSecretKeyRing pskr = generator.GenerateSecretKeyRing();
            PgpPublicKeyRing ppkr = generator.GeneratePublicKeyRing();

            // Mensaje de debug
            Debug.WriteLine(string.Format("Generated master key '{0}' identified as '{3}' with Fingerprint: '{1}' in {2}", ppkr.GetPublicKey().KeyId.ToString("X"), HashedFingerprint(ppkr.GetPublicKey(), uppercase: true), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds, true), identity), "Information");

            // Retorna el id de la clave maestra generada
            return (pskr, ppkr, ackp);
        }

        public static void Test()
        {
            PgpContext context = PgpContext.Make(mode: PgpContext.PgpContextMode.Persistent, dumpFrequency: PgpContext.PgpKeyRingDumpFrequency.Inmediately, path: Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Tantra Online Classic\\User Keyrings\\"));
            byte[] jandulila = Encoding.UTF8.GetBytes("Me toca las pelotas");

            PgpSecretKey pSec = context.GetPgpSecretKey("joseantonio.lopeznavarro93@gmail.com");

            Stream signature = context.NewDoSign(jandulila, pSec, [.. "Noelia.2021.$"], false);
            signature.Seek(0, SeekOrigin.Begin);

            MemoryStream signatureBytes = new((int)signature.Length);
            signature.CopyTo(signatureBytes);
            signatureBytes.Seek(0, SeekOrigin.Begin);
            bool verify = context.NewDoVerify(pSec.PublicKey, jandulila, signatureBytes.ToArray());
            string ano = string.Empty;

            /*
            AsymmetricCipherKeyPair ackp = GenerateAsymmetricalKeyPair(AsymmetricalEncryptionAlgorithms.RSA, RsaStrengthPriority.Balanced);


            byte[] textoJandulilo = Encoding.UTF8.GetBytes("ajandulilila, ajandulila chikram chikram");
            byte[] contrasenia = Encoding.UTF8.GetBytes("NoMelaPILLASijueputa2030");

            byte[] uf128 = SymmetricalCiphers.Encrypt(textoJandulilo, contrasenia, SymmetricalCiphers.KeyLength._128, SymmetricalCiphers.AvailableAlgorithms.AESCTRPkcs7Padding);
            byte[] uf192 = SymmetricalCiphers.Encrypt(textoJandulilo, contrasenia, SymmetricalCiphers.KeyLength._192, SymmetricalCiphers.AvailableAlgorithms.AESGCMNoPadding);
            byte[] uf256 = SymmetricalCiphers.Encrypt(textoJandulilo, contrasenia, SymmetricalCiphers.KeyLength._256, SymmetricalCiphers.AvailableAlgorithms.AESGCMNoPadding);


            byte[] dec128 = SymmetricalCiphers.Decrypt(uf128, contrasenia);
            byte[] dec192 = SymmetricalCiphers.Decrypt(uf192, contrasenia);
            byte[] dec256 = SymmetricalCiphers.Decrypt(uf256, contrasenia);


            PgpContext ncpgp = Make(mode: PgpContextMode.Persistent, dumpFrequency: PgpKeyRingDumpFrequency.Inmediately, name: "Testeando");

            SetPassphrasePatternSolidity(Passphrase.PatternSolidity.PriorizeNonPattern);
            SetPassphraseLengthSolidity(Passphrase.LengthSolidity.Secure);
            SetPassphraseLengthSolidity(Passphrase.LengthSolidity.Extreme, true);
            SetPassprhaseCharacterSolidity(Passphrase.CharSolidity.AlphanumericWithSpecialChars);
            SetPassprhaseCharacterSolidity(Passphrase.CharSolidity.AlphanumericWithSpecialChars, true);

            string pasfrase = "2906.Noelia.&.2021";
            string pasfrase2 = "&.furby.Anuar@2020";
            
            long furby = ncpgp.GenerateMasterKeyPair("Jandulila", pasfrase, secretKeyEncryptionAlgorithm: SymmetricKeyAlgorithmTag.Aes256, symmetricalAlgorithmDirective: SymmetricalAlgorithmSeverityDirectives.Secure, hashAlgorithmDirective: HashAlgorithmSeverityDirectives.Maximum, rsaStrengthPriority: RsaStrengthPriority.Security);

            long strongest = ncpgp.AddSubKey(furby
                , PublicKeyAlgorithmTag.RsaGeneral
                , PgpKeyFlags.CanSign | PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage
                , "Fuerte"
                , pasfrase
                , DateTime.Now.AddYears(5)
                , SymmetricalAlgorithmSeverityDirectives.Secure
                , HashAlgorithmSeverityDirectives.Maximum
                , AsymmetricalEncryptionAlgorithms.RSA
                , RsaStrengthPriority.Security);

            long choni = ncpgp.GenerateMasterKeyPair("La Choni", pasfrase2, secretKeyEncryptionAlgorithm: SymmetricKeyAlgorithmTag.Aes256, symmetricalAlgorithmDirective: SymmetricalAlgorithmSeverityDirectives.Secure, hashAlgorithmDirective: HashAlgorithmSeverityDirectives.Maximum, rsaStrengthPriority: RsaStrengthPriority.Security);

            long coca = ncpgp.AddSubKey(choni
                , PublicKeyAlgorithmTag.RsaGeneral
                , PgpKeyFlags.CanSign | PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage
                , "Cocaina de la choni"
                , pasfrase2
                , DateTime.Now.AddYears(5)
                , SymmetricalAlgorithmSeverityDirectives.Secure
                , HashAlgorithmSeverityDirectives.Maximum
                , AsymmetricalEncryptionAlgorithms.RSA
                , RsaStrengthPriority.Security);

            
            PgpPublicKey ppks = ncpgp.GetPgpPublicKey("C53E56E83E986E1E87A6CAC737B7CDB1214237F5");
            PgpSecretKey pskb = ncpgp.GetPgpSecretKey(8723149854165089254);// "7B2D75C5E8B430DD369A561B06E09F5E28125A74");
            PgpPublicKey ppkb = ncpgp.GetPgpPublicKey(8723149854165089254);// "7B2D75C5E8B430DD369A561B06E09F5E28125A74");

            FileStream fsr = new(@"C:\Users\josea\OneDrive\Escritorio\Gatete.jpg", FileMode.Open);

            MemoryStream ms = new();
            fsr.CopyTo(ms);

            Random rnd = new();
            byte[] b = new byte[256];
            rnd.NextBytes(b);

            // byte[] sig = ncpgp.Sign(pskb, pasfrase2.ToCharArray(), b, HashAlgorithmTag.Sha512);// b);

            // bool ver = ncpgp.Verify(ppkb, b, sig, HashAlgorithmTag.Sha512);

            byte[] sigNenc = ncpgp.SignAndEncryptFile(b, new PgpPublicKey[] { ppks }, pskb, pasfrase2.ToCharArray(), true, false, CompressionAlgorithmTag.Uncompressed);

            //byte[] data = ncpgp.EncryptToArray(ms.ToArray(), new PgpPublicKey[] { ppks, ppkb }, true, false, CompressionAlgorithmTag.Uncompressed);
            // byte[] data = ncpgp.EncryptToArray(fsr, new PgpPublicKey[] { ppks, ppkb }, true, false, CompressionAlgorithmTag.Uncompressed);
            //byte[] data = ncpgp.EncryptToArray(b, new PgpPublicKey[] { ppks, ppkb }, true, false, CompressionAlgorithmTag.Uncompressed);
            // byte[] data = ncpgp.EncryptToArray(b, ppks, true, false, CompressionAlgorithmTag.Uncompressed);
            // byte[] sigData = ncpgp.Sign(pskb, pasfrase2.ToCharArray(), data, HashAlgorithmTag.Sha512);
            // bool verData = ncpgp.Verify(ppkb, data, sigData, HashAlgorithmTag.Sha512);
            // byte[] dataDecrypt = ncpgp.DecryptToArray(data, pasfrase);


            byte[] ano = ncpgp.EncryptAndSign(b, new PgpPublicKey[] { ppks }, pskb, pasfrase2.ToCharArray(), true, false, CompressionAlgorithmTag.Uncompressed, HashAlgorithmTag.Sha512);
            ano[0] = 2;
            var fulano = ncpgp.VerifyAndDecrypt(ano, pasfrase);
            //byte[] data = ncpgp.Encrypt(ano, ppks, true, false, CompressionAlgorithmTag.Uncompressed);
            //byte[] datab = ncpgp.Encrypt(ms.ToArray(), ppkb, true, false, CompressionAlgorithmTag.Uncompressed);
            //byte[] datah = ncpgp.Encrypt(ms.ToArray(), ppkh, true, false, CompressionAlgorithmTag.Uncompressed);

            // FileStream fsw = new(@"C:\Users\josea\OneDrive\Escritorio\Gatete.crypted", FileMode.Create);

            // fsw.Write(data, 0, data.Length);
            // ncpgp.Encrypt(fsr, new PgpPublicKey[] { ppks, ppkb }, true, false, CompressionAlgorithmTag.Uncompressed).CopyTo(fsw);
            // fsw.Close();

            //FileStream fsrd = new(@"C:\Users\josea\OneDrive\Escritorio\Gatete.crypted", FileMode.Open);
            // FileStream fswd = new(@"C:\Users\josea\OneDrive\Escritorio\Gatete.jandulila.jpg", FileMode.Create);

            // fswd.Write(dataDecrypt, 0, dataDecrypt.Length);
            //ncpgp.Decrypt(fsrd, pasfrase).CopyTo(fswd);
            // fswd.Close();

            
            dataDecrypt = ncpgp.DecryptToArray(data, pasfrase2);

            FileStream fswd2 = new(@"C:\Users\josea\OneDrive\Escritorio\Gatete.choni.jpg", FileMode.Create);

            fswd2.Write(dataDecrypt, 0, dataDecrypt.Length);
            fswd2.Close();

            return;
            PgpKeyRingGenerator low = CreateKeyRingGenerator("Furby anonimo", "jandulila", rsaStrengthPriority: RsaStrengthPriority.Speed);

            PgpPublicKeyRing pkrLow = low.GeneratePublicKeyRing();
            PgpSecretKeyRing skrLow = low.GenerateSecretKeyRing();
            
            // InsertPublicKey(pkrLow);

            PgpKeyRingGenerator low2 = CreateKeyRingGenerator("Furby anonimo 2", "jandulila2", rsaStrengthPriority: RsaStrengthPriority.Speed);

            PgpPublicKeyRing pkrLow2 = low2.GeneratePublicKeyRing();
            PgpSecretKeyRing skrLow2 = low2.GenerateSecretKeyRing();

            PgpKeyRingGenerator medium = CreateKeyRingGenerator("Furby anonimo", "jandulila", rsaStrengthPriority: RsaStrengthPriority.Balanced);

            PgpPublicKeyRing pkrMedium = medium.GeneratePublicKeyRing();
            PgpSecretKeyRing skrMedium = medium.GenerateSecretKeyRing();
            

            // PgpKeyRingGenerator strong = CreateKeyRingGenerator("Ano fuerte", "chicheida", rsaStrengthPriority: RsaStrengthPriority.Security);

            // PgpPublicKeyRing pkrStrong = strong.GeneratePublicKeyRing();
            // PgpSecretKeyRing skrStrong = strong.GenerateSecretKeyRing();

            MemoryStream ms = new(8192);
            pkrLow.Encode(ms);
            pkrLow2.Encode(ms);
            pkrMedium.Encode(ms);
            // pkrStrong.Encode(ms);
            ms.Seek(0, SeekOrigin.Begin);
            PgpPublicKeyRingBundle s = new(ms);
            */
        }


        /// <summary>
        /// Método que devuelve el hash del identificador de una pareja de claves PGP 
        /// </summary>
        /// <param name="key">Llave PGP de la que se desea recuperar el identificador hash</param>
        /// <param name="hash">Algoritmo de hashing con el que se desea exportar el identificador de la llave</param>
        /// <param name="uppercase">True: Retornará el fingerprint en mayúsculas, False: retornará el fingerprint en minúsculas</param>
        /// <returns></returns>
        public static string HashedIdentifier(PgpKeyPair keyPair, HashAlgorithms hash = HashAlgorithms.SHA256, bool uppercase = false)
        {
            // Referenciamos un algoritmo de Hashing
            HashAlgorithm hasher;

            // Se hace un switch para determinar que algoritmo usar según el argumento 'hash'
            switch (hash)
            {
                default: hasher = SHA256.Create(); break;
                case HashAlgorithms.MD5: hasher = MD5.Create(); break;
                case HashAlgorithms.SHA1: hasher = SHA1.Create(); break;
                case HashAlgorithms.SHA384: hasher = SHA384.Create(); break;
                case HashAlgorithms.SHA512: hasher = SHA512.Create(); break;
            }

            // Instanciamos un StringBuilder para concatenar los bytes obtenidos del hash computado
            StringBuilder builder = new();

            // Monta un string concatenando cada byte del hash obtenido
            foreach(byte b in hasher.ComputeHash(BitConverter.GetBytes(keyPair.KeyId)))
            {
                // Concatena el byte en Hexadecimal de 2 dígitos al string de salida
                builder.Append(b.ToString("x2"));
            }

            // Retorna el string montado
            return !uppercase ? builder.ToString() : builder.ToString().ToUpper();
        }

        /// <summary>
        /// Método que devuelve el hash del identificador de una clave pública PGP 
        /// </summary>
        /// <param name="key">Llave PGP de la que se desea recuperar el identificador hash</param>
        /// <param name="hash">Algoritmo de hashing con el que se desea exportar el identificador de la llave</param>
        /// <param name="uppercase">True: Retornará el fingerprint en mayúsculas, False: retornará el fingerprint en minúsculas</param>
        /// <returns></returns>
        public static string HashedIdentifier(PgpPublicKey key, HashAlgorithms hash = HashAlgorithms.SHA256, bool uppercase = false)
        {
            // Referenciamos un algoritmo de Hashing
            HashAlgorithm hasher;

            // Se hace un switch para determinar que algoritmo usar según el argumento 'hash'
            switch (hash)
            {
                default: hasher = SHA256.Create(); break;
                case HashAlgorithms.MD5: hasher = MD5.Create(); break;
                case HashAlgorithms.SHA1: hasher = SHA1.Create(); break;
                case HashAlgorithms.SHA384: hasher = SHA384.Create(); break;
                case HashAlgorithms.SHA512: hasher = SHA512.Create(); break;
            }

            // Instanciamos un StringBuilder para concatenar los bytes obtenidos del hash computado
            StringBuilder builder = new();

            // Monta un string concatenando cada byte del hash obtenido
            foreach (byte b in hasher.ComputeHash(BitConverter.GetBytes(key.KeyId)))
            {
                // Concatena el byte en Hexadecimal de 2 dígitos al string de salida
                builder.Append(b.ToString("x2"));
            }

            // Retorna el string montado
            return !uppercase ? builder.ToString() : builder.ToString().ToUpper();
        }

        /// <summary>
        /// Método que devuelve el hash del identificador de una clave privada PGP 
        /// </summary>
        /// <param name="key">Llave PGP de la que se desea recuperar el identificador hash</param>
        /// <param name="hash">Algoritmo de hashing con el que se desea exportar el identificador de la llave</param>
        /// <param name="uppercase">True: Retornará el fingerprint en mayúsculas, False: retornará el fingerprint en minúsculas</param>
        /// <returns></returns>
        public static string HashedIdentifier(PgpSecretKey key, HashAlgorithms hash = HashAlgorithms.SHA256, bool uppercase = false)
        {
            // Referenciamos un algoritmo de Hashing
            HashAlgorithm hasher;

            // Se hace un switch para determinar que algoritmo usar según el argumento 'hash'
            switch (hash)
            {
                default: hasher = SHA256.Create(); break;
                case HashAlgorithms.MD5: hasher = MD5.Create(); break;
                case HashAlgorithms.SHA1: hasher = SHA1.Create(); break;
                case HashAlgorithms.SHA384: hasher = SHA384.Create(); break;
                case HashAlgorithms.SHA512: hasher = SHA512.Create(); break;
            }

            // Instanciamos un StringBuilder para concatenar los bytes obtenidos del hash computado
            StringBuilder builder = new();

            // Monta un string concatenando cada byte del hash obtenido
            foreach (byte b in hasher.ComputeHash(BitConverter.GetBytes(key.KeyId)))
            {
                // Concatena el byte en Hexadecimal de 2 dígitos al string de salida
                builder.Append(b.ToString("x2"));
            }

            // Retorna el string montado
            return !uppercase ? builder.ToString() : builder.ToString().ToUpper();
        }

        /// <summary>
        /// Método que devuelve el fingerprint de una pareja de claves PGP en formato string
        /// </summary>
        /// <param name="key">Clave pública de la que se desea extraer el fingerprint</param>
        /// <param name="uppercase">True: Retornará el fingerprint en mayúsculas, False: retornará el fingerprint en minúsculas</param>
        /// <returns></returns>
        public static string HashedFingerprint(PgpKeyPair keyPair, bool uppercase = false)
        {
            // Instanciamos un StringBuilder para concatenar los bytes del Fingerprint
            StringBuilder sb = new();

            // Recupera el fingerprint de la clave pública
            foreach (byte b in keyPair.PublicKey.GetFingerprint())
            {
                // Concatena cada byte como hexadecimal de dos dígitos
                sb.Append(b.ToString("x2"));
            }

            // Retorna el string montado
            return !uppercase ? sb.ToString() : sb.ToString().ToUpper();
        }

        /// <summary>
        /// Método que devuelve el fingerprint de una clave pública PGP en formato string
        /// </summary>
        /// <param name="key">Llave pública de la que se desea extraer el fingerprint</param>
        /// <param name="uppercase">True: Retornará el fingerprint en mayúsculas, False: retornará el fingerprint en minúsculas</param>
        /// <returns></returns>
        public static string HashedFingerprint(PgpPublicKey key, bool uppercase = false)
        {
            // Instanciamos un StringBuilder para concatenar los bytes del Fingerprint
            StringBuilder sb = new();

            // Recupera el fingerprint de la clave pública
            foreach (byte b in key.GetFingerprint())
            {
                // Concatena cada byte como hexadecimal de dos dígitos
                sb.Append(b.ToString("x2"));
            }

            // Retorna el string montado
            return !uppercase ? sb.ToString() : sb.ToString().ToUpper();
        }

        /// <summary>
        /// Método que devuelve el fingerprint de una clave secreta PGP en formato string
        /// </summary>
        /// <param name="key">Clave secreta de la que se desea extraer el fingerprint</param>
        /// <param name="uppercase">True: Retornará el fingerprint en mayúsculas, False: retornará el fingerprint en minúsculas</param>
        /// <returns></returns>
        public static string HashedFingerprint(PgpSecretKey key, bool uppercase = false)
        {
            // Instanciamos un StringBuilder para concatenar los bytes del Fingerprint
            StringBuilder sb = new();

            // Recupera el fingerprint de la clave pública
            foreach (byte b in key.PublicKey.GetFingerprint())
            {
                // Concatena cada byte como hexadecimal de dos dígitos
                sb.Append(b.ToString("x2"));
            }

            // Retorna el string montado
            return !uppercase ? sb.ToString() : sb.ToString().ToUpper();
        }

        /// <summary>
        /// Método que convierte un SymmetricalAlgorithmSeverityDirectives en un array de Algoritmos de encriptación simétrica
        /// </summary>
        /// <param name="directive">Directiva que se desea aplicar</param>
        /// <returns>SymmetricKeyAlgorithmTag[]</returns>
        protected static SymmetricKeyAlgorithmTag[] ParseSeverityDirectiveInSymetricalAlgorithmTagArray(SymmetricalAlgorithmSeverityDirectives directive)
        {
            // Se hace un switch de la directiva para determinar los SymmetricalKeyAlgorithmTag que se deben añadir al array de retorno
            switch (directive)
            {
                // Salida por defecto (Modo compatibilidad)
                default:
                    return new SymmetricKeyAlgorithmTag[] {
                        SymmetricKeyAlgorithmTag.Aes256,
                        SymmetricKeyAlgorithmTag.Aes192,
                        SymmetricKeyAlgorithmTag.Aes128
                    };
                
                // Salida para grado medio de seguridad
                case SymmetricalAlgorithmSeverityDirectives.Medium:
                    return new SymmetricKeyAlgorithmTag[] {
                        SymmetricKeyAlgorithmTag.Aes256,
                        SymmetricKeyAlgorithmTag.Aes192
                    };

                // Salida para grado seguro
                case SymmetricalAlgorithmSeverityDirectives.Secure:
                    return new SymmetricKeyAlgorithmTag[] {
                        SymmetricKeyAlgorithmTag.Aes256
                    };
            }
        }

        /// <summary>
        /// Método que convierte un SymmetricalAlgorithmSeverityDirectives en un array de Algoritmos de encriptación simétrica
        /// </summary>
        /// <param name="directive">Directiva que se desea aplicar</param>
        /// <returns>SymmetricKeyAlgorithmTag[]</returns>
        protected static int[] ParseSeverityDirectivesInIntArray(SymmetricalAlgorithmSeverityDirectives directive)
        {
            // Se hace un switch de la directiva para determinar los SymmetricalKeyAlgorithmTag que se deben añadir al array de retorno
            return (from a in ParseSeverityDirectiveInSymetricalAlgorithmTagArray(directive)
                    select (int)a).ToArray();
        }

        /// <summary>
        /// Método que convierte un HashAlgorithmSeverityDirectives en un array de Algoritmos de encriptación simétrica
        /// </summary>
        /// <param name="directive">Directiva que se desea aplicar</param>
        /// <returns>HashAlgorithmTag[]</returns>
        protected static HashAlgorithmTag[] ParseSeverityDirectiveInHashAlgorithmTagArray(HashAlgorithmSeverityDirectives directive)
        {
            // Se hace un switch de la directiva para determinar los HashAlgorithmTag que se deben añadir al array de retorno
            switch (directive)
            {
                // Salida por defecto (Modo compatibilidad)
                default:
                    return new HashAlgorithmTag[] {
                        HashAlgorithmTag.MD5,
                        HashAlgorithmTag.Sha1,
                        HashAlgorithmTag.Sha224,
                        HashAlgorithmTag.Sha256,
                        HashAlgorithmTag.Sha384,
                        HashAlgorithmTag.Sha512,
                    };

                // Salida para grado mínimo de seguridad
                case HashAlgorithmSeverityDirectives.Minimal:
                    return new HashAlgorithmTag[] {
                        HashAlgorithmTag.MD5,
                        HashAlgorithmTag.Sha1
                    };

                // Salida para grado medio de seguridad
                case HashAlgorithmSeverityDirectives.Medium:
                    return new HashAlgorithmTag[] {
                        HashAlgorithmTag.Sha1,
                        HashAlgorithmTag.Sha224,
                        HashAlgorithmTag.Sha256,
                    };

                // Salida para grado seguro de seguridad
                case HashAlgorithmSeverityDirectives.Secure:
                    return new HashAlgorithmTag[] {
                        HashAlgorithmTag.Sha256,
                        HashAlgorithmTag.Sha384,
                        HashAlgorithmTag.Sha512
                    };

                // Salida para grado maximo de seguridad
                case HashAlgorithmSeverityDirectives.Maximum:
                    return new HashAlgorithmTag[] {
                        HashAlgorithmTag.Sha512
                    };
            }
        }

        /// <summary>
        /// Método que convierte un SymmetricalAlgorithmSeverityDirectives en un array de Algoritmos de encriptación simétrica
        /// </summary>
        /// <param name="directive">Directiva que se desea aplicar</param>
        /// <returns>SymmetricKeyAlgorithmTag[]</returns>
        protected static int[] ParseSeverityDirectivesInIntArray(HashAlgorithmSeverityDirectives directive)
        {
            // Se hace un switch de la directiva para determinar los SymmetricalKeyAlgorithmTag que se deben añadir al array de retorno
            return (from a in ParseSeverityDirectiveInHashAlgorithmTagArray(directive)
                    select (int)a).ToArray();
        }

        /// <summary>
        /// Método que convierte un HashAlgorithmSeverityDirectives en un array de Algoritmos de encriptación simétrica
        /// </summary>
        /// <param name="algorithm">Algoritmo de encriptación asimétrica a convertir</param>
        /// <returns></returns>
        public static string ParseAsymmetricalEncryptionAlgorithmInString(AsymmetricalEncryptionAlgorithms algorithm)
        {
            // Realiza un switch por algoritmo
            switch (algorithm)
            {
                // Salida por defecto
                default: return algorithm.ToString();

                // Salida por entrada RSASSA_PSS
                case AsymmetricalEncryptionAlgorithms.RSASSA_PSS: return "RSASSA-PSS";
            }
        }

        /// <summary>
        /// Método que devuelve una nueva instancia de un <see cref="Leviathan.Lib.NetCorePGP.PgpKeyRingGenerator"/> 
        /// </summary>
        /// <param name="identity">Proporciona datos de indentidad del propietario del KeyRing PGP que el PgpKeyRingGenerator pueda generar</param>
        /// <param name="password">Contraseña secreta que usará el propietario para firmar y encriptar el o los KeyRing PGP que el PgpKeyRingGenerator pueda generar</param>
        /// <param name="secretKeyEncryptionAlgorithm"></param>
        /// <param name="symmetricalAlgorithmDirective"></param>
        /// <param name="hashAlgorithmDirective"></param>
        /// <param name="asymmetricalEncryptionAlgorithm"></param>
        /// <returns></returns>
        private static PgpKeyRingGenerator CreateKeyRingGenerator(
            string identity
            , string passphrase
            , int pubkeyFlags = PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify
            , SymmetricKeyAlgorithmTag secretKeyEncryptionAlgorithm = SymmetricKeyAlgorithmTag.Aes256
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Invoca al método maestro y retorna el resultante
            return DoCreateKeyRingGenerator(DoGenerateAsymmetricalKeyPair(asymmetricalEncryptionAlgorithm, rsaStrengthPriority), identity, passphrase, pubkeyFlags: pubkeyFlags, secretKeyEncryptionAlgorithm: secretKeyEncryptionAlgorithm, symmetricalAlgorithmDirective: symmetricalAlgorithmDirective, hashAlgorithmDirective: hashAlgorithmDirective, rsaStrengthPriority: rsaStrengthPriority);

            /*
            // Instanciamos un KeyRingParams para configurar datos de cifrado y establecemos una referencia a la instancia en keyRingParams
            KeyRingParams keyRingParams = new(rsaStrengthPriority)
            {
                Password = passphrase,
                Identity = identity,
                PrivateKeyEncryptionAlgorithm = secretKeyEncryptionAlgorithm,
                SymmetricAlgorithms = ParseSeverityDirectiveInSymetricalAlgorithmTagArray(symmetricalAlgorithmDirective),
                HashAlgorithms = ParseSeverityDirectiveInHashAlgorithmTagArray(hashAlgorithmDirective)
            };

            // Resetea el contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Genera una llave maestra, con utilidad para firmar únicamente
            // Create the master (signing-only) key.
            PgpKeyPair masterKeyPair = new(
                PublicKeyAlgorithmTag.RsaSign,
                DoGenerateAsymmetricalKeyPair(asymmetricalEncryptionAlgorithm, rsaStrengthPriority),
                DateTime.UtcNow);

            // Mensaje de debug
            Debug.WriteLine(string.Format("Generated master key '{0}' identified as '{3}' and Fingerprint: '{1}' in {2}", masterKeyPair.KeyId.ToString("X"), HashedFingerprint(masterKeyPair, uppercase: true), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds, true), keyRingParams.Identity), "Information");

            // Instanciamos un PgpSignatureSubpacketGenerator
            PgpSignatureSubpacketGenerator masterSubpckGen = new();

            // Fija las utiliades del subkey de la llamve maestra
            masterSubpckGen.SetKeyFlags(false, pubkeyFlags);

            // Fija los algoritmos de encriptación simetrica preferida
            masterSubpckGen.SetPreferredSymmetricAlgorithms(false, ParseSeverityDirectivesInIntArray(symmetricalAlgorithmDirective));

            // Fija los algoritmos de hash prefereidos
            masterSubpckGen.SetPreferredHashAlgorithms(false, ParseSeverityDirectivesInIntArray(hashAlgorithmDirective));
            
            
            // Resetea el contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Instanciamos una llave de encriptación para uso general
            PgpKeyPair encKeyPair = new(
                PublicKeyAlgorithmTag.RsaGeneral,
                generator.GenerateKeyPair(),
                DateTime.UtcNow);

            // Mensaje de debug
            Debug.WriteLine(string.Format("Generated encryption key with ID: '{0}' and Fingerprint: '{1}' in {2}", encKeyPair.KeyId.ToString("X"), HashedFingerprint(encKeyPair, uppercase: true), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Seconds, true)), "Information");
            
            // Instanciamos un PgpSignatureSubpacketGenerator
            PgpSignatureSubpacketGenerator encSubpckGen = new();

            // Fijamos las utilidades del certificado
            encSubpckGen.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);

            // Fija los algoritmos de encriptación simetrica preferida
            encSubpckGen.SetPreferredSymmetricAlgorithms(false, ParseSeverityDirectivesInIntArray(symmetricalAlgorithmDirective));

            // Fija los algoritmos de hash prefereidos
            encSubpckGen.SetPreferredHashAlgorithms(false, ParseSeverityDirectivesInIntArray(hashAlgorithmDirective));
            

            // Instancia un PgpKeyRingGenerator
            // Create the key ring.
            PgpKeyRingGenerator keyRingGen = new(
                PgpSignature.DefaultCertification,
                masterKeyPair,
                keyRingParams.Identity,
                keyRingParams.PrivateKeyEncryptionAlgorithm.Value,
                keyRingParams.HashAlgorithms.Last(),
                keyRingParams.GetPassword(),
                hashAlgorithmDirective == HashAlgorithmSeverityDirectives.Compatibility || hashAlgorithmDirective == HashAlgorithmSeverityDirectives.Minimal,
                masterSubpckGen.Generate(),
                null,
                new SecureRandom());

            // Añade la llave de encriptación al KeyRing
            // Add encryption subkey.
            // keyRingGen.AddSubKey(encKeyPair, encSubpckGen.Generate(), null);

            // Retorna la referencia del KeyRing
            return keyRingGen; */
        }

        /// <summary>
        /// Método maestro que devuelve una nueva instancia de un <see cref="Leviathan.Lib.NetCorePGP.PgpKeyRingGenerator"/> 
        /// </summary>
        /// <param name="keyPair">Pareja de claves de encriptación asimétrica del keyring PGP</param>
        /// <param name="identity">Proporciona datos de indentidad del propietario del KeyRing PGP que el PgpKeyRingGenerator pueda generar</param>
        /// <param name="password">Contraseña secreta que usará el propietario para firmar y encriptar el o los KeyRing PGP que el PgpKeyRingGenerator pueda generar</param>
        /// <param name="secretKeyEncryptionAlgorithm"></param>
        /// <param name="symmetricalAlgorithmDirective"></param>
        /// <param name="hashAlgorithmDirective"></param>
        /// <returns></returns>
        private static PgpKeyRingGenerator DoCreateKeyRingGenerator(
            AsymmetricCipherKeyPair keyPair
            , string identity
            , string passphrase
            , PublicKeyAlgorithmTag pubkeyAlgorithm = PublicKeyAlgorithmTag.RsaSign
            , int pubkeyFlags = PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify
            , SymmetricKeyAlgorithmTag secretKeyEncryptionAlgorithm = SymmetricKeyAlgorithmTag.Aes256
            , SymmetricalAlgorithmSeverityDirectives symmetricalAlgorithmDirective = SymmetricalAlgorithmSeverityDirectives.Compatibility
            , HashAlgorithmSeverityDirectives hashAlgorithmDirective = HashAlgorithmSeverityDirectives.Compatibility
            , RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Instanciamos un KeyRingParams para configurar datos de cifrado y establecemos una referencia a la instancia en keyRingParams
            KeyRingParams keyRingParams = new(rsaStrengthPriority)
            {
                Password = passphrase,
                Identity = identity,
                PrivateKeyEncryptionAlgorithm = secretKeyEncryptionAlgorithm,
                SymmetricAlgorithms = ParseSeverityDirectiveInSymetricalAlgorithmTagArray(symmetricalAlgorithmDirective),
                HashAlgorithms = ParseSeverityDirectiveInHashAlgorithmTagArray(hashAlgorithmDirective)
            };

            // Genera una llave maestra, con utilidad para firmar únicamente
            /* Create the master (signing-only) key. */
            PgpKeyPair masterKeyPair = new(
                pubkeyAlgorithm,
                keyPair,
                DateTime.UtcNow);

            // Instanciamos un PgpSignatureSubpacketGenerator
            PgpSignatureSubpacketGenerator masterSubpckGen = new();

            // Fija las utiliades del subkey de la llamve maestra
            masterSubpckGen.SetKeyFlags(false, pubkeyFlags);

            // Fija los algoritmos de encriptación simetrica preferida
            masterSubpckGen.SetPreferredSymmetricAlgorithms(false, ParseSeverityDirectivesInIntArray(symmetricalAlgorithmDirective));

            // Fija los algoritmos de hash prefereidos
            masterSubpckGen.SetPreferredHashAlgorithms(false, ParseSeverityDirectivesInIntArray(hashAlgorithmDirective));

            // Instancia un PgpKeyRingGenerator
            /* Create the key ring. */
            PgpKeyRingGenerator keyRingGen = new(
                PgpSignature.DefaultCertification,
                masterKeyPair,
                keyRingParams.Identity,
                keyRingParams.PrivateKeyEncryptionAlgorithm.Value,
                keyRingParams.HashAlgorithms.Last(),
                keyRingParams.GetPassword(),
                hashAlgorithmDirective == HashAlgorithmSeverityDirectives.Compatibility || hashAlgorithmDirective == HashAlgorithmSeverityDirectives.Minimal,
                masterSubpckGen.Generate(),
                null,
                new SecureRandom());

            // Retorna la referencia del KeyRing
            return keyRingGen;
        }

        /// <summary>
        /// Método maestro que genera una pareja de claves asimétricas
        /// </summary>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de encriptación asimétrica que usarán la pareja de claves</param>
        /// <param name="rsaStrengthPriority">Robustez de la clave asimétrica</param>
        /// <returns>La pareja de claves generada</returns>
        private static AsymmetricCipherKeyPair DoGenerateAsymmetricalKeyPair(AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA, RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Instanciamos un generador de claves asimétricas
            IAsymmetricCipherKeyPairGenerator generator = GeneratorUtilities.GetKeyPairGenerator(ParseAsymmetricalEncryptionAlgorithmInString(asymmetricalEncryptionAlgorithm));

            // Iniciamos el generador con los KeyRingParams definidos anteriormente
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), (int)rsaStrengthPriority, 12));

            // Genera la pareja de claves y las retorna
            return generator.GenerateKeyPair();
        }

        /// <summary>
        /// Método que genera una pareja de claves asimétricas
        /// </summary>
        /// <param name="asymmetricalEncryptionAlgorithm">Algoritmo de encriptación asimétrica que usarán la pareja de claves</param>
        /// <param name="rsaStrengthPriority">Robustez de la clave asimétrica</param>
        /// <returns>La pareja de claves generada</returns>
        public static AsymmetricCipherKeyPair GenerateAsymmetricalKeyPair(AsymmetricalEncryptionAlgorithms asymmetricalEncryptionAlgorithm = AsymmetricalEncryptionAlgorithms.RSA, RsaStrengthPriority rsaStrengthPriority = RsaStrengthPriority.Balanced)
        {
            // Resetea el contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Genera la pareja de claves y las referencia en generatedKeyPair
            AsymmetricCipherKeyPair generatedKeyPair = DoGenerateAsymmetricalKeyPair(asymmetricalEncryptionAlgorithm, rsaStrengthPriority);

            // Mensaje de debug
            Debug.WriteLine(string.Format("Generated new asymmetrical key pair using '{0}' algorithm with '{1}' bits length in {2}", asymmetricalEncryptionAlgorithm, (int)rsaStrengthPriority, Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds, true)), "Information");

            // Retorna la pareja de claves
            return generatedKeyPair;
        }

        // Define other methods and classes here
        private class KeyRingParams
        {

            public SymmetricKeyAlgorithmTag? PrivateKeyEncryptionAlgorithm { get; set; }
            public SymmetricKeyAlgorithmTag[] SymmetricAlgorithms { get; set; }
            public HashAlgorithmTag[] HashAlgorithms { get; set; }
            public RsaKeyGenerationParameters RsaParams { get; set; }
            public string Identity { get; set; }
            public string Password { get; set; }
            //= EncryptionAlgorithm.NULL;

            public char[] GetPassword()
            {
                return Password.ToCharArray();
            }

            /// <summary>
            /// Constructor general de <see cref="Leviathan.Lib.NetCorePGP.KeyRingParams"/> 
            /// </summary>
            public KeyRingParams()
            {
                //Org.BouncyCastle.Crypto.Tls.EncryptionAlgorithm
                RsaParams = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 12);
            }

            /// <summary>
            /// Constructor que acepta un RsaStrengthPriority como argumento
            /// </summary>
            /// <param name="rsaKeyGenerationParameter">Parámetros de configuración RSA</param>
            public KeyRingParams(RsaStrengthPriority rsaStrengthPriority)
            {
                RsaParams = new(BigInteger.ValueOf(0x10001), new SecureRandom(), (int)rsaStrengthPriority, 12);
            }

            /// <summary>
            /// Constructor que acepta un RsaKeyGenerationParameters como argumento
            /// </summary>
            /// <param name="rsaKeyGenerationParameter">Parámetros de configuración RSA</param>
            private KeyRingParams(RsaKeyGenerationParameters rsaKeyGenerationParameter)
            {
                //Org.BouncyCastle.Crypto.Tls.EncryptionAlgorithm
                RsaParams = rsaKeyGenerationParameter;
            }

            /// <summary>
            /// Método que devuelve la referencia a una nueva instania de <see cref="Leviathan.Lib.NetCorePGP.KeyRingParams"/> 
            /// </summary>
            /// <param name="encryptionMode">Fortaleza en el cifrado RSA en función del rendimiento deseado</param>
            /// <returns></returns>
            public static KeyRingParams Make(RsaStrengthPriority rsaEncryptionPriority)
            {
                switch(rsaEncryptionPriority)
                {
                    case RsaStrengthPriority.Speed:
                        return new KeyRingParams(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 1024, 12));
                    case RsaStrengthPriority.Balanced:
                        return new KeyRingParams(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 12));
                    default:
                        return new KeyRingParams(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 4096, 12));
                }
            }
        }

        /**
        * A simple routine that opens a key ring file and loads the first available key suitable for
        * encryption.
        *
        * @param in
        * @return
        * @m_out
        * @
        */
        public PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new(inputStream);
            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //
            //
            // iterate through the key rings.
            //
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Método que recupera la clave privada del keyring
        /// </summary>
        /// <param name="keyId">Id de la clave que se desea recuperar</param>
        /// <param name="passphrase">Constraseña para extraer la clave privada</param>
        /// <returns>Retorna la clave privada o nulo si no ha encongrado el id en el keyring</returns>
        private PgpPrivateKey? GetPrivateKeyFromSecretKey(long keyId, char[] passphrase)
        {
            // Busca el secret key
            PgpSecretKey pgpSecKey = SecretKeyRingBundle.GetSecretKey(keyId);

            // Si no recupera ninguno, retorna nulo
            if (pgpSecKey == null) { return null; }

            // Retorna la clave priva extraida del secret key usando el passphrase
            return pgpSecKey.ExtractPrivateKey(passphrase);
        }

        /// <summary>
        /// Método que recupera el algoritmo de encriptación mas robusto de un array de claves publicas
        /// </summary>
        /// <param name="ppkList">Lista de claves públicas en las que buscar</param>
        /// <returns></returns>
        private SymmetricKeyAlgorithmTag GetMaxSymmetricalAlgorithmStrengthInList(PgpPublicKey[] ppkList, SymmetricKeyAlgorithmTag fallbackSymmetricalAlgorithm = SymmetricKeyAlgorithmTag.Aes256)
        {
            // Definimos un retorno por defecto
            SymmetricKeyAlgorithmTag _return = fallbackSymmetricalAlgorithm;

            // Recorre cada PgpPublicKey de la lista
            foreach (PgpPublicKey ppk in ppkList)
            {
                // Si no recupera el PgpSecretKey, rompe el bucle
                if (ppk == null) { break; }

                // Recuperamos el secret key ligado al public key
                PgpSecretKey psk = SecretKeyRingBundle.GetSecretKey(ppk.KeyId);

                // Si no recupera el PgpSecretKey, rompe el bucle
                if (psk == null) { break; }

                // Si la clave de encriptación simétrica de la clave secreta es mas seguro que la salida anterior, fija el nuevo valor como el mas alto
                if (psk.KeyEncryptionAlgorithm > _return) { _return = psk.KeyEncryptionAlgorithm; }
            }

            // Retorna la clave de encriptación mas alta
            return _return;
        }

        /// <summary>
        /// Método que realiza la desencriptación de datos encriptados con clave pública PGP desde un array de bytes como fuente de datos encriptados
        /// </summary>
        /// <param name="inputData">Array de bytes continente de los datos encriptados con clave pública</param>
        /// <param name="passphrase">Contraseña de la clave privada que va a desencriptar los datos</param>
        /// <returns>Retorna un array de bytes con los datos desencriptados</returns>
        /// <returns></returns>
        public byte[]? DecryptToArray(byte[] inputData, string passphrase)
        {
            // Retorna un array de bytes con los datos desencriptados
            return DecryptToArray(new MemoryStream(inputData), passphrase);
        }

        /// <summary>
        /// Método que realiza la desencriptación de datos encriptados con clave pública PGP desde un Stream como fuente de datos encriptados
        /// </summary>
        /// <param name="inputStream">Stream continente de los datos encriptados con clave pública</param>
        /// <param name="passphrase">Contraseña de la clave privada que va a desencriptar los datos</param>
        /// <returns>Retorna un array de bytes con los datos desencriptados</returns>
        public byte[]? DecryptToArray(Stream inputStream, string passphrase)
        {
            // Instanciamos un memorystream para retornar los datos, será nulo por defecto
            MemoryStream _return = new();

            // Se realiza el decrypt y se copian los datos en el MemoryStream de retorno
            Decrypt(inputStream, passphrase)?.CopyTo(_return);

            // Retornar el MemoryStream como array o nulo si el MemoryStream está vacío
            return _return.Length == 0 ? null : _return.ToArray();
        }

        /// <summary>
        /// Método que realiza la desencriptación de datos encriptados con clave pública PGP desde un array de bytes como fuente de datos encriptados
        /// </summary>
        /// <param name="inputData">Array de bytes continente de los datos encriptados con clave pública</param>
        /// <param name="passphrase">Contraseña de la clave privada que va a desencriptar los datos</param>
        /// <returns>Retorna un Stream con los datos desencriptados</returns>
        public Stream? Decrypt(byte[] inputData, string passphrase)
        {
            // Retorna un array de bytes con los datos desencriptados
            return Decrypt(new MemoryStream(inputData), passphrase);
        }

        /// <summary>
        /// Método que realiza la desencriptación de datos encriptados con clave pública PGP desde un Stream como fuente de datos encriptados
        /// </summary>
        /// <param name="inputStream">Stream continente de los datos encriptados con clave pública</param>
        /// <param name="passphrase">Contraseña de la clave privada que va a desencriptar los datos</param>
        /// <returns>Retorna un Stream con los datos desencriptados</returns>
        public Stream? Decrypt(Stream inputStream, string passphrase)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Realiza la desencriptación de los datos
            (Stream? dataDecrypted, PgpSecretKey? decryptor) = DoDecrypt(inputStream, passphrase);

            // Si se recuperan datos y el desencriptador
            if (dataDecrypted != null && decryptor != null) 
            {
                // Escribe mensaje de debug
                Debug.WriteLine("{0} decrypted succesfull using '{2}' key in {1}", Utilities.File.GetSizeFormatted(inputStream.Length), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(decryptor, 0));

                // Retorna los datos desencriptados
                return dataDecrypted;
            }

            // Retorna nulo por defecto
            return null;
        }

        /// <summary>
        /// Método maestro que realiza la desencriptación de datos encriptados con clave pública PGP desde un Stream como fuente de datos encriptados
        /// </summary>
        /// <param name="inputStream">Stream de datos a desencriptar</param>
        /// <param name="passphrase">Contraseña para realizar la desencriptación</param>
        /// <returns>Stream con los datos desencriptados, PgpSecretKey clave secreta que realiza la desencriptación</returns>
        private (Stream? dataDecrypted, PgpSecretKey? decryptor) DoDecrypt(Stream inputStream, string passphrase)
        {
            // Decodifica el stream
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            // Prepara un stream de retorno
            MemoryStream decoded = new();

            // Se prepara un espacio controlado de procesamiento con Try/Catch
            try
            {
                // Instanciamos un PgpObjectFactory para desgregar los datos encriptados
                PgpObjectFactory pgpF = new(inputStream);

                // Declaramos un PgpEncryptedDataList para 
                PgpEncryptedDataList? enc = null;

                // Instalamos un PgpObject para iterar los componentes de los datos encriptados con ayuda del PgpObjectFactory
                PgpObject o = pgpF.NextPgpObject();

                // Si el primer objeto Pgp obtenido desde el PgpObjectFactory es un PgpEncryptedDataList, lo referenciamos en la refernecia "enc"
                if (o is PgpEncryptedDataList list) { enc = list; }
                // Si el primer objeto no era un PgpEncryptedDataList, recupera el siguiente objeto con aydua del PgpObjectFactory y lo castea como PgpEncryptedDataList, entonces lo referencia en "enc"
                else { enc = (PgpEncryptedDataList)pgpF.NextPgpObject(); }

                // Si no se recuperan datos encriptados
                if (enc == null)
                {
                    // Escribe error en el log
                    Debug.WriteLine(string.Format("No PGP objects found in {0} data", Utilities.File.GetSizeFormatted(inputStream.Length)), "PGP Error");

                    // Retorna nulo
                    return (null, null);
                }

                // Declaramos una referencia para clave privada
                PgpPrivateKey? privKey = null;

                // Declaramos una referencia para user ID
                // string senderId = null;
                PgpSecretKey? decryptor = null;

                // Declaramos una referencia para datos encriptados por clave púlbica
                PgpPublicKeyEncryptedData? pbe = null;

                // Recorre los datos encriptados por clave pública 'PgpPublicKeyEncryptedData' contenidos en el 'PgpEncryptedDataList' que se referenció anteriormente en la referencia 'enc'
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    ////// Recuepra la clave privada desde clave secreta usando el passphrase
                    // ++++ Se usa Try/Catch para contemplar la posiblidad de contener varias claves secretas distintas en la encriptación y que el passphrase no concuerde con la iteración ++++
                    try { privKey = GetPrivateKeyFromSecretKey(pked.KeyId, passphrase.ToCharArray()); }
                    // Pasa al siguiente ciclo de iteración si ha ocurrido una excepción de tipo PgpException
                    catch (PgpException) { continue; }

                    // Si no ha habido excepciones y se ha recuperado el key
                    if (privKey != null)
                    {
                        // Memoriza la clave secreta
                        // senderId = GetKeyUid(pked.KeyId, 0);// SecretKeyRingBundle.GetSecretKey(PublicKeyRingBundle.GetPublicKey(pked.KeyId).GetSignatures().Cast<PgpSignature>().ToArray().First().KeyId);
                        decryptor = SecretKeyRingBundle.GetSecretKey(pked.KeyId);

                        // Memoriza el 'PgpPublicKeyEncryptedData' iterado en este ciclo
                        pbe = pked;

                        // Rompe el bucle para dejar de buscar
                        break;
                    }
                    // Si no se ha recuperado un secret Key, lanza excepción
                    else { throw new ArgumentException("No secret key found to decrypt data."); }
                }

                // Si no se ha recuperado el privKey, lanza excepción
                if (privKey == null) { throw new ArgumentException("Cannot get the private key. Probably the passphrase is no correct!!"); }

                // Si no hay datos encriptados
                if (pbe == null) { throw new InvalidOperationException("No encrypted data founded"); }

                // Instanciamos un stream para almacenar datos en claro desencriptando con la clave privada vinculada a la clave pública que encriptó los datos
                Stream clear = pbe.GetDataStream(privKey);

                // Recupera el primer PgpObject contenido en el stream de datos en claro con ayuda de un PgpObjectFactory
                PgpObject message = new PgpObjectFactory(clear).NextPgpObject();

                // Si el primer objeto es un PgpCompressedData
                if (message is PgpCompressedData cData)
                {
                    //PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(cData.GetDataStream());
                    //PgpObjectFactory pgpFact = pgpObjectFactory;
                    // Con ayuda de un PgpObjectFactory temporal instanciado con los datos descomprimidos, recupera el siguiente objeto y lo referencia en la referencia "message"
                    message = new PgpObjectFactory(cData.GetDataStream()).NextPgpObject();
                }

                // Si la referencia "message" es ahora de tipo "PgpLiteralData"
                if (message is PgpLiteralData ld)
                {
                    // Referenciamos el input stream del PgpLiteralData
                    // Stream unc = ld.GetInputStream();
                    Streams.PipeAll(ld.GetInputStream(), decoded);
                }
                // Si por el contrario, la referencia "Message" es de tipo PgpOnePassSignatureList, lanza excepción ya que los datos no están encriptados sino firmados únicamente
                else if (message is PgpOnePassSignatureList) { throw new PgpException("Encrypted message contains a signed message - not literal data."); }
                // Si la refernecia "message" es cualquier otro tipo, lanza excepción de error desconocido
                else { throw new PgpException("Message is not a simple encrypted file - type unknown."); }

                // Si los datos contienen protección de integridad
                if (pbe.IsIntegrityProtected())
                {
                    // Si la comprobación de la integridad de los datos no es satisfactoria, escribe error en el log, Retorna nulo
                    if (!pbe.Verify()) { Debug.WriteLine("Message failed integrity check.", "PGP Error"); return (null, null); }
                }

                // Fija el Stream en la posición 0
                decoded.Seek(0, SeekOrigin.Begin);

                // Retorna los datos desencriptados
                return (decoded, decryptor);//; Tuple.Create<Stream, PgpSecretKey>(decoded, decryptor);
            }
            // Si se ha producido alguna excepción
            catch (Exception e)
            {
                // Modifica el mensaje de log según el inicio del mensaje de excepción
                if (e.Message.StartsWith("Checksum mismatch")) { Debug.WriteLine("Likely invalid passcode. Possible data corruption.", "Invalid Passcode"); }
                else if (e.Message.StartsWith("Object reference not")) { Debug.WriteLine("PGP data does not exist.", "PGP Error"); }
                else if (e.Message.StartsWith("Premature end of stream")) { Debug.WriteLine("Partial PGP data found.", "PGP Error"); }
                else { Debug.WriteLine("Partial PGP data found.", "PGP Error"); }

                // Recupera la excepción original si la hay y la escribe en el log
                if (e.InnerException != null) { Debug.WriteLine(e.InnerException.Message, "PGP Error"); }

                // Retorna nulo
                return (null, null);
            }
        }

        /// <summary>
        /// Método que realiza la encriptación de los datos continentes en un array de bytes usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputData">Array de bytes con los datos que se desean encriptar</param>
        /// <param name="recipient">Clave pública con la que se van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un array de bytes con los datos encriptados</returns>
        public byte[]? EncryptToArray(byte[] inputData, PgpPublicKey recipient, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Invoca al método principal
            return EncryptToArray(inputData, new PgpPublicKey[] { recipient }, withIntegrityCheck, armor, compressionAlgorithm);
        }

        /// <summary>
        /// Método que realiza la encriptación de los datos continentes en un array de bytes usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputData">Array de bytes con los datos que se desean encriptar</param>
        /// <param name="recipients">Lista de claves públicas que van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un array de bytes con los datos encriptados</returns>
        public byte[]? EncryptToArray(byte[] inputData, PgpPublicKey[] recipients, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Instanciamos un memorystream para retornar los datos, será nulo por defecto
            MemoryStream _return = new();

            // Se realiza el encrypt y se copian los datos en el MemoryStream de retorno
            Encrypt(inputData, recipients, withIntegrityCheck, armor, compressionAlgorithm)?.CopyTo(_return);

            // Retornar el MemoryStream como array o nulo si el MemoryStream está vacío
            return _return.Length == 0 ? null : _return.ToArray();
        }

        /// <summary>
        /// Método que realiza la encriptación de los datos continentes en un array de bytes usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputStream">Stream con los datos que se desean encriptar</param>
        /// <param name="recipient">Clave pública con la que se van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un array de bytes con los datos encriptados</returns>
        public byte[]? EncryptToArray(Stream inputStream, PgpPublicKey recipient, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Invoca al método principal
            return EncryptToArray(inputStream, new PgpPublicKey[] { recipient }, withIntegrityCheck, armor, compressionAlgorithm);
        }

        /// <summary>
        /// Método que realiza la encriptación de los datos continentes en un array de bytes usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputStream">Stream con los datos que se desean encriptar</param>
        /// <param name="recipients">Lista de claves públicas que van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un array de bytes con los datos encriptados</returns>
        public byte[]? EncryptToArray(Stream inputStream, PgpPublicKey[] recipients, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Instanciamos un memorystream para retornar los datos, será nulo por defecto
            MemoryStream _return = new();

            // Se realiza el encrypt y se copian los datos en el MemoryStream de retorno
            Encrypt(inputStream, recipients, withIntegrityCheck, armor, compressionAlgorithm)?.CopyTo(_return);

            // Retornar el MemoryStream como array o nulo si el MemoryStream está vacío
            return _return.Length == 0 ? null : _return.ToArray();
        }

        /// <summary>
        /// Método que realiza la encriptación de los datos continentes en un array de bytes usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputData">Array de bytes con los datos que se desean encriptar</param>
        /// <param name="recipient">Clave pública con la que se van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un stream con los datos encriptados</returns>
        public Stream? Encrypt(byte[] inputData, PgpPublicKey recipient, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Invoca al método principal
            return Encrypt(inputData, new PgpPublicKey[] { recipient }, withIntegrityCheck, armor, compressionAlgorithm);
        }

        /// <summary>
        /// Método que realiza la encriptación de los datos continentes en un array de bytes usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputData">Array de bytes con los datos que se desean encriptar</param>
        /// <param name="recipients">Lista de claves públicas que van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un stream con los datos encriptados</returns>
        public Stream? Encrypt(byte[] inputData, PgpPublicKey[] recipients, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Encripta los datos y los devuelve en stream
            Stream? bOut = DoEncrypt(inputData,recipients, withIntegrityCheck, armor, compressionAlgorithm);

            // Si la encriptación viene nula
            if (bOut == null) { Debug.WriteLine("Cant encrypt {0}. Encryption process returns null", Utilities.File.GetSizeFormatted(inputData.LongLength)); return null; }

            // Escribe en el log
            Debug.WriteLine("{0} encrypted succesfull in {1}", Utilities.File.GetSizeFormatted(inputData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds));

            // Fija el Stream en la posición 0
            bOut.Seek(0, SeekOrigin.Begin);

            // Retorna el MemoryStream
            return bOut;
        }

        /// <summary>
        /// Método maestro que realiza la encriptación de los datos continentes en un array de bytes usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputData">Array de bytes con los datos que se desean encriptar</param>
        /// <param name="recipients">Lista de claves públicas que van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un stream con los datos encriptados</returns>
        private Stream? DoEncrypt(byte[] inputData, PgpPublicKey[]? recipients, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Si la lista es nula, retorna nulo directo
            if (recipients == null) { return null; }

            // Comprime los datos según el algoritmo de encriptacion que se haya pasado como argumento
            byte[] processedData = Compress(inputData, PgpLiteralData.Console, compressionAlgorithm);

            // Instancia Streams para trabajar con los datos
            MemoryStream bOut = new();
            Stream output = bOut;

            // Si se ha decidido armar los datos en ASCII para que puedan enviarse facilmente como texto, instancia un ArmoredOutputStream
            if (armor) { output = new ArmoredOutputStream(bOut); }

            // Instancia un PgpEncryptedDataGenerator para realizar la encriptación de los datos
            PgpEncryptedDataGenerator encGen = new(GetMaxSymmetricalAlgorithmStrengthInList(recipients), withIntegrityCheck, new SecureRandom());

            // Contador de recipientes añadidos
            uint _addedRecipients = 0;

            // Recorre cada recipiente
            foreach (PgpPublicKey? ppk in recipients)
            {
                // Si el public key recorrido es nulo, pasa de ciclo
                if (ppk == null) { continue; }

                // Añade la clave pública como método de encriptación
                encGen.AddMethod(ppk);

                // Incrementa el contador
                _addedRecipients++;
            }

            // Si no se ha añadido ningún método de encriptación, retorna nulo
            if (_addedRecipients == 0) { return null; }

            // Prepara un Stream donde encriptar los datos
            Stream encOut = encGen.Open(output, processedData.Length);

            // Escribe los datos a encriptar
            encOut.Write(processedData, 0, processedData.Length);

            // Cierra el Stream
            encOut.Close();

            // Si se ha decidido armar los datos en ASCII para que puedan enviarse facilmente como texto, cierra el ArmoredOutputStream
            if (armor) { output.Close(); }

            // Fija el Stream en la posición 0
            bOut.Seek(0, SeekOrigin.Begin);

            // Retorna el MemoryStream
            return bOut;
        }

        /// <summary>
        /// Método que realiza la encriptación de los datos continentes en un Stream usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputStream">Stream de datos que se desean encriptar</param>
        /// <param name="recipients">Lista de claves públicas que van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un stream con los datos encriptados</returns>
        public Stream? Encrypt(Stream inputStream, PgpPublicKey[] recipients, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Instanciamos un memorystream para retornar los datos
            MemoryStream _input = new();

            // Copia los datos en el MemoryStream de input
            inputStream.CopyTo(_input);

            // Llama al método principal y devuelve el resultado
            return Encrypt(_input.ToArray(), recipients, withIntegrityCheck, armor, compressionAlgorithm);

        }

        /// <summary>
        /// Método que realiza la encriptación de los datos continentes en un Stream usando clave pública PGP como método de encriptación
        /// </summary>
        /// <param name="inputStream">Stream de datos que se desean encriptar</param>
        /// <param name="recipient">Clave pública que van a encriptar los datos</param>
        /// <param name="withIntegrityCheck">True: Los datos encriptados contendrán  balizas de chequeo de integridad</param>
        /// <param name="armor">True: Los datos encriptados se armarán con caracteres ASCII para facilitar que sean compartidos</param>
        /// <param name="compressionAlgorithm">Algoritmo de compresión que se desea aplicar a los datos</param>
        /// <returns>Retorna un stream con los datos encriptados</returns>
        public Stream? Encrypt(Stream inputStream, PgpPublicKey recipient, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Instanciamos un memorystream para retornar los datos
            MemoryStream _input = new();

            // Copia los datos en el MemoryStream de input
            inputStream.CopyTo(_input);

            // Llama al método principal y devuelve el resultado
            return Encrypt(_input.ToArray(), [recipient], withIntegrityCheck, armor, compressionAlgorithm);

        }

        public byte[]? SignAndEncryptFile(byte[] inputData, PgpPublicKey[] recipients, PgpSecretKey signer, char[] signerPassphrase, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed)
        {
            // Escribe en log
            Debug.WriteLine("Method under construction", "Advertisement");

            // Retorna nulo
            return null;

            /*
            MemoryStream outputStream = new();
            Stream output = outputStream;

            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Comprime los datos según el algoritmo de encriptacion que se haya pasado como argumento
            // byte[] compressedData = Compress(inputData, PgpLiteralData.Console, compressionAlgorithm);

            const int BUFFER_SIZE = 1 << 16; // should always be power of 2

            // Instancia Streams para trabajar con los datos
            // MemoryStream bOut = new();
            // Stream output = bOut;

            // Si se ha decidido armar los datos en ASCII para que puedan enviarse facilmente como texto, instancia un ArmoredOutputStream
            if (armor) { output = new ArmoredOutputStream(outputStream); }

            // Init encrypted data generator
            // Instancia un PgpEncryptedDataGenerator para realizar la encriptación de los datos
            // PgpEncryptedDataGenerator encryptedDataGenerator = new(GetMaxSymmetricalAlgorithmStrengthInList(recipients), withIntegrityCheck, new SecureRandom());
            //PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());


            // Recorre cada recipiente
            // foreach (PgpPublicKey ppk in recipients)
            //{
                // Añade la clave pública como método de encriptación
            //    encryptedDataGenerator.AddMethod(ppk);
            //}
            //encryptedDataGenerator.AddMethod(encKey);


            // Instancia Streams para trabajar con los datos
            // MemoryStream eOut = new();

            // Encripta los datos y los almacena en un stream
            // Stream encryptedOut = encryptedDataGenerator.Open(eOut, compressedData.Length);// inputData);


            // Escribe los datos a encriptar
            // encryptedOut.Write(compressedData, 0, compressedData.Length);

            // Cierra el Stream
            // encryptedOut.Close();

            byte[] encryptedBytes = EncryptToArray(inputData, recipients, withIntegrityCheck, false, compressionAlgorithm);// eOut.ToArray();

            // Cierra el Stream
            //encryptedOut.Close();
            // Init compression
            //PgpCompressedDataGenerator compressedDataGenerator = new(compressionAlgorithm);
            //Stream compressedOut = compressedDataGenerator.Open(output);//encryptedOut);
            //compressedOut.Close();
            // Init signature
            // PgpSecretKeyRingBundle pgpSecBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
            // PgpSecretKey pgpSecKey = pgpSecBundle.GetSecretKey(keyId);
            // if (pgpSecKey == null)
            //     throw new ArgumentException(keyId.ToString("X") + " could not be found in specified key ring bundle.", "keyId");


            // PgpPrivateKey pgpPrivKey = signer.ExtractPrivateKey(password);
            PgpPrivateKey pgpPrivKey = signer.ExtractPrivateKey(signerPassphrase);

            // Instanciamos un PgpSignatureGeneratos y lo referenciamos en 'signatureGenerator'
            PgpSignatureGenerator signatureGenerator = new(signer.PublicKey.Algorithm, HashAlgorithmTag.Sha256);

            // Realiza la firma con la clave privada
            signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

            // Recorre cada uno de los userIds asociados a la clave publica del SecretKey de firma
            foreach (string userId in signer.PublicKey.GetUserIds())
            {

                PgpSignatureSubpacketGenerator spGen = new();

                spGen.SetSignerUserId(false, userId);


                signatureGenerator.SetHashedSubpackets(spGen.Generate());
                // Just the first one!
                break;
            }

            PgpCompressedDataGenerator cGen = new(CompressionAlgorithmTag.Uncompressed);
            BcpgOutputStream bOut = new BcpgOutputStream(cGen.Open(output));

            signatureGenerator.GenerateOnePassVersion(false).Encode(bOut);

            // Create the Literal Data generator output stream
            PgpLiteralDataGenerator literalDataGenerator = new();

            // FileInfo embeddedFile = new FileInfo(embeddedFileName);
            // FileInfo actualFile = new FileInfo(actualFileName);
            
            // TODO: Use lastwritetime from source file
            Stream literalOut = literalDataGenerator.Open(bOut, PgpLiteralData.Binary, "Test Sign", DateTime.Now, new byte[BUFFER_SIZE]);

            // Open the input file
            //FileStream inputStream = actualFile.OpenRead();

            //byte[] buf = new byte[BUFFER_SIZE];
            //int len;
            //output.Seek(0, SeekOrigin.Begin);
            //while ((len = output.Read(buf, 0, buf.Length)) > 0)
            //{
            literalOut.Write(encryptedBytes);// buf, 0, len);
            signatureGenerator.Update(encryptedBytes);// buf, 0, len);
            //}

            //literalOut.Write(compressedOut.ToArray(), 0, compressedOut.Length);
            //signatureGenerator.Update(buf, 0, len);

            // literalOut.Close();
            literalDataGenerator.Close();
            signatureGenerator.Generate().Encode(bOut);
            cGen.Close();
            // compressedOut.Close();
            // compressedDataGenerator.Close();
            // encryptedOut.Close();
            // encryptedDataGenerator.Close();
            //inputStream.Close();

            if (armor) { output.Close(); }

            // Escribe en el log
            Debug.WriteLine("{0} have been signed with '{2}' key and encrypted succesfull in {1}", Utilities.File.GetSizeFormatted(inputData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(signer, 0));

            return outputStream.ToArray();
            */
        }

        /// <summary>
        /// Método que realiza una firma digital con clave privada en los datos
        /// </summary>
        /// <param name="signer">PgpSecretKey desde el que se desea firmar</param>
        /// <param name="signerPassphrase">Contraseña para extraer la clave privada con la que firmar</param>
        /// <param name="BytesToSign">Datos en formato array que van a ser firmados</param>
        /// <returns>Retorna la firma digital en formato array de bytes</returns>
        public byte[]? Sign(PgpSecretKey signer, char[] signerPassphrase, byte[] BytesToSign, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Fijamos la firma en la referencia Signature de tipo array de bytes
            byte[] Signature = DoSign(signer, signerPassphrase, BytesToSign, signHashAlgorithm);

            // Si se han firmado correctamente los datos, Escribe en el log el mensaje de información
            if (Signature.Length > 0) { Debug.WriteLine("{0} have been signed succesfull with '{2}' key in {1}", Utilities.File.GetSizeFormatted(BytesToSign.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(signer, 0)); }
            // Si no se han firmado los datos, escribe en el log el error y retorna nulo
            else { Debug.WriteLine("Sign is empty, the signature process will return null."); return null; }

            // Retorna la firma
            return Signature;
        }

        /// <summary>
        /// Método que realiza una firma digital con clave privada en los datos
        /// </summary>
        /// <param name="signer">String desde el que buscar el PgpSecretKey con el que firmar</param>
        /// <param name="signerPassphrase">Contraseña para extraer la clave privada con la que firmar</param>
        /// <param name="BytesToSign">Datos en formato array que van a ser firmados</param>
        /// <returns>Retorna la firma digital en formato array de bytes</returns>
        public byte[]? Sign(string signer, char[] signerPassphrase, byte[] BytesToSign, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Recupera el secret key que realizará la firma digital buscandolo en los keyring con el argumento 'signer'
            PgpSecretKey? psk = GetPgpSecretKey(signer);

            // Si no se recupera ningún secret key con el que firmar digitalmente con los datos facilitados
            if (psk == null)
            {
                // Escribe en el log
                throw new InvalidOperationException(string.Format("No signer key found with identifier '{0}' on the keyrings. Signature can't continue.", signer));
            }

            // Fijamos la firma en la referencia Signature de tipo array de bytes
            byte[] Signature = DoSign(psk, signerPassphrase, BytesToSign, signHashAlgorithm);

            // Si se han firmado correctamente los datos, Escribe en el log el mensaje de información
            if (Signature.Length > 0) { Debug.WriteLine("{0} have been signed succesfull with '{2}' key in {1}", Utilities.File.GetSizeFormatted(BytesToSign.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(psk, 0)); }
            // Si no se han firmado los datos, escribe en el log el error y retorna nulo
            else { Debug.WriteLine("Sign is empty, the signature process will return null."); return null; }

            // Retorna la firma
            return Signature;
        }

        /// <summary>
        /// Método que realiza una firma digital con clave privada en los datos
        /// </summary>
        /// <param name="signer">PgpSecretKey desde el que se desea firmar</param>
        /// <param name="signerPassphrase">Contraseña para extraer la clave privada con la que firmar</param>
        /// <param name="StreamToSign">Datos en formato array que van a ser firmados</param>
        /// <returns>Retorna la firma digital en formato array de bytes</returns>
        public byte[]? Sign(PgpSecretKey signer, char[] signerPassphrase, Stream StreamToSign, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Instanciamos un MemoryStream
            MemoryStream ms = new();

            // Copia los datos 
            StreamToSign.CopyTo(ms);

            // Fijamos la firma en la referencia Signature de tipo array de bytes
            byte[] Signature = DoSign(signer, signerPassphrase, ms.ToArray(), signHashAlgorithm);

            // Si se han firmado correctamente los datos, Escribe en el log el mensaje de información
            if (Signature.Length > 0) { Debug.WriteLine("{0} have been signed succesfull with '{2}' key in {1}", Utilities.File.GetSizeFormatted(ms.Length), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(signer, 0)); }
            // Si no se han firmado los datos, escribe en el log el error y retorna nulo
            else { Debug.WriteLine("Sign is empty, the signature process will return null."); return null; }

            // Retorna la firma
            return Signature;
        }

        /// <summary>
        /// Método que realiza una firma digital con clave privada en los datos
        /// </summary>
        /// <param name="signer">String desde el que buscar el PgpSecretKey con el que firmar</param>
        /// <param name="signerPassphrase">Contraseña para extraer la clave privada con la que firmar</param>
        /// <param name="StreamToSign">Datos en formato array que van a ser firmados</param>
        /// <returns>Retorna la firma digital en formato array de bytes</returns>
        public byte[]? Sign(string signer, char[] signerPassphrase, Stream StreamToSign, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Instanciamos un MemoryStream
            MemoryStream ms = new();

            // Copia los datos 
            StreamToSign.CopyTo(ms);

            // Recupera el secret key que realizará la firma digital buscandolo en los keyring con el argumento 'signer'
            PgpSecretKey? psk = GetPgpSecretKey(signer);

            // Si no se recupera ningún secret key con el que firmar digitalmente con los datos facilitados
            if (psk == null)
            {
                // Escribe en el log
                throw new InvalidOperationException(string.Format("No signer key found with identifier '{0}' on the keyrings. Signature can't continue.", signer));
            }

            // Fijamos la firma en la referencia Signature de tipo array de bytes
            byte[] Signature = DoSign(psk, signerPassphrase, ms.ToArray(), signHashAlgorithm);

            // Si se han firmado correctamente los datos, Escribe en el log el mensaje de información
            if (Signature.Length > 0) { Debug.WriteLine("{0} have been signed succesfull with '{2}' key in {1}", Utilities.File.GetSizeFormatted(ms.Length), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(psk, 0)); }
            // Si no se han firmado los datos, escribe en el log el error y retorna nulo
            else { Debug.WriteLine("Sign is empty, the signature process will return null."); return null; }

            // Retorna la firma
            return Signature;
        }

        /// <summary>
        /// Método maestro que realiza una firma digital con clave privada en los datos
        /// </summary>
        /// <param name="signer">PgpSecretKey desde el que se desea firmar</param>
        /// <param name="signerPassphrase">Contraseña para extraer la clave privada con la que firmar</param>
        /// <param name="BytesToSign">Datos en formato array que van a ser firmados</param>
        /// <returns>Retorna la firma digital en formato array de bytes</returns>
        /// <exception cref="InvalidOperationException">Cuando no ha sido posible computar el hash de los datos</exception>
        private byte[] DoSign(PgpSecretKey? signer, char[]? signerPassphrase, byte[] BytesToSign, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256)
        {
            // Si el firmante o el passphrase viene nulo, retorna array vacío
            if (signer == null || signerPassphrase == null) { return Array.Empty<byte>(); }

            // Instanciamos una lista de bytes como output
            List<byte> Signature = new();

            // Instanciamos un AsymmetricCipherKeyPair basandonos en la clave pública y privada del PgpSecretKey
            AsymmetricCipherKeyPair KeyPair = new(signer.PublicKey.GetKey(), signer.ExtractPrivateKey(signerPassphrase).Key);

            // Declaramos una referencia de tipo GeneralDigest
            GeneralDigest? digest = null;
            LongDigest? longDigest = null;

            // Referencia de tipo PssSigner, para realizar firmas digitales
            PssSigner? Signer;

            // Hacemos switch segun algoritmo de hash
            switch (signHashAlgorithm)
            {
                // Digest SHA256 por defecto
                default: digest = new Sha256Digest(); Signer = new(new RsaEngine(), new Sha256Digest(), digest.GetDigestSize()); break;

                // Digest MD5
                case HashAlgorithmTag.MD5: digest = new MD5Digest(); Signer = new(new RsaEngine(), new MD5Digest(), digest.GetDigestSize()); break;

                // Digest SHA1
                case HashAlgorithmTag.Sha1: digest = new Sha1Digest(); Signer = new(new RsaEngine(), new Sha1Digest(), digest.GetDigestSize()); break;

                // Digest SHA224
                case HashAlgorithmTag.Sha224: digest = new Sha224Digest(); Signer = new(new RsaEngine(), new Sha224Digest(), digest.GetDigestSize()); break;

                // Digest SHA384
                case HashAlgorithmTag.Sha384: longDigest = new Sha384Digest(); Signer = new(new RsaEngine(), new Sha384Digest(), longDigest.GetDigestSize()); break;

                // Digest SHA512
                case HashAlgorithmTag.Sha512: longDigest = new Sha512Digest(); Signer = new(new RsaEngine(), new Sha512Digest(), longDigest.GetDigestSize()); break;
            }

            // Declaramos arrays
            byte[]? TheHash;

            // Si se ha definido un LongDigest
            if (longDigest != null)
            {
                // Dimensionamos el array del hash según el tamaño de salida del Digest
                TheHash = new byte[longDigest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                longDigest.BlockUpdate(BytesToSign, 0, BytesToSign.Length);

                // Almacena el hash en el array
                longDigest.DoFinal(TheHash, 0);
            }
            // Si no se ha definido un LongDigest
            else
            {
                // Si no se ha calculado el hash, lanza excepción
                if (digest == null) { throw new InvalidOperationException("No hashing digest available."); }

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                TheHash = new byte[digest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                digest.BlockUpdate(BytesToSign, 0, BytesToSign.Length);

                // Almacena el hash en el array
                digest.DoFinal(TheHash, 0);
            }

            // Si no se ha calculado el hash, lanza excepción
            if (TheHash == null) { throw new InvalidOperationException("Error ocurred calculating data hash. It is not possible to continue with the signing process."); }

            // Inicializamos el PssSigner con la clave privada y en modo firma
            Signer.Init(true, KeyPair.Private);

            // Añade el hash de los datos a la firma
            Signer.BlockUpdate(TheHash, 0, TheHash.Length);

            // Añade el algoritmo de hash empleado en la firma
            Signature.Add((byte)signHashAlgorithm);

            // Finalmente añade la firma digital al output
            Signature.AddRange(Signer.GenerateSignature());

            // Retorna la firma
            return Signature.ToArray();
        }


        /**
        * Generate an encapsulated signed file.
        *
        * @param fileName
        * @param keyIn
        * @param outputStream
        * @param pass
        * @param armor
        */
        private Stream NewDoSign(byte[] clearData, PgpSecretKey pgpSec, char[] pass, bool armor,CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Uncompressed, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256)
        {
            Stream outputStream = new MemoryStream();

            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            PgpPrivateKey pgpPrivKey = pgpSec.ExtractPrivateKey(pass);

            PgpSignatureGenerator sGen = new(pgpSec.PublicKey.Algorithm, signHashAlgorithm);

            sGen.InitSign(PgpSignature.DefaultCertification, pgpPrivKey);
            foreach (string userId in pgpSec.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator spGen = new();
                spGen.SetSignerUserId(false, userId);
                sGen.SetHashedSubpackets(spGen.Generate());
                // Just the first one!
                break;
            }

            //PgpCompressedDataGenerator cGen = new(compressionAlgorithm);

            //Stream compressedOut = cGen.Open(outputStream);


            //BcpgOutputStream bOut = new(cOut);

            //sGen.GenerateOnePassVersion(false).Encode(outputStream);
            sGen.Generate().Encode(outputStream);

            PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
            Stream lOut = lGen.Open(outputStream, PgpLiteralData.Binary, "test", DateTime.Now, clearData);

            // FileInfo file = new FileInfo(fileName);

            // PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();

            // Stream lOut = lGen.Open(bOut, PgpLiteralData.Binary, file);
            // FileStream fIn = file.OpenRead();
            // int ch = 0;


            lOut.Write(clearData, 0, clearData.Length);
            sGen.Update(clearData, 0, clearData.Length);

            // fIn.Close();
            // lGen.Close();

            sGen.Generate().Encode(outputStream);

            //compressedOut.Close();

            /*if (armor)
            {
                outputStream.Close();
            }*/
            //outputStream.Close();

            return outputStream;
        }

        /*
        public void SignAndEncryptFile(string actualFileName, string embeddedFileName,
            Stream keyIn, long keyId, Stream outputStream,
            char[] password, bool armor, bool withIntegrityCheck, PgpPublicKey encKey)
        {
            const int BUFFER_SIZE = 1 << 16; // should always be power of 2

            if (armor)
                outputStream = new ArmoredOutputStream(outputStream);

            // Init encrypted data generator
            PgpEncryptedDataGenerator encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
            encryptedDataGenerator.AddMethod(encKey);
            Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte&#91;BUFFER_SIZE&#93;);
 
            // Init compression
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            Stream compressedOut = compressedDataGenerator.Open(encryptedOut);

            // Init signature
            PgpSecretKeyRingBundle pgpSecBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
            PgpSecretKey pgpSecKey = pgpSecBundle.GetSecretKey(keyId);
            if (pgpSecKey == null)
                throw new ArgumentException(keyId.ToString("X") + " could not be found in specified key ring bundle.", "keyId");
            PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(password);
            PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
            signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);
            foreach (string userId in pgpSecKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
                spGen.SetSignerUserId(false, userId);
                signatureGenerator.SetHashedSubpackets(spGen.Generate());
                // Just the first one!
                break;
            }
            signatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);

            // Create the Literal Data generator output stream
            PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
            FileInfo embeddedFile = new FileInfo(embeddedFileName);
            FileInfo actualFile = new FileInfo(actualFileName);
            // TODO: Use lastwritetime from source file
            Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary,
                embeddedFile.Name, actualFile.LastWriteTime, new byte&#91;BUFFER_SIZE&#93;);
 
            // Open the input file
            FileStream inputStream = actualFile.OpenRead();

            byte&#91;&#93; buf = new byte&#91;BUFFER_SIZE&#93;;
            int len;
            while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, len);
                signatureGenerator.Update(buf, 0, len);
            }

            literalOut.Close();
            literalDataGenerator.Close();
            signatureGenerator.Generate().Encode(compressedOut);
            compressedOut.Close();
            compressedDataGenerator.Close();
            encryptedOut.Close();
            encryptedDataGenerator.Close();
            inputStream.Close();

            if (armor)
                outputStream.Close();
        }
        */

        /// <summary>
        /// Método que encripta datos y los firmas despues de encriptarlos
        /// </summary>
        /// <param name="clearData">Array de bytes de datos en claro</param>
        /// <param name="recipients">Array de PgpPublicKeys con los que realizar la encriptación</param>
        /// <param name="signer">PgpSecretKey que realiza la firma digital</param>
        /// <param name="signerPassphrase">Passphrase para realizar la firma digital</param>
        /// <param name="withIntegrityCheck">True: Habilitará verificación de integridad de los datos</param>
        /// <param name="armor">True: Armará los datos con carácteres ASCII para facilitar su transporte como mensaje de texto</param>
        /// <param name="encryptDataCompression">Algoritmo de compresión a aplicar a los datos encriptados para reducir el espacio ocupado por los mimos</param>
        /// <param name="signHashAlgorithm">Algoritmo de hash que se empleará para realizar la firma digital</param>
        /// <returns>Array de bytes con los datos encriptados y firmados</returns>
        public byte[] EncryptAndSign(byte[] clearData, PgpPublicKey[]? recipients, PgpSecretKey signer, char[]? signerPassphrase, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag encryptDataCompression = CompressionAlgorithmTag.Uncompressed, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256, bool passthorughIfEncryptionFails = false, bool passthroughIfSignatureFails = false)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Invoca al método maestro
            byte[] returnBytes = DoEncryptAndSign(clearData, recipients, signer, signerPassphrase, withIntegrityCheck, armor, encryptDataCompression, signHashAlgorithm, passthorughIfEncryptionFails);

            // Escribe en el log
            Debug.WriteLine("{0} have been encrypted to recipients and signed using '{2}' key in {1}", Utilities.File.GetSizeFormatted(clearData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(signer, 0));

            // Retorna la firma
            return returnBytes;
        }

        /// <summary>
        /// Método que encripta datos y los firmas despues de encriptarlos
        /// </summary>
        /// <param name="clearData">Array de bytes de datos en claro</param>
        /// <param name="recipient">PgpPublicKey con el que realizar la encriptación</param>
        /// <param name="signer">PgpSecretKey que realiza la firma digital</param>
        /// <param name="signerPassphrase">Passphrase para realizar la firma digital</param>
        /// <param name="withIntegrityCheck">True: Habilitará verificación de integridad de los datos</param>
        /// <param name="armor">True: Armará los datos con carácteres ASCII para facilitar su transporte como mensaje de texto</param>
        /// <param name="encryptDataCompression">Algoritmo de compresión a aplicar a los datos encriptados para reducir el espacio ocupado por los mimos</param>
        /// <param name="signHashAlgorithm">Algoritmo de hash que se empleará para realizar la firma digital</param>
        /// <returns>Array de bytes con los datos encriptados y firmados</returns>
        public byte[] EncryptAndSign(byte[] clearData, PgpPublicKey? recipient, PgpSecretKey signer, char[]? signerPassphrase, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag encryptDataCompression = CompressionAlgorithmTag.Uncompressed, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256, bool passthorughIfEncryptionFails = false, bool passthroughIfSignatureFails = false)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Invoca al método maestro
            byte[] returnBytes = DoEncryptAndSign(clearData, new PgpPublicKey[] { recipient }, signer, signerPassphrase, withIntegrityCheck, armor, encryptDataCompression, signHashAlgorithm, passthorughIfEncryptionFails);

            // Escribe en el log
            Debug.WriteLine("{0} have been {3} and signed using '{2}' key in {1}", Utilities.File.GetSizeFormatted(clearData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(signer, 0)
                , recipient != null ? string.Format("encrypted to '{0}'", GetKeyUid(recipient, 0)) : "passthrough encryption" );

            // Retorna la firma
            return returnBytes;
        }

        /// <summary>
        /// Método maestro que encripta datos y los firmas despues de encriptarlos
        /// </summary>
        /// <param name="clearData">Array de bytes de datos en claro</param>
        /// <param name="recipient">Idenficiador de la clave recipiente (Fingerprint, Email, Nombre...)</param>
        /// <param name="signer">Idenficiador de la clave que realiza la firma digital (Fingerprint, Email, Nombre...)</param>
        /// <param name="signerPassphrase">Passphrase para realizar la firma digital</param>
        /// <param name="withIntegrityCheck">True: Habilitará verificación de integridad de los datos</param>
        /// <param name="armor">True: Armará los datos con carácteres ASCII para facilitar su transporte como mensaje de texto</param>
        /// <param name="encryptDataCompression">Algoritmo de compresión a aplicar a los datos encriptados para reducir el espacio ocupado por los mimos</param>
        /// <param name="signHashAlgorithm">Algoritmo de hash que se empleará para realizar la firma digital</param>
        /// <returns>Array de bytes con los datos encriptados y firmados</returns>
        private byte[] DoEncryptAndSign(byte[] clearData, PgpPublicKey[] recipients, PgpSecretKey? signer, char[]? signerPassphrase, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag encryptDataCompression = CompressionAlgorithmTag.Uncompressed, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256, bool passthorughIfEncryptionFails = false, bool passthroughIfSignatureFails = false)
        {
            // Declaramos array de retorno
            List<byte> _return = new();

            // Declara Stream de datos encriptados
            MemoryStream cryptedData = new();

            // Encripta los datos
            DoEncrypt(clearData, recipients, withIntegrityCheck, false, encryptDataCompression)?.CopyTo(cryptedData);

            // Si la encriptación no retorna datos y nos se desea pasar por alto
            if (cryptedData.Length == 0 && !passthorughIfEncryptionFails) { throw new InvalidOperationException("Encryption returns empty data. Cannot continue with the encryption and signing process."); }
            // Si la encriptación no retorna datos pero se desea pasar por alto, escribe los datos en claro
            else if (cryptedData.Length == 0 && passthorughIfEncryptionFails) { cryptedData.Write(clearData, 0, clearData.Length); }

            // Firma los datos ya encriptados
            byte[] signature = DoSign(signer, signerPassphrase, cryptedData.ToArray(), signHashAlgorithm);

            // Si la firma viene nula, lanza excepción
            if (signature.Length == 0 && !passthroughIfSignatureFails) { throw new InvalidOperationException("Signature is empty. Cannot continue with the encryption and signing process."); }

            // Añade el tamaño de la firma al output
            _return.AddRange(BitConverter.GetBytes((ushort)signature.Length));

            // Añade la firma al output
            _return.AddRange(signature);

            // Agrega los datos encriptados al final
            _return.AddRange(cryptedData.ToArray());

            // Retorna la firma
            return _return.ToArray();
        }

        /// <summary>
        /// Método que encripta datos y los firmas despues de encriptarlos
        /// </summary>
        /// <param name="clearData">Array de bytes de datos en claro</param>
        /// <param name="recipient">Idenficiador de la clave recipiente (Fingerprint, Email, Nombre...)</param>
        /// <param name="signer">Idenficiador de la clave que realiza la firma digital (Fingerprint, Email, Nombre...)</param>
        /// <param name="signerPassphrase">Passphrase para realizar la firma digital</param>
        /// <param name="withIntegrityCheck">True: Habilitará verificación de integridad de los datos</param>
        /// <param name="armor">True: Armará los datos con carácteres ASCII para facilitar su transporte como mensaje de texto</param>
        /// <param name="encryptDataCompression">Algoritmo de compresión a aplicar a los datos encriptados para reducir el espacio ocupado por los mimos</param>
        /// <param name="signHashAlgorithm">Algoritmo de hash que se empleará para realizar la firma digital</param>
        /// <returns>Array de bytes con los datos encriptados y firmados</returns>
        public byte[] EncryptAndSign(byte[] clearData, string recipient, string signer, char[] signerPassphrase, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag encryptDataCompression = CompressionAlgorithmTag.Uncompressed, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256, bool passthorughIfEncryptionFails = false, bool passthroughIfSignatureFails = false)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Recupera el public key que realizará la firma digital buscandolo en los keyring con el argumento 'recipient'
            PgpPublicKey? ppk = recipient != string.Empty ? GetPgpPublicKey(recipient) : null;

            // Si no se recupera ningún public key con el que encriptar con los datos facilitados
            if (ppk == null && !passthorughIfEncryptionFails) 
            {
                // Escribe en el log
                throw new InvalidOperationException(string.Format("No recipient key found with identifier '{0}' on the keyrings. Encryption can't continue.", recipient));
            }

            // Recupera el secret key que realizará la firma digital buscandolo en los keyring con el argumento 'signer'
            PgpSecretKey? psk = GetPgpSecretKey(signer);

            // Si no se recupera ningún secret key con el que firmar digitalmente con los datos facilitados
            if (psk == null && !passthroughIfSignatureFails)
            {
                // Escribe en el log
                throw new InvalidOperationException(string.Format("No signer key found with identifier '{0}' on the keyrings. Encryption can't continue.", signer));
            }

            // Invoca al método maestro
            byte[] returnBytes = DoEncryptAndSign(clearData, new PgpPublicKey[] { ppk }, psk, signerPassphrase, withIntegrityCheck, armor, encryptDataCompression, signHashAlgorithm, passthorughIfEncryptionFails, passthroughIfSignatureFails);

            // Escribe en el log
            Debug.WriteLine("{0} have been {3} and {2} in {1}", Utilities.File.GetSizeFormatted(clearData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds)
                , psk != null ? string.Format("signed using '{0}' key", GetKeyUid(psk, 0)) : "passthrough signature"
                , ppk != null ? string.Format("encrypted to '{0}'", GetKeyUid(ppk, 0)) : "passthrough encryption");

            // Retorna la firma
            return returnBytes;
        }

        /// <summary>
        /// Método que encripta datos y los firmas despues de encriptarlos
        /// </summary>
        /// <param name="clearData">Array de bytes de datos en claro</param>
        /// <param name="recipient">Idenficiador de la clave recipiente (Fingerprint, Email, Nombre...)</param>
        /// <param name="signer">Idenficiador de la clave que realiza la firma digital (Fingerprint, Email, Nombre...)</param>
        /// <param name="signerPassphrase">Passphrase para realizar la firma digital</param>
        /// <param name="withIntegrityCheck">True: Habilitará verificación de integridad de los datos</param>
        /// <param name="armor">True: Armará los datos con carácteres ASCII para facilitar su transporte como mensaje de texto</param>
        /// <param name="encryptDataCompression">Algoritmo de compresión a aplicar a los datos encriptados para reducir el espacio ocupado por los mimos</param>
        /// <param name="signHashAlgorithm">Algoritmo de hash que se empleará para realizar la firma digital</param>
        /// <returns>Array de bytes con los datos encriptados y firmados</returns>
        public byte[] EncryptAndSign(byte[] clearData, string[] recipients, string signer, char[] signerPassphrase, bool withIntegrityCheck = false, bool armor = false, CompressionAlgorithmTag encryptDataCompression = CompressionAlgorithmTag.Uncompressed, HashAlgorithmTag signHashAlgorithm = HashAlgorithmTag.Sha256, bool passthorughIfEncryptionFails = false, bool passthroughIfSignatureFails = false)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Declaramos lista de recipients
            List<PgpPublicKey> _recipients = new();

            // Recorre la lista de recipientes a buscar
            foreach(string recipient in recipients)
            {
                // Recupera el public key que realizará la firma digital buscandolo en los keyring con el argumento 'recipient'
                PgpPublicKey? ppk = GetPgpPublicKey(recipient);

                // Si se recuperan datos, se añaden a la lista
                if (ppk != null) { _recipients.Add(ppk); }
            }

            // Si no se recupera ningún public key con el que encriptar con los datos facilitados
            if (_recipients.Count == 0)
            {
                // Escribe en el log
                throw new InvalidOperationException("No recipient keys found with that identifiers. Encryption can't continue.");
            }

            // Recupera el secret key que realizará la firma digital buscandolo en los keyring con el argumento 'signer'
            PgpSecretKey? psk = GetPgpSecretKey(signer);

            // Si no se recupera ningún secret key con el que firmar digitalmente con los datos facilitados
            if (psk == null)
            {
                // Escribe en el log
                throw new InvalidOperationException(string.Format("No signer key found with identifier '{0}' on the keyrings. Encryption can't continue.", signer));
            }

            // Invoca al método maestro
            byte[] returnBytes = DoEncryptAndSign(clearData, _recipients.ToArray(), psk, signerPassphrase, withIntegrityCheck, armor, encryptDataCompression, signHashAlgorithm, passthorughIfEncryptionFails);

            // Escribe en el log
            Debug.WriteLine("{0} have been encrypted to recipients and signed using '{2}' key in {1}", Utilities.File.GetSizeFormatted(clearData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(psk, 0));

            // Retorna la firma
            return returnBytes;
        }

        /// <summary>
        /// Método que busca el propietario de una firma en un array de bytes
        /// </summary>
        /// <param name="signedData">Datos firmados en formato array</param>
        /// <param name="signature">Firma a buscar</param>
        /// <returns>El PgpPublicKey que firmó los datos</returns>
        public PgpPublicKey? Verify(byte[] signedData, byte[] signature)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Recupera el PgpPublicKey que ha firmado los datos
            PgpPublicKey? signer = DoVerify(signedData, signature);

            // Si se ha recuperado un firmante, escribirá en el log mensaje de verificación
            if (signer != null) { Debug.WriteLine(string.Format("Verified '{2}' key signature on {0} in {1}", Utilities.File.GetSizeFormatted(signedData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(signer, 0)), "PGP Signature Verification"); }
            // Si no se ha recuperado ningún firmante, escribirá en el log mensaje de no verificación
            else { Debug.WriteLine(string.Format("Not verified the signature on {0}", Utilities.File.GetSizeFormatted(signedData.LongLength)), "PGP Signature Verification"); }


            // Retorna el PgpPublicKey que ha realizado la firma
            return signer;
        }

        /// <summary>
        /// Método que busca el propietario de una firma en un array de bytes
        /// </summary>
        /// <param name="signedData">Datos firmados en formato array</param>
        /// <returns>El PgpPublicKey que firmó los datos</returns>
        public PgpPublicKey? Verify(byte[] signedData)
        {
            // Si los datos a verificar no superan los 2 bytes, retornará todo como nulo
            if (signedData.Length <= 2) { return null; }

            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Desglosamos la firma y los datos encriptados
            ushort signatureLength = BitConverter.ToUInt16(signedData, 0);
            byte[] signature = Utilities.Array.GetByteArrayFragment(2, signatureLength, signedData);

            // Recupera el PgpPublicKey que ha firmado los datos
            PgpPublicKey? signer = DoVerify(signedData, signature);

            // Si se ha recuperado un firmante, escribirá en el log mensaje de verificación
            if (signer != null) { Debug.WriteLine(string.Format("Verified '{2}' key signature on {0} in {1}", Utilities.File.GetSizeFormatted(signedData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(signer, 0)), "PGP Signature Verification"); }
            // Si no se ha recuperado ningún firmante, escribirá en el log mensaje de no verificación
            else { Debug.WriteLine(string.Format("Not verified the signature on {0}", Utilities.File.GetSizeFormatted(signedData.LongLength)), "PGP Signature Verification"); }

            // Retorna el PgpPublicKey que ha realizado la firma
            return signer;
        }

        /// <summary>
        /// Método que busca el propietario de una firma en un array de bytes
        /// </summary>
        /// <param name="signedData">Datos firmados en formato array</param>
        /// <param name="signature">Firma a buscar</param>
        /// <returns>El PgpPublicKey que firmó los datos</returns>
        public PgpPublicKey? NewVerify(byte[] signedData, byte[] signature)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Recupera el PgpPublicKey que ha firmado los datos
            PgpPublicKey? signer = NewDoVerify(signedData, signature);

            // Si se ha recuperado un firmante, escribirá en el log mensaje de verificación
            if (signer != null) { Debug.WriteLine("Verified '{2}' key signature on {0} in {1}", Utilities.File.GetSizeFormatted(signedData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(signer, 0)); }
            // Si no se ha recuperado ningún firmante, escribirá en el log mensaje de no verificación
            else { Debug.WriteLine("Not verified the signature on {0}", Utilities.File.GetSizeFormatted(signedData.LongLength)); }

            // Retorna el PgpPublicKey que ha realizado la firma
            return signer;
        }

        /// <summary>
        /// Método maestro que busca el propietario de una firma en un array de bytes
        /// </summary>
        /// <param name="signedData">Datos firmados en formato array</param>
        /// <param name="signature">Firma a buscar</param>
        /// <returns>El PgpPublicKey que firmó los datos</returns>
        private PgpPublicKey? DoVerify(byte[] signedData, byte[] signature)
        {
            // Recorre cada public key del keyring bundle
            foreach (PgpPublicKeyRing ppkr in PublicKeyRingBundle.GetKeyRings())
            {
                // Recorre cada public key del keyring
                foreach (PgpPublicKey ppk in ppkr.GetPublicKeys())
                {
                    // Descarta las PgpPublicKeys que nos son MasterKeys
                    if (!ppk.IsMasterKey) { continue; }

                    // Si se detecta una firma del public key  la firma
                    if (DoVerify(ppk, signedData, signature))
                    {
                        // Retorna el PgpPublicKey que ha verificado la firma
                        return ppk;
                    }
                }
            }

            // Sale con nulo si no se encuentra una firma
            return null;
        }

        /// <summary>
        /// Método maestro que busca el propietario de una firma en un array de bytes
        /// </summary>
        /// <param name="signedData">Datos firmados en formato array</param>
        /// <param name="signature">Firma a buscar</param>
        /// <returns>El PgpPublicKey que firmó los datos</returns>
        private PgpPublicKey? NewDoVerify(byte[] signedData, byte[] signature)
        {
            // Recorre cada public key del keyring bundle
            foreach (PgpPublicKeyRing ppkr in PublicKeyRingBundle.GetKeyRings())
            {
                // Recorre cada public key del keyring
                foreach (PgpPublicKey ppk in ppkr.GetPublicKeys())
                {
                    // Si se detecta una firma del public key  la firma
                    if (NewDoVerify(ppk, signedData, signature))
                    {
                        // Retorna el PgpPublicKey que ha verificado la firma
                        return ppk;
                    }
                }
            }

            // Sale con nulo si no se encuentra una firma
            return null;
        }

        /// <summary>
        /// Método que busca la firma de una clave pública en un array de bytes
        /// </summary>
        /// <param name="verifier">PgpPublicKey con el que verificar los datos</param>
        /// <param name="signedData">Datos firmados en formato array</param>
        /// <param name="signature">Firma digital</param>
        /// <returns>True si se ha validado la firma del PgpPublicKey en los datos</returns>
        public bool NewVerify(PgpPublicKey verifier, byte[] signedData, byte[] signature)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Realiza la verificación de la firma y recupera el resultado
            bool verification = NewDoVerify(verifier, signedData, signature);

            // Escribe el resultado en el log
            Debug.WriteLine("{3} '{2}' key sign in {0} in {1}", Utilities.File.GetSizeFormatted(signedData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(verifier, 0), verification ? "Verified" : "Not Verified");

            // Retorna el resultado
            return verification;
        }

        /// <summary>
        /// Método que busca la firma de una clave pública en un array de bytes
        /// </summary>
        /// <param name="verifier">PgpPublicKey con el que verificar los datos</param>
        /// <param name="signedData">Datos firmados en formato array</param>
        /// <returns>True si se ha validado la firma del PgpPublicKey en los datos</returns>
        public bool Verify(PgpPublicKey verifier, byte[] signedData)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Desglosamos la firma y los datos encriptados
            ushort signatureLength = BitConverter.ToUInt16(signedData, 0);
            byte[] signature = Utilities.Array.GetByteArrayFragment(2, signatureLength, signedData);
            byte[] encryptedData = Utilities.Array.GetByteArrayFragment(2 + signatureLength, signedData);

            // Realiza la verificación de la firma y recupera el resultado
            bool verification = DoVerify(verifier, encryptedData, signature);

            // Escribe el resultado en el log
            Debug.WriteLine(string.Format("{3} '{2}' key sign in {0} in {1}", Utilities.File.GetSizeFormatted(signedData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(verifier, 0), verification ? "Verified" : "Not Verified"), "PGP Signature Verification");

            // Retorna el resultado
            return verification;
        }

        /// <summary>
        /// Método que busca la firma de una clave pública en un array de bytes
        /// </summary>
        /// <param name="verifier">PgpPublicKey con el que verificar los datos</param>
        /// <param name="signedData">Datos firmados en formato array</param>
        /// <param name="signature">Firma digital</param>
        /// <returns>True si se ha validado la firma del PgpPublicKey en los datos</returns>
        public bool Verify(PgpPublicKey verifier, byte[] signedData, byte[] signature)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Realiza la verificación de la firma y recupera el resultado
            bool verification = DoVerify(verifier, signedData, signature);

            // Escribe el resultado en el log
            Debug.WriteLine(string.Format("{3} '{2}' key sign in {0} in {1}", Utilities.File.GetSizeFormatted(signedData.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds), GetKeyUid(verifier, 0), verification ? "Verified" : "Not Verified"), "PGP Signature Verification");

            // Retorna el resultado
            return verification;
        }

        /// <summary>
        /// Método maestro que busca la firma de una clave pública en un array de bytes
        /// </summary>
        /// <param name="verifier">PgpPublicKey con el que verificar los datos</param>
        /// <param name="signedBytes">Datos firmados en formato array</param>
        /// <param name="ExpectedSignatureBytes">Firma digital</param>
        /// <returns>True si se ha validado la firma del PgpPublicKey en los datos</returns>
        private bool DoVerify(PgpPublicKey verifier, byte[] signedBytes, byte[] ExpectedSignatureBytes)
        {
            // Si los datos a verificar no superan los 2 bytes, retornará todo como nulo
            if (signedBytes.Length <= 2) { return false; }

            // Desglosa la firma y el byte de identificacion de algoritmo de hash
            byte hashAlgorithmId = Utilities.Array.GetByteArrayFragment(0, 1, ExpectedSignatureBytes)[0];
            byte[] signature = Utilities.Array.GetByteArrayFragment(1, ExpectedSignatureBytes);

            // Recupera el identificador del algoritmo de hash que codifica la firma
            HashAlgorithmTag signHashAlgorithm = (HashAlgorithmTag)Enum.ToObject(typeof(HashAlgorithmTag), hashAlgorithmId);

            // Recupera la clave pública del verificador
            AsymmetricKeyParameter KeyPair = verifier.GetKey();

            // Declaramos una referencia de tipo GeneralDigest
            GeneralDigest? digest = null;
            LongDigest? longDigest = null;

            // Referencia de tipo PssSigner, para realizar firmas digitales
            PssSigner? Signer = null;
            
            // Hacemos switch segun algoritmo de hash
            switch (signHashAlgorithm)
            {
                // Digest SHA256 por defecto
                default: digest = new Sha256Digest(); Signer = new(new RsaEngine(), new Sha256Digest(), digest.GetDigestSize()); break;

                // Digest MD5
                case HashAlgorithmTag.MD5: digest = new MD5Digest(); Signer = new(new RsaEngine(), new MD5Digest(), digest.GetDigestSize()); break;

                // Digest SHA1
                case HashAlgorithmTag.Sha1: digest = new Sha1Digest(); Signer = new(new RsaEngine(), new Sha1Digest(), digest.GetDigestSize()); break;

                // Digest SHA224
                case HashAlgorithmTag.Sha224: digest = new Sha224Digest(); Signer = new(new RsaEngine(), new Sha224Digest(), digest.GetDigestSize()); break;

                // Digest SHA384
                case HashAlgorithmTag.Sha384: longDigest = new Sha384Digest(); Signer = new(new RsaEngine(), new Sha384Digest(), longDigest.GetDigestSize()); break;

                // Digest SHA512
                case HashAlgorithmTag.Sha512: longDigest = new Sha512Digest(); Signer = new(new RsaEngine(), new Sha512Digest(), longDigest.GetDigestSize()); break;
            }
            //longDigest = new Sha512Digest(); Signer = new(new RsaEngine(), new Sha512Digest(), longDigest.GetDigestSize());

            // Declaramos arrays
            byte[]? TheHash = null;

            // Si se ha definido un LongDigest
            if (longDigest != null)
            {
                // Dimensionamos el array del hash según el tamaño de salida del Digest
                TheHash = new byte[longDigest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                longDigest.BlockUpdate(signedBytes, 0, signedBytes.Length);

                // Almacena el hash en el array
                longDigest.DoFinal(TheHash, 0);
            }
            // Si no se ha definido un LongDigest
            else
            {
                // Si no se ha calculado el hash, lanza excepción
                if (digest == null) { throw new InvalidOperationException("Error ocurred calculating data hash. No digest found."); }

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                TheHash = new byte[digest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                digest.BlockUpdate(signedBytes, 0, signedBytes.Length);

                // Almacena el hash en el array
                digest.DoFinal(TheHash, 0);
            }

            // Si no se ha calculado el hash, lanza excepción
            if (TheHash == null) { throw new InvalidOperationException("Error ocurred calculating data hash. It is not possible to continue with the signing process."); }

            // Inicializamos el PssSigner con la clave privada y en modo validación de firmas
            Signer.Init(false, KeyPair);

            // Añade el hash de los datos a la firma
            Signer.BlockUpdate(TheHash, 0, TheHash.Length);

            // Retorna el resultado de la verificación
            return Signer.VerifySignature(signature);
        }

        /// <summary>
        /// Método maestro que busca la firma de una clave pública en un array de bytes
        /// </summary>
        /// <param name="publicKey">PgpPublicKey con el que verificar los datos</param>
        /// <param name="data">Datos firmados en formato array</param>
        /// <param name="expectedSignatureBytes">Firma digital</param>
        /// <returns>True si se ha validado la firma del PgpPublicKey en los datos</returns>
        private bool NewDoVerify(PgpPublicKey publicKey, byte[] data, byte[] expectedSignatureBytes)
        {
            // Se decodifica la firma en un stream
            Stream stream = PgpUtilities.GetDecoderStream(new MemoryStream(expectedSignatureBytes));

            // Se construye un PgpObjectFactory desde el stream
            PgpObjectFactory pgpFact = new(stream);

            // Si el ControlResponse viene nulo
            if (pgpFact.NextPgpObject() is not PgpSignatureList sList)
            {
                // Lanza excepción
                throw new InvalidOperationException("No signature found on expected signature");
            }

            // Recupera la firma PGP 
            PgpSignature firstSig = sList[0];

            /*
            // Añade el PgpPublicKey con el que realizar la verificación
            firstSig.InitVerify(publicKey);

            // Actualiza los datos de verficación
            firstSig.Update(data, 0, data.Length);*/

            // Realiza la verificación
            bool verified = firstSig.KeyId == publicKey.KeyId; //firstSig.Verify();

            // Retorna el resultado
            return verified;
        }

        /// <summary>
        /// Método que verifica y desencripta los datos encriptados en formato stream
        /// </summary>
        /// <param name="data">Array de bytes de datos encriptados</param>
        /// <param name="decrypterPassprase">Passphrase para la desencriptación de los datos</param>
        /// <returns>Stream con los datos desencriptados, PgpPublicKey con el verificador de la firma, PgpSecretKey con el desencriptador</returns>
        public (Stream? data, PgpPublicKey? signer, PgpSecretKey? decrypter) VerifyAndDecrypt(byte[] data, string decrypterPassprase, bool passthroughDecryptionFails = false, bool passthroughVerificationFails = false)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Invoca al método maestro
            (Stream? _returnData, PgpPublicKey? verifier, PgpSecretKey? decrypter) = DoVerifyAndDecrypt(data, decrypterPassprase, passthroughDecryptionFails);

            // Escribe en el log
            Debug.WriteLine("{2} on {0} and {3} in {1}"
                , Utilities.File.GetSizeFormatted(data.LongLength)
                , Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds)
                , verifier == null ? "Not verified signature" : string.Format("Verified signature of '{0}' key", GetKeyUid(verifier, 0))
                , _returnData != null && decrypter != null ? string.Format("decrypted {0} using '{1}' key", Utilities.File.GetSizeFormatted(_returnData.Length), GetKeyUid(decrypter, 0)) : "cannot decrypt data");

            // Retorna resultados
            return (_returnData, verifier, decrypter);
        }

        /// <summary>
        /// Método maestro que verifica y desencripta los datos encriptados en formato stream
        /// </summary>
        /// <param name="data">Array de bytes de datos encriptados</param>
        /// <param name="decrypterPassprase">Passphrase para la desencriptación de los datos</param>
        /// <returns>Stream con los datos desencriptados, PgpPublicKey con el verificador de la firma, PgpSecretKey con el desencriptador</returns>
        private (Stream? data, PgpPublicKey? signer, PgpSecretKey? decrypter) DoVerifyAndDecrypt(byte[] data, string decrypterPassprase, bool passthroughDecryptionFails = false, bool passthroughVerificationFails = false)
        {
            // Si los datos a verificar no superan los 2 bytes, retornará todo como nulo
            if (data.Length <= 2) { return (null, null, null); }

            // Desglosamos la firma y los datos encriptados
            ushort signatureLength = BitConverter.ToUInt16(data, 0);
            byte[] signature = Utilities.Array.GetByteArrayFragment(2, signatureLength, data);
            byte[] encryptedData = Utilities.Array.GetByteArrayFragment(2 + signatureLength, data);

            // Verifica la firma y recupera el PgpPublicKey
            PgpPublicKey? verifier = null;

            // Verifica la firma y recupera el PgpPublicKey
            try { verifier = DoVerify(encryptedData, signature); } catch (Exception) { }

            // Declaramos datos de retorno
            Stream? _returnData;
            PgpSecretKey? decrypter;

            // Desencripta los datos
            (_returnData, decrypter) = DoDecrypt(new MemoryStream(encryptedData), decrypterPassprase);

            // Si no se han recuperado datos de la desencriptación pero se desea pasar por alto, retornará los datos en bruto
            if (_returnData == null && passthroughDecryptionFails) { _returnData = new MemoryStream(encryptedData); }

            // Retorna resultados
            return (_returnData, verifier, decrypter);
        }

        /// <summary>
        /// Método maestro que verifica y desencripta los datos encriptados en formato stream
        /// </summary>
        /// <param name="data">Array de bytes de datos encriptados</param>
        /// <param name="decrypterPassprase">Passphrase para la desencriptación de los datos</param>
        /// <param name="expectedSigner">PgpPublicKey con el que comprobar la firma de los datos</param>
        /// <returns>Stream con los datos desencriptados, PgpPublicKey con el verificador de la firma, PgpSecretKey con el desencriptador</returns>
        private (Stream? data, PgpPublicKey? signer, PgpSecretKey? decrypter) DoVerifyAndDecrypt(byte[] data, string decrypterPassprase, PgpPublicKey expectedSigner, bool passthroughDecryptionFails = false, bool passthroughVerificationFails = false)
        {
            // Si los datos a verificar no superan los 2 bytes, retornará todo como nulo
            if (data.Length <= 2) { return (null, null, null); }

            // Desglosamos la firma y los datos encriptados
            ushort signatureLength = BitConverter.ToUInt16(data, 0);
            byte[] signature = Utilities.Array.GetByteArrayFragment(2, signatureLength, data);
            byte[] encryptedData = Utilities.Array.GetByteArrayFragment(2 + signatureLength, data);

            // Verifica la firma y recupera el PgpPublicKey
            PgpPublicKey? verifier = null;

            // Verifica la firma y recupera el PgpPublicKey
            try { verifier = DoVerify(expectedSigner, encryptedData, signature) ? expectedSigner : null; } catch (Exception) { }

            // Declaramos datos de retorno
            Stream? _returnData;
            PgpSecretKey? decrypter;

            // Desencripta los datos
            (_returnData, decrypter) = DoDecrypt(new MemoryStream(encryptedData), decrypterPassprase);

            // Si no se han recuperado datos de la desencriptación pero se desea pasar por alto, retornará los datos en bruto
            if (_returnData == null && passthroughDecryptionFails) { _returnData = new MemoryStream(encryptedData); }

            // Retorna resultados
            return (_returnData, verifier, decrypter);
        }


        /// <summary>
        /// Método que verifica y desencripta los datos encriptados en formato array de bytes
        /// </summary>
        /// <param name="data">Array de bytes de datos encriptados</param>
        /// <param name="decrypterPassprase">Passphrase para la desencriptación de los datos</param>
        /// <returns>Array de bytes con los datos desencriptados, PgpPublicKey con el verificador de la firma, PgpSecretKey con el desencriptador</returns>
        public (byte[]? data, PgpPublicKey? signer, PgpSecretKey? decrypter) VerifyAndDecryptToArray(byte[] data, string decrypterPassprase, bool passthroughDecryptionFails = false, bool passthroughVerificationFails = false)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Invoca al método maestro
            (Stream? _returnData, PgpPublicKey? verifier, PgpSecretKey? decrypter) = DoVerifyAndDecrypt(data, decrypterPassprase, passthroughDecryptionFails, passthroughVerificationFails);

            // Escribe en el log
            Debug.WriteLine("{2} on {0} and {3} in {1}"
                , Utilities.File.GetSizeFormatted(data.LongLength)
                , Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds)
                , verifier == null ? "Not verified signature" : string.Format("Verified signature of '{0}' key", GetKeyUid(verifier, 0))
                , _returnData != null && decrypter != null ? string.Format("decrypted {0} using '{1}' key", Utilities.File.GetSizeFormatted(_returnData.Length), GetKeyUid(decrypter, 0)) : "cannot decrypt data");

            // Declaramos array de retorno
            byte[]? _arrayReturn = null;

            // Si se han leído datos
            if (_returnData != null)
            {
                // Instanciamos un array de bytes de la longitud del stream
                _arrayReturn = new byte[_returnData.Length];

                // Escribe los datos del stream en el array de datos
                _returnData.Read(_arrayReturn, 0, _arrayReturn.Length);
            }

            // Retorna resultados
            return (_arrayReturn, verifier, decrypter);
        }

        /// <summary>
        /// Método que verifica y desencripta los datos encriptados en formato array de bytes
        /// </summary>
        /// <param name="data">Array de bytes de datos encriptados</param>
        /// <param name="decrypterPassprase">Passphrase para la desencriptación de los datos</param>
        /// <returns>Array de bytes con los datos desencriptados, PgpPublicKey con el verificador de la firma, PgpSecretKey con el desencriptador</returns>
        public (byte[]? data, PgpPublicKey? signer, PgpSecretKey? decrypter) VerifyAndDecryptToArray(byte[] data, string decrypterPassprase, PgpPublicKey expectedSigner, bool passthroughDecryptionFails = false, bool passthroughVerificationFails = false)
        {
            // Resetea contador de tiempo transcurrido
            Utilities.Time.ResetElapsed();

            // Invoca al método maestro
            (Stream? _returnData, PgpPublicKey? verifier, PgpSecretKey? decrypter) = DoVerifyAndDecrypt(data, decrypterPassprase, expectedSigner, passthroughDecryptionFails, passthroughVerificationFails);

            // Escribe en el log
            Debug.WriteLine("{2} on {0} and {3} in {1}"
                , Utilities.File.GetSizeFormatted(data.LongLength)
                , Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds)
                , verifier == null ? "Not verified signature" : string.Format("Verified signature of '{0}' key", GetKeyUid(verifier, 0))
                , _returnData != null && decrypter != null ? string.Format("decrypted {0} using '{1}' key", Utilities.File.GetSizeFormatted(_returnData.Length), GetKeyUid(decrypter, 0)) : "cannot decrypt data");

            // Declaramos array de retorno
            byte[]? _arrayReturn = null;

            // Si se han leído datos
            if (_returnData != null)
            {
                // Instanciamos un array de bytes de la longitud del stream
                _arrayReturn = new byte[_returnData.Length];

                // Escribe los datos del stream en el array de datos
                _returnData.Read(_arrayReturn, 0, _arrayReturn.Length);
            }

            // Retorna resultados
            return (_arrayReturn, verifier, decrypter);
        }


        /// <summary>
        /// Método estático que comprime datos continentes en un array de bytes
        /// </summary>
        /// <param name="clearData">Array de bytes continente de los datos en claro</param>
        /// <param name="fileName">Nombre asociado al fichero de los datos compresos</param>
        /// <param name="algorithm">Algoritmo de compresión a aplicar</param>
        /// <returns>Retorna un nuevo array de bytes con los datos compresos</returns>
        private static byte[] Compress(byte[] clearData, string fileName, CompressionAlgorithmTag algorithm)
        {
            // Instancia un nuevo MemoryStream
            MemoryStream bOut = new();

            // Instancia un nuevo PgpCompressedDataGenerator en base al algoritmo de compresión pasador por argumento y lo referencia en 'comData'
            PgpCompressedDataGenerator comData = new(algorithm);
            
            // Abre el PgpCompressedDataGenerator pasando el MemoryStream de retorno como argumento
            Stream cos = comData.Open(bOut);
            
            // Instanciamos un nuevo PgpLiteralDataGenerator
            PgpLiteralDataGenerator lData = new();

            // Instanciamos un nuevo Stream estructurando los datos con la ayuda del PgpLiteralDataGenerator anteriormente instanciado
            Stream pOut = lData.Open(
            cos,                    // Stream de retorno comprimido
            PgpLiteralData.Binary,  // Tipo de datos binarios
            fileName,               // Nombre del fichero a almacenar
            clearData.Length,       // Longitud total de los datos antes de comprimir
            DateTime.UtcNow         // Fecha de creación de los datos compresos
            );

            // Escribe los datos en el stream estructurado
            pOut.Write(clearData, 0, clearData.Length);
            
            // Cierra el stream estructurado
            pOut.Close();

            // Cierra el compresor de datos
            comData.Close();

            // Retorna salida como array de bytes
            return bOut.ToArray();
        }

    }

    public class DecryptResult
    {
        PgpPublicKey signer;
        PgpSecretKey decrypter;
        Stream decryptedData;

        public PgpPublicKey Signer => signer;
        public PgpSecretKey Decrypter => decrypter;
        public Stream Data => decryptedData;
        public byte[] DataArray => StreamToArray(decryptedData);

        public DecryptResult(Stream decryptedData, PgpPublicKey signer, PgpSecretKey decrypter)
        {
            this.decryptedData = decryptedData;
            this.signer = signer;
            this.decrypter = decrypter;
        }

        private byte[] StreamToArray(Stream data)
        {
            data.Seek(0, SeekOrigin.Begin);

            MemoryStream ms = new();

            data.CopyTo(ms);

            ms.Seek(0, SeekOrigin.Begin);

            return ms.ToArray();
        }
    }
}
