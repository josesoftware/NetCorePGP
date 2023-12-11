using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics;
using System.Text;
using static NetCorePGP.SymmetricalCiphers.AES;

namespace NetCorePGP
{
    public class SymmetricalCiphers
    {
        public static class AES
        {
            // Algoritmos disponibles
            public enum CipherMode
            {
                CBC = 0,
                GCM = 1,
                CTR = 2
            }
            public enum Padding
            {
                NoPadding = 0,
                PKCS7 = 1
            }
            public enum KeyLength
            {
                AES128 = 0,
                AES192 = 1,
                AES256 = 2,
                AESRAW = 3
            }
            private const byte AesIvSize = 16;
            private const byte GcmTagSize = 16; // in bytes

            // Método que computa el hash a la clave según keyLength
            private static byte[] ComputeKeyHash(byte[] key, KeyLength keyLenght)
            {
                return keyLenght switch
                {
                    // Para AES-128
                    KeyLength.AES128 => HashingUtilities.MD5.ComputeBytes(key),
                    // Para AES-192
                    KeyLength.AES192 => HashingUtilities.TIGER192.ComputeBytes(key),
                    // Para AES-256
                    KeyLength.AES256 => HashingUtilities.SHA256.ComputeBytes(key),
                    // No calcula HASH a la clave, la devuelve sin cambios
                    KeyLength.AESRAW => key,
                    // Por defecto lanza excepción
                    _ => throw new InvalidOperationException("Invalid key length")
                };
            }

            // Método maestro que lleva a cabo una encriptación de un array de bytes usando el algoritmo de encriptación de clave simétrica AES
            private static byte[] DoEncrypt(byte[] clearBytes, byte[] key, CipherMode cipherMode = CipherMode.GCM, Padding padding = Padding.NoPadding, KeyLength keyLength = KeyLength.AES256)
            {
                // Instanciamos un nuevo SecureRandom
                SecureRandom random = new();

                // Generamos IV
                byte[] iv = random.GenerateSeed(AesIvSize);

                // Generamos parametros de llave
                ICipherParameters keyParameters = CreateKeyParameters(ComputeKeyHash(key, keyLength), iv, GcmTagSize * 8, cipherMode);

                // Recupera el cifrador AES según argumentos
                IBufferedCipher cipher = CipherUtilities.GetCipher($"AES/{cipherMode}/{padding}");

                // Inicializamos el cifrador en modo encriptación y con los parámetros de llave pasados como argumento
                cipher.Init(true, keyParameters);

                // Lleva a cabo la encriptación
                byte[] encryptedBytes = cipher.DoFinal(clearBytes);

                // Retorna los datos empaquetados
                return PackCipherData(encryptedBytes, iv, cipherMode, padding, keyLength);
            }

            // Método que lleva a cabo una encriptación de un array de bytes usando el algoritmo de encriptación de clave simétrica AES
            public static byte[] Encrypt(byte[] clearBytes, byte[] key, CipherMode cipherMode = CipherMode.GCM, Padding padding = Padding.NoPadding, KeyLength keyLength = KeyLength.AES256, bool debug = false)
            {
                // Resetea contador de tiempo transcurrido
                Utilities.Time.ResetElapsed();

                // Desencripta los datos
                byte[] encryptedData = DoEncrypt(clearBytes, key, cipherMode, padding, keyLength);

                // Escribe en log
                if (debug) { Debug.WriteLine(string.Format("Encryption of {0} successfull in {1}", Utilities.File.GetSizeFormatted(clearBytes.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds, true)), "AES Encryption"); }

                // Retorna los datos desencriptados
                return encryptedData;
            }

            // Método maestro que lleva a cabo la desencriptación de un array de bytes encriptados con el algoritmo de encriptación de clave simétrica AES
            private static byte[] DoDecrypt(byte[] dataBlock, byte[] key)
            {
                // Desempaqueta el bloque de datos
                (byte[] encryptedBytes, byte[] iv, byte tagSize, Padding padding, CipherMode cipherMode, KeyLength keyLength) = UnpackCipherData(dataBlock);

                // Creamos parámetros de llave
                ICipherParameters keyParameters = CreateKeyParameters(ComputeKeyHash(key, keyLength), iv, tagSize * 8, cipherMode);

                // Recupera el cifrador AES según argumentos
                IBufferedCipher cipher = CipherUtilities.GetCipher($"AES/{cipherMode}/{padding}");

                // Inicializamos el cifrador en modo desencriptación y con los parámetros de llave pasados como argumento
                cipher.Init(false, keyParameters);

                // Desencripta los datos
                byte[] decryptedData = cipher.DoFinal(encryptedBytes);

                // Retorna los datos desencriptados
                return decryptedData;
            }

            // Método que lleva a cabo la desencriptación de un array de bytes encriptados con el algoritmo de encriptación de clave simétrica AES
            public static byte[] Decrypt(byte[] dataBlock, byte[] key, bool debug = false)
            {
                // Resetea contador de tiempo transcurrido
                Utilities.Time.ResetElapsed();

                // Desencripta los datos
                byte[] decryptedData = DoDecrypt(dataBlock, key);

                // Escribe en log
                if (debug) { Debug.WriteLine(string.Format("Decryption of {0} successfull in {1}", Utilities.File.GetSizeFormatted(dataBlock.LongLength), Utilities.Time.GetElapsed(Utilities.Time.ElapsedUnit.Milliseconds, true)), "AES Decryption"); }

                // Retorna los datos desencriptados
                return decryptedData;
            }


            // Método que crea parámetros de encriptación AES
            private static ICipherParameters CreateKeyParameters(byte[] key, byte[] iv, int macSize, CipherMode cipherMode)
            {
                // Instanciamos un KeyParameter
                KeyParameter keyParameter = new(key);

                // Según el modo de cifrado
                return cipherMode switch
                {
                    // Modo de cifrado AES-CBC
                    CipherMode.CBC => new ParametersWithIV(keyParameter, iv),
                    // Modo de cifrado AES-CTR
                    CipherMode.CTR => new ParametersWithIV(keyParameter, iv),
                    // Modo de cifrado AES-GCM
                    CipherMode.GCM => new AeadParameters(keyParameter, macSize, iv),
                    // Modo no permitido
                    _ => throw new Exception("Unsupported cipher mode")
                };
            }

            // Método que empaqueta datos encriptados con AES
            private static byte[] PackCipherData(byte[] encryptedBytes, byte[] iv, CipherMode cipherMode, Padding padding, KeyLength keyLength)
            {
                // Define el tamaño de los datos
                long dataSize = encryptedBytes.LongLength + iv.LongLength + 4;

                // Si el modo de cifrado es 'GCM', incrementa en 1 su tamaño
                if (cipherMode == CipherMode.GCM) { dataSize += 1; }

                // Definimos un index para navegar por las posiciones del array
                long index = 0;
                
                // Instanciamos un nuevo array de bytes del tamaño del paquete de datos
                byte[] dataBlock = new byte[dataSize];

                // Escribe el Id del cipher mode en el primer byte
                dataBlock[index] = (byte)cipherMode;

                // Incrementa el índice
                index++;

                // Escribe el padding en el segundo byte
                dataBlock[index] = (byte)padding;

                // Incrementa el índice
                index++;

                // Escribe el keyLength en el tercer byte
                dataBlock[index] = (byte)keyLength;

                // Incrementa el índice
                index++;

                // El siguiente byte del array define el Iv Size
                dataBlock[index] = AesIvSize;

                // Incrementa el índice
                index++;

                // Si el modo de ficrado es GCM
                if (cipherMode == CipherMode.GCM)
                {
                    // El siguiente byte representa el GcmTagSize
                    dataBlock[index] = GcmTagSize;

                    // Incrementa el índice
                    index++;
                }

                // Copia los datos del array 'iv' al array del bloque de datos
                Array.Copy(iv, 0, dataBlock, index, iv.LongLength);

                // Incrementa el índice con el tamaño del array 'iv'
                index += iv.LongLength;

                // Copia los datos encriptados al array del bloque de datos
                Array.Copy(encryptedBytes, 0, dataBlock, index, encryptedBytes.LongLength);

                // Retorna el bloque de datos
                return dataBlock;
            }

            // Método que desempaqueta un bloque de datos AES
            private static (byte[], byte[], byte, Padding, CipherMode, KeyLength) UnpackCipherData(byte[] dataBlock)
            {
                // Se define un índice para navegar por las posiciones del array
                long index = 0;

                // Recupera el cipherMode
                CipherMode cipherMode = (CipherMode)Enum.ToObject(typeof(CipherMode), dataBlock[index]);

                // Incrementa el índice
                index++;

                // Recupera el padding
                Padding padding = (Padding)Enum.ToObject(typeof(Padding), dataBlock[index]);

                // Incrementa el índice
                index++;

                // Recupera el keyLength
                KeyLength keyLength = (KeyLength)Enum.ToObject(typeof(KeyLength), dataBlock[index]);

                // Incrementa el índice
                index++;

                // Recupera el ivSize
                byte ivSize = dataBlock[index];

                // Incrementa el índice
                index++;

                // Recupera el TagSize
                byte tagSize = 0;

                // Si el modo de ficrado es GCM
                if (cipherMode == CipherMode.GCM)
                {
                    // Recupera el tagSize del bloque de datos
                    tagSize = dataBlock[index];

                    // Incrementa el índice
                    index++;
                }

                // Instanciamos un nuevo array con el tamaño del IV
                byte[] iv = new byte[ivSize];

                // Copia los datos referentes al IV del bloque en el array 'iv'
                Array.Copy(dataBlock, index, iv, 0, ivSize);

                // Incrementa el índice con el tamaño del IV
                index += ivSize;

                // Instancia un nuevo array del tamaño total del bloque de datos menos el ínidce
                byte[] encryptedBytes = new byte[dataBlock.LongLength - index];

                // Copia los datos encriptados del bloque al array de retorno
                Array.Copy(dataBlock, index, encryptedBytes, 0, encryptedBytes.LongLength);

                // Retorna los el array con los datos encriptados, el array con el IV, el byte del tagSize, el padding, el cipherMode y el keyLength
                return (encryptedBytes, iv, tagSize, padding, cipherMode, keyLength);
            }
        }
    }
}
