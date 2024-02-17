using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace NetCorePGP
{
    public static class HashingUtilities
    {
        public static class CRC24
        {
            public static int ComputeBytes(byte[] inner)
            {
                Crc24 crc = new();

                // Recorre cada byte
                foreach(byte b in inner) 
                {
                    // Actualiza el CRC
                    crc.Update(b);
                }

                // Retorna el hash
                return crc.Value;
            }
            public static int ComputeString(string innerString)
            {
                // Convierte el string en bytes y lo computa
                return ComputeBytes(Encoding.UTF8.GetBytes(innerString));
            }
        }

        public static class SHA512
        {
            public static byte[] ComputeBytes(byte[] inner)
            {
                // Prepara el digest
                Sha512Digest longDigest = new();

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                byte[] TheHash = new byte[longDigest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                longDigest.BlockUpdate(inner, 0, inner.Length);

                // Almacena el hash en el array
                longDigest.DoFinal(TheHash, 0);

                // Retorna el hash
                return TheHash;
            }

            public static string ParseString(byte[] innerHash, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in innerHash)
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeBytesToString(byte[] inner, bool uppercase = false)
            {
                // Computa el hash y hace un parse a string
                string hashString = ParseString(ComputeBytes(inner), uppercase);

                // Retorna el string obtenido
                return !uppercase ? hashString.ToLower() : hashString.ToUpper();
            }

            public static string ComputeStringToString(string inner, bool uppercase = false)
            {
                // Retorna el string obtenido
                return ComputeBytesToString(Encoding.UTF8.GetBytes(inner), uppercase);
            }
        }

        public static class SHA384
        {
            public static byte[] ComputeBytes(byte[] inner)
            {
                // Prepara el digest
                Sha384Digest longDigest = new();

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                byte[] TheHash = new byte[longDigest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                longDigest.BlockUpdate(inner, 0, inner.Length);

                // Almacena el hash en el array
                longDigest.DoFinal(TheHash, 0);

                // Retorna el hash
                return TheHash;
            }
            public static string ParseString(byte[] innerHash, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in innerHash)
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeBytesToString(byte[] inner, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in ComputeBytes(inner))
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeStringToString(string inner, bool uppercase = false)
            {
                // Retorna el string obtenido
                return ComputeBytesToString(Encoding.UTF8.GetBytes(inner), uppercase);
            }
        }

        public static class SHA256
        {
            public static byte[] ComputeBytes(byte[] inner)
            {
                // Prepara el digest
                Sha256Digest digest = new();

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                byte[] TheHash = new byte[digest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                digest.BlockUpdate(inner, 0, inner.Length);

                // Almacena el hash en el array
                digest.DoFinal(TheHash, 0);

                // Retorna el hash
                return TheHash;
            }
            public static string ParseString(byte[] innerHash, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in innerHash)
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeBytesToString(byte[] inner, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in ComputeBytes(inner))
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeStringToString(string inner, bool uppercase = false)
            {
                // Retorna el string obtenido
                return ComputeBytesToString(Encoding.UTF8.GetBytes(inner), uppercase);
            }
        }

        public static class SHA224
        {
            public static byte[] ComputeBytes(byte[] inner)
            {
                // Prepara el digest
                Sha224Digest digest = new();

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                byte[] TheHash = new byte[digest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                digest.BlockUpdate(inner, 0, inner.Length);

                // Almacena el hash en el array
                digest.DoFinal(TheHash, 0);

                // Retorna el hash
                return TheHash;
            }
            public static string ParseString(byte[] innerHash, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in innerHash)
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeBytesToString(byte[] inner, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in ComputeBytes(inner))
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeStringToString(string inner, bool uppercase = false)
            {
                // Retorna el string obtenido
                return ComputeBytesToString(Encoding.UTF8.GetBytes(inner), uppercase);
            }
        }

        public static class SHA1
        {
            public static byte[] ComputeBytes(byte[] inner)
            {
                // Prepara el digest
                Sha1Digest digest = new();

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                byte[] TheHash = new byte[digest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                digest.BlockUpdate(inner, 0, inner.Length);

                // Almacena el hash en el array
                digest.DoFinal(TheHash, 0);

                // Retorna el hash
                return TheHash;
            }
            public static string ParseString(byte[] innerHash, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in innerHash)
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeBytesToString(byte[] inner, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in ComputeBytes(inner))
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeStringToString(string inner, bool uppercase = false)
            {
                // Retorna el string obtenido
                return ComputeBytesToString(Encoding.UTF8.GetBytes(inner), uppercase);
            }
        }

        public static class MD5
        {
            public static byte[] ComputeBytes(byte[] inner)
            {
                // Prepara el digest
                MD5Digest digest = new();

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                byte[] TheHash = new byte[digest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                digest.BlockUpdate(inner, 0, inner.Length);

                // Almacena el hash en el array
                digest.DoFinal(TheHash, 0);

                // Retorna el hash
                return TheHash;
            }
            public static string ParseString(byte[] innerHash, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in innerHash)
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeBytesToString(byte[] inner, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in ComputeBytes(inner))
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeStringToString(string inner, bool uppercase = false)
            {
                // Retorna el string obtenido
                return ComputeBytesToString(Encoding.UTF8.GetBytes(inner), uppercase);
            }
        }
        
        public static class TIGER192
        {
            public static byte[] ComputeBytes(byte[] inner)
            {
                // Prepara el digest
                TigerDigest digest = new();

                // Dimensionamos el array del hash según el tamaño de salida del Digest
                byte[] TheHash = new byte[digest.GetDigestSize()];

                // Computa el hash usando el algoritmo del Digest
                digest.BlockUpdate(inner, 0, inner.Length);

                // Almacena el hash en el array
                digest.DoFinal(TheHash, 0);

                // Retorna el hash
                return TheHash;
            }
            public static string ParseString(byte[] innerHash, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in innerHash)
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeBytesToString(byte[] inner, bool uppercase = false)
            {
                // Instanciamos un stringBuilder
                StringBuilder sb = new();

                // Recorremos cada byte del hash obtenido de los datos
                foreach (byte B in ComputeBytes(inner))
                {
                    // Concatena el byte en formato hexadecimal al string
                    sb.Append(B.ToString("x2"));
                }

                // Retorna el string obtenido
                return !uppercase ? sb.ToString().ToLower() : sb.ToString().ToUpper();
            }

            public static string ComputeStringToString(string inner, bool uppercase = false)
            {
                // Retorna el string obtenido
                return ComputeBytesToString(Encoding.UTF8.GetBytes(inner), uppercase);
            }
        }
    }
}
