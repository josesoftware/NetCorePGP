using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace NetCorePGP.Utilities
{
    /// <summary>
    /// Clase estática de utiliades en relación a ficheros
    /// </summary>
    public static class File
    {
        // Load all suffixes in an array  
        static readonly string[] suffixes ={ "Bytes", "KB", "MB", "GB", "TB", "PB" };
        public static string GetSizeFormatted(long bytes)
        {
            int counter = 0;
            decimal number = bytes;
            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }
            return string.Format("{0:n1} {1}", number, suffixes[counter]);
        }
    }

    /// <summary>
    /// Clase estática de utilidades en relación a fechas con soporte para operar con subprocesos
    /// </summary>
    public static class Time
    {
        /// <summary>
        /// Enumerado de unidades de tiempo disponibles
        /// </summary>
        public enum ElapsedUnit
        {
            Milliseconds,
            Seconds,
            Minutes,
            Hours,
            Days,
        }

        // Datetame que se usa para realizar calculos
        static readonly Dictionary<ushort, DateTime> _tick = new();

        /// <summary>
        /// Método que resetea el contador
        /// </summary>
        public static void ResetElapsed()
        {
            // Si no existen datos memorizados del pid, los memoriza y sale del método
            if (!_tick.ContainsKey((ushort)Environment.ProcessId)) { _tick.Add((ushort)Environment.ProcessId, DateTime.Now); return; }

            // Resetea el tick a la fecha y hora actual
            _tick[(ushort)Environment.ProcessId] = DateTime.Now;
        }

        /// <summary>
        /// Método que resetea el contador
        /// </summary>
        /// <param name="pid">Id del proceso que desea resetear el contador</param>
        public static void ResetElapsed(ushort pid)
        {
            // Si no existen datos memorizados del pid, los memoriza y sale del método
            if (!_tick.ContainsKey(pid)) { _tick.Add(pid, DateTime.Now); return; }

            // Resetea el tick a la fecha y hora actual
            _tick[pid] = DateTime.Now;
        }

        /// <summary>
        /// Método que devuelve el tiempo transcurrido en un intervalo
        /// </summary>
        /// <returns>TimeSpan con el tiempo transcurrido</returns>
        public static TimeSpan GetElapsed()
        {
            // Si no existen datos memorizados del pid, hace un reset
            if (!_tick.ContainsKey((ushort)Environment.ProcessId)) { ResetElapsed(); }

            // Retorna el tiempo transcurrido desde el último tick hasta ahora mismo
            return DateTime.Now - _tick[(ushort)Environment.ProcessId];
        }

        /// <summary>
        /// Método que devuelve el tiempo transcurrido en un intervalo
        /// </summary>
        /// <param name="pid">Id del proceso que desea resetear el contador</param>
        /// <returns>TimeSpan con el tiempo transcurrido</returns>
        public static TimeSpan GetElapsed(ushort pid)
        {
            // Si no existen datos memorizados del pid, hace un reset
            if (!_tick.ContainsKey(pid)) { ResetElapsed(pid); }

            // Retorna el tiempo transcurrido desde el último tick hasta ahora mismo
            return DateTime.Now - _tick[pid];
        }

        /// <summary>
        /// Método que devuelve el tiempo transcurrido en un intervalo en un string formateado
        /// </summary>
        /// <param name="unit"></param>
        /// <param name="isTotalUnits"></param>
        /// <returns>String con el tiempo transcurrido formateado</returns>
        public static string GetElapsed(ElapsedUnit unit, bool isTotalUnits = false)
        {
            // Si no existen datos memorizados del pid, hace un reset
            if (!_tick.ContainsKey((ushort)Environment.ProcessId)) { ResetElapsed(); }

            // Definimos un double para calcular unidades transcurridas
            double elapsedUnits;

            // Realizamos un switch en función de la unidad que desamos exportar
            switch (unit)
            {
                default:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[(ushort)Environment.ProcessId]).Seconds : (DateTime.Now - _tick[(ushort)Environment.ProcessId]).Seconds;

                    // Retorna el texto formateado
                    return string.Format("{0} sec", elapsedUnits);
                case ElapsedUnit.Milliseconds:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[(ushort)Environment.ProcessId]).TotalMilliseconds : (DateTime.Now - _tick[(ushort)Environment.ProcessId]).Milliseconds;

                    // Retorna el texto formateado
                    return string.Format("{0} ms",  Math.Round(elapsedUnits, 0));
                case ElapsedUnit.Minutes:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[(ushort)Environment.ProcessId]).TotalMinutes : (DateTime.Now - _tick[(ushort)Environment.ProcessId]).Minutes;

                    // Retorna el texto formateado
                    return string.Format("{0} min", elapsedUnits);
                case ElapsedUnit.Hours:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[(ushort)Environment.ProcessId]).TotalHours : (DateTime.Now - _tick[(ushort)Environment.ProcessId]).Hours;

                    // Retorna el texto formateado
                    return string.Format("{0} hour", elapsedUnits);
                case ElapsedUnit.Days:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[(ushort)Environment.ProcessId]).TotalDays : (DateTime.Now - _tick[(ushort)Environment.ProcessId]).Days;

                    // Retorna el texto formateado
                    return string.Format("{0} day", elapsedUnits);
            }
        }

        /// <summary>
        /// Método que devuelve el tiempo transcurrido en un intervalo en un string formateado
        /// </summary>
        /// <param name="unit">Unidad de tiempo que se desea exportar a texto</param>
        /// <param name="pid">Id del proceso que desea resetear el contador</param>
        /// <param name="isTotalUnits">True: Exportará todo el acumulado en la unidad de tiempo especificada</param>
        /// <returns>String con el tiempo transcurrido formateado</returns>
        public static string GetElapsed(ElapsedUnit unit, ushort pid, bool isTotalUnits = false)
        {
            // Si no existen datos memorizados del pid, hace un reset
            if (!_tick.ContainsKey(pid)) { ResetElapsed(pid); }

            // Definimos un double para calcular unidades transcurridas
            double elapsedUnits;

            // Realizamos un switch en función de la unidad que desamos exportar
            switch (unit)
            {
                default:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[pid]).Seconds : (DateTime.Now - _tick[pid]).Seconds;

                    // Retorna el texto formateado
                    return string.Format("{0} sec", elapsedUnits);
                case ElapsedUnit.Milliseconds:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[pid]).TotalMilliseconds : (DateTime.Now - _tick[pid]).Milliseconds;

                    // Retorna el texto formateado
                    return string.Format("{0} ms", elapsedUnits);
                case ElapsedUnit.Minutes:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[pid]).TotalMinutes : (DateTime.Now - _tick[pid]).Minutes;

                    // Retorna el texto formateado
                    return string.Format("{0} min", elapsedUnits);
                case ElapsedUnit.Hours:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[pid]).TotalHours : (DateTime.Now - _tick[pid]).Hours;

                    // Retorna el texto formateado
                    return string.Format("{0} hour", elapsedUnits);
                case ElapsedUnit.Days:
                    // Calcula las unidades de tiempo transcurridas
                    elapsedUnits = isTotalUnits ? (DateTime.Now - _tick[pid]).TotalDays : (DateTime.Now - _tick[pid]).Days;

                    // Retorna el texto formateado
                    return string.Format("{0} day", elapsedUnits);
            }
        }

        /// <summary>
        /// Método que devuelve el tiempo transcurrido en un intervalo en un string formateado
        /// </summary>
        /// <param name="format">Formato de exportación a texto</param>
        /// <param name="pid">Id del proceso que desea resetear el contador</param>
        /// <param name="isTotalUnits">True: Exportará el total por unidad de tiempo basandose en el formato de exportación</param>
        /// <returns>String con el tiempo transcurrido formateado</returns>
        public static string GetElapsed(string format, bool isTotalUnits = false)
        {
            // Si no existen datos memorizados del pid, hace un reset
            if (!_tick.ContainsKey((ushort)Environment.ProcessId)) { ResetElapsed(); }

            // Recuperamos el tiempo transcurrido entre 
            TimeSpan elapsedTime = DateTime.Now - _tick[(ushort)Environment.ProcessId];

            // Si no se desean exportar las unidades totales
            if (!isTotalUnits) { return elapsedTime.ToString(format); }

            // Reemplaza el formato por las unidades de tiempo
            if (format.Contains('d'))
            { format = format.Replace("d", Math.Truncate(elapsedTime.TotalDays).ToString()); }
            if (format.Contains("hh")) 
            { format = format.Replace("hh", Math.Truncate(elapsedTime.TotalHours).ToString()); }
            if (format.Contains("mm")) 
            { format = format.Replace("mm", Math.Truncate(elapsedTime.TotalMinutes).ToString()); }
            if (format.Contains("ss")) 
            { format = format.Replace("ss", Math.Truncate(elapsedTime.TotalSeconds).ToString()); }
            if (format.Contains("fffffff")) 
            { format = format.Replace("fffffff", Math.Truncate(elapsedTime.TotalMilliseconds).ToString()); }

            // Retorna el formato con los valores
            return format.Replace("\\", "");
        }

        /// <summary>
        /// Método que devuelve el tiempo transcurrido en un intervalo en un string formateado
        /// </summary>
        /// <param name="format">Formato de exportación a texto</param>
        /// <param name="pid">Id del proceso que desea resetear el contador</param>
        /// <param name="isTotalUnits">True: Exportará el total por unidad de tiempo basandose en el formato de exportación</param>
        /// <returns>String con el tiempo transcurrido formateado</returns>
        public static string GetElapsed(string format, ushort pid, bool isTotalUnits = false)
        {
            // Si no existen datos memorizados del pid, hace un reset
            if (!_tick.ContainsKey(pid)) { ResetElapsed(pid); }

            // Recuperamos el tiempo transcurrido entre 
            TimeSpan elapsedTime = DateTime.Now - _tick[pid];

            // Si no se desean exportar las unidades totales
            if (!isTotalUnits) { return elapsedTime.ToString(format); }

            // Reemplaza el formato por las unidades de tiempo
            if (format.Contains('d'))
            { format = format.Replace("d", Math.Truncate(elapsedTime.TotalDays).ToString()); }
            if (format.Contains("hh"))
            { format = format.Replace("hh", Math.Truncate(elapsedTime.TotalHours).ToString()); }
            if (format.Contains("mm"))
            { format = format.Replace("mm", Math.Truncate(elapsedTime.TotalMinutes).ToString()); }
            if (format.Contains("ss"))
            { format = format.Replace("ss", Math.Truncate(elapsedTime.TotalSeconds).ToString()); }
            if (format.Contains("fffffff"))
            { format = format.Replace("fffffff", Math.Truncate(elapsedTime.TotalMilliseconds).ToString()); }

            // Retorna el formato con los valores
            return format.Replace("\\", "");
        }
    
        /// <summary>
        /// Método que limpia datos memorizados de un proceso para evitar sobrecargas de memoria
        /// </summary>
        public static void Flush()
        {
            // Elimina los datos
            _tick.Remove((ushort)Environment.ProcessId);
        }

        /// <summary>
        /// Método que limpia datos memorizados de un proceso para evitar sobrecargas de memoria
        /// </summary>
        /// <param name="pid">Id del proceso que desea resetear el contador</param>
        public static void Flush(ushort pid)
        {
            // Elimina los datos
            _tick.Remove(pid);
        }

        /// <summary>
        /// Método que limpia datos memorizados de todos los procesos para evitar sobrecargas de memoria
        /// </summary>
        public static void FlushAll()
        {
            // Elimina todos los datos
            _tick.Clear();
        }
    }

    public static class Array
    {
        // Método que recupera un fragmento concreto de un array de bytes con iteración finita
        public static byte[] GetByteArrayFragment(long skip, long take, byte[] byteArray)
        {
            // Prepara lista de bytes de retorno
            List<byte> _return = new List<byte>();

            // Siempre que no se vayan a ignorar más bytes de los que contiene el array original
            if (skip < byteArray.LongLength)
            {
                // Computa el fin de ciclo
                long _lastCycle = Mathematics.Clamp(skip + take, 1, byteArray.LongLength);

                // Recorre lista de bytes
                for (long i = skip; i < _lastCycle; i++)
                {
                    // Añade el byte al resultado
                    _return.Add(byteArray[i]);
                }
            }

            // Retorna lista de datos
            return _return.ToArray();
        }

        // Método que recupera un fragmento concreto de un array de bytes sin iteración finita
        public static byte[] GetByteArrayFragment(long skip, byte[] byteArray)
        {
            // Prepara lista de bytes de retorno
            List<byte> _return = new List<byte>();

            // Siempre que no se vayan a ignorar más bytes de los que contiene el array original
            if (skip < byteArray.LongLength)
            {
                // Recorre lista de bytes
                for (long i = skip; i < byteArray.LongLength; i++)
                {
                    // Añade el byte al resultado
                    _return.Add(byteArray[i]);
                }
            }

            // Retorna lista de datos
            return _return.ToArray();
        }

    }

    public static class Strings
    {
        public static char GetSecureStringChar(SecureString value, int idx)
        {
            IntPtr bstr = Marshal.SecureStringToBSTR(value);
            try
            {
                // Index in 2-byte (char) chunks
                //TODO: Some range validation might be good.
                return (char)Marshal.ReadByte(bstr, idx * 2);
            }
            finally
            {
                Marshal.FreeBSTR(bstr);
            }
        }

        public static char[] SecureStringToCharArray(SecureString value)
        {
            if (value == null) { return null; }

            List<char> _return = new();

            for (int i = 0; i < value.Length; i++)
            {
                _return.Add(GetSecureStringChar(value, i));
            }

            return _return.ToArray();
        }
    }

    public static class Mathematics
    {
        // Función matemática Clamp
        public static T Clamp<T>(this T val, T min, T max) where T : IComparable<T>
        {
            if (val.CompareTo(min) < 0) return min;
            else if (val.CompareTo(max) > 0) return max;
            else return val;
        }

    }
}
