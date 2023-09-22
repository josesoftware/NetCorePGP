using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text.RegularExpressions;

namespace NetCorePGP
{
    public static class Passphrase
    {
        public abstract class PatternSolidity
        {
            public const int Negligent = 0;
            public const int AllowNumericSecuences = 1;
            public const int AllowDates = 2;
            public const int AllowCharacterSequece = 4;
            public const int PriorizeNonPattern = 16;
        }

        public abstract class LengthSolidity
        {
            public const int Negligent = -1;
            public const int Minimal = 4;
            public const int Secure = 8;
            public const int VerySecure = 16;
            public const int Hard = 32;
            public const int VeryHard = 64;
            public const int Extreme = 128;
            public const int Absolute = 256;
            public static int Custom = Secure;
        }

        private abstract class CharacterSolidity
        {
            private static readonly char[] LOWER_ALPHABET = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'ñ', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            private static readonly char[] UPPER_ALPHABET = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'Ñ', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            private static readonly char[] NUMBERS = { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };
            private static readonly char[] SYMBOLS = { '=', '+', '-', '*', '/', '\\', '@', '$', '&', '_', '.', '<', '>', '#', '(', ')' };

            public static readonly char[] Negligent = null;
            public static char[] Alphabetical => LOWER_ALPHABET.Concat(UPPER_ALPHABET).ToArray();
            public static char[] LowerAlphabetical => LOWER_ALPHABET.ToArray();
            public static char[] UpperAlphabetical => UPPER_ALPHABET.ToArray();
            public static char[] Numerical => NUMBERS.ToArray();
            public static char[] Alphanumerical => Alphabetical.Concat(NUMBERS).ToArray();
            public static char[] LowerAlphanumerical => LOWER_ALPHABET.Concat(NUMBERS).ToArray();
            public static char[] UpperAlphanumerical => UPPER_ALPHABET.Concat(NUMBERS).ToArray();
            public static char[] SpecialChars => SYMBOLS.ToArray();
            public static char[] AlphanumericalWithSpecialChars => Alphanumerical.Concat(SYMBOLS).ToArray();
            public static char[] LowerAlphanumericalWithSpecialChars => LowerAlphanumerical.Concat(SYMBOLS).ToArray();
            public static char[] UpperAlphanumericalWithSpecialChars => UpperAlphanumerical.Concat(SYMBOLS).ToArray();
            public static char[] NumericalWithSpecialChars => Numerical.Concat(SYMBOLS).ToArray();
            public static char[] AlphabeticalWithSpecialChars => Alphabetical.Concat(SYMBOLS).ToArray();
            public static char[] LowerAlphabeticalWithSpecialChars => LowerAlphabetical.Concat(SYMBOLS).ToArray();
            public static char[] UpperAlphabeticalWithSpecialChars => UpperAlphabetical.Concat(SYMBOLS).ToArray();
        }

        const int SEQUENCE_TARGET = 3;

        private static readonly Dictionary<CharSolidity, char[]> charAllowdPerSolidity = new()
        {
            { CharSolidity.Alphabetical, CharacterSolidity.Alphabetical },
            { CharSolidity.LowerAlphabetical, CharacterSolidity.LowerAlphabetical },
            { CharSolidity.UpperAlphabetical, CharacterSolidity.UpperAlphabetical },
            { CharSolidity.Numerical, CharacterSolidity.Numerical },
            { CharSolidity.Alphanumerical, CharacterSolidity.Alphanumerical },
            { CharSolidity.LowerAlphanumerical, CharacterSolidity.LowerAlphanumerical },
            { CharSolidity.UpperAlphanumerical, CharacterSolidity.UpperAlphanumerical },
            { CharSolidity.SpecialChars, CharacterSolidity.SpecialChars },
            { CharSolidity.AlphanumericWithSpecialChars, CharacterSolidity.AlphanumericalWithSpecialChars },
            { CharSolidity.LowerAlphanumericWithSpecialChars, CharacterSolidity.LowerAlphanumericalWithSpecialChars },
            { CharSolidity.UpperAlphanumericWithSpecialChars, CharacterSolidity.UpperAlphanumericalWithSpecialChars },
            { CharSolidity.AlphabeticalWithSpecialChars, CharacterSolidity.AlphabeticalWithSpecialChars },
            { CharSolidity.LowerAlphabeticalWithSpecialChars, CharacterSolidity.LowerAlphabeticalWithSpecialChars },
            { CharSolidity.UpperAlphabeticalWithSpecialChars, CharacterSolidity.UpperAlphabeticalWithSpecialChars },
            { CharSolidity.NumericalWithSpecialChars, CharacterSolidity.NumericalWithSpecialChars },
        };

        public enum CharSolidity
        {
            Negligent = 0,
            Numerical = 1,
            LowerAlphabetical = 2,
            UpperAlphabetical = 3,
            Alphabetical = 4,
            LowerAlphanumerical = 5,
            UpperAlphanumerical = 6,
            Alphanumerical = 7,
            SpecialChars = 8,
            NumericalWithSpecialChars = 9,
            LowerAlphabeticalWithSpecialChars = 10,
            UpperAlphabeticalWithSpecialChars = 11,
            AlphabeticalWithSpecialChars = 12,
            LowerAlphanumericWithSpecialChars = 13,
            UpperAlphanumericWithSpecialChars = 14,
            AlphanumericWithSpecialChars = 15

        }

        private static CharSolidity minimumCharRequired = CharSolidity.AlphanumericWithSpecialChars;
        private static CharSolidity maximumCharAllowed = CharSolidity.AlphanumericWithSpecialChars;
        private static int patternSolidity = PatternSolidity.PriorizeNonPattern;
        private static int minimumLengthRequired = LengthSolidity.Secure;
        private static int maximumLengthAllowed = LengthSolidity.Absolute;

        public static CharSolidity MinimumCharacterSolidityRequired { get => minimumCharRequired; set { minimumCharRequired = (value <= maximumCharAllowed) ? value : throw new InvalidOperationException("The maximum character solidity cannot be less reliable than minimum required."); } }
        public static CharSolidity MaximumCharacterSolidityAllowed { get => maximumCharAllowed; set { maximumCharAllowed = (value >= minimumCharRequired) ? value : throw new InvalidOperationException("The maximum character solidity cannot be less reliable than minimum required."); } }
        public static int MinimumLengthSolidityRequired { get => minimumLengthRequired; set { minimumLengthRequired = (value <= maximumLengthAllowed) ? value : throw new InvalidOperationException("Maximum length allowed cannot be less than minimum required."); } }
        public static int MaximumLengthSolidityAllowed { get => maximumLengthAllowed; set { maximumLengthAllowed = (value >= minimumLengthRequired) ? value : throw new InvalidOperationException("Maximum length allowed cannot be less than minimum required."); } }
        public static int PatternSolidityLevel { get => patternSolidity; set { patternSolidity = value; } }

        public static bool Equal(SecureString s1, SecureString s2)
        {
            // Si alguno de los dos viene nulo, sale con falso
            if (s1 == null || s2 == null) { return false; }

            // Si s2 mide menos que s1
            if (s1.Length != s2.Length) { return false; }

            // Recore los caracteres del secure string
            for (int i = 0; i < s1.Length; i++)
            {
                // Si no concuerda un character, sale con falso
                if (Utilities.Strings.GetSecureStringChar(s1, i) != Utilities.Strings.GetSecureStringChar(s2, i)) { return false; }
            }

            // Retorna verdadero por defecto
            return true;
        }

        public static void Validate(char[] passphrase, int patternSolidity, int minimumLengthSolidity, int maximumLengthAllowed, CharSolidity minimumCharSolidity, CharSolidity maximumCharSolidity)
        {
            // Comprueba que la longitud del passphrase supera el nivel de solidez de longitud
            CheckPassphraseLength(passphrase, minimumLengthSolidity, maximumLengthAllowed);

            // Comprueba que los caracteres que componen el passphrase superan el nivel de solidez de caracteres
            CheckPassphraseChar(passphrase, minimumCharSolidity, maximumCharSolidity);

            // Comprueba que los caracteres que componen el passphrase superan el nivel de solidez de patrones
            ChackPassphrasePattern(passphrase, patternSolidity);
        }

        public static void Validate(SecureString passphrase, int patternSolidity, int minimumLengthSolidity, int maximumLengthAllowed, CharSolidity minimumCharSolidity, CharSolidity maximumCharSolidity)
        {
            List<char> _passphrase = new();

            for (int i = 0; i < passphrase.Length; i++)
            {
                _passphrase.Add(Utilities.Strings.GetSecureStringChar(passphrase, i));
            }

            // Invoca al método maestro
            Validate(_passphrase.ToArray(), patternSolidity, minimumLengthSolidity, maximumLengthAllowed, minimumCharSolidity, maximumCharSolidity);
        }

        public static void Validate(SecureString passphrase)
        {
            List<char> _passphrase = new();

            for(int i = 0; i < passphrase.Length; i++)
            {
                _passphrase.Add(Utilities.Strings.GetSecureStringChar(passphrase, i));
            }

            // Invoca al método maestro
            Validate(_passphrase.ToArray());
        }

        public static void Validate(char[] passphrase)
        {
            // Comprueba que la longitud del passphrase supera el nivel de solidez de longitud
            CheckPassphraseLength(passphrase, minimumLengthRequired, maximumLengthAllowed);

            // Comprueba que los caracteres que componen el passphrase superan el nivel de solidez de caracteres
            CheckPassphraseChar(passphrase, minimumCharRequired, maximumCharAllowed);

            // Comprueba que los caracteres que componen el passphrase superan el nivel de solidez de patrones
            ChackPassphrasePattern(passphrase, patternSolidity);
        }

        private static bool FindDateInCharArray(char[] inputArray)
        {
            // Declaramos un string para concatenar caracteres
            string concatArray = string.Concat(inputArray);

            // Declaramos patrones permitidos de fecha
            string[] datePatterns = {
                @"\d{2}-\d{2}-\d{4}", @"\d{1}-\d{2}-\d{4}", @"\d{2}-\d{1}-\d{4}", @"\d{1}-\d{1}-\d{4}", @"\d{2}-\d{2}-\d{2}", @"\d{1}-\d{2}-\d{2}", @"\d{2}-\d{1}-\d{2}", @"\d{1}-\d{1}-\d{2}",
                @"\d{2}/\d{2}/\d{4}", @"\d{1}/\d{2}/\d{4}", @"\d{2}/\d{1}/\d{4}", @"\d{1}/\d{1}/\d{4}", @"\d{2}/\d{2}/\d{2}", @"\d{1}/\d{2}/\d{2}", @"\d{2}/\d{1}/\d{2}", @"\d{1}/\d{1}/\d{2}",
                @"\d{6}", @"\d{8}"
            };

            // Itera los patrones de busqueda de fecha
            foreach (string datePattern in datePatterns)
            {
                // Instancia un Regex con el patrón iterado
                Regex rgx = new(datePattern);

                // Instanciamos un Match basado en el Regex recién instanciado 
                Match mat = rgx.Match(concatArray);

                // Si no encuentra el patrón, pasa al siguente
                if (!mat.Success) { continue; }

                // Memoriza el texto que del patrón encontrado
                string detected = mat.ToString();

                // Declaramos buleano de retorno
                bool _return = false;

                // Si patrón encontrado no contiene caracteres de separación de fecha
                if (!detected.Contains('/') && !detected.Contains('-'))
                {
                    // Se hace una selección por tamaño de resultado
                    switch (detected.Length)
                    {
                        // Añade separadores de fecha al candidato a fecha y comprueba si puede hacer o no el parse
                        case 6: return DateTime.TryParse(detected.Insert(2, "/").Insert(5, "/"), out DateTime _);

                        // Añade separadores de fecha al candidato a fecha y comprueba si puede hacer o no el parse
                        case 8: return DateTime.TryParse(detected.Insert(2, "/").Insert(5, "/"), out DateTime _) | DateTime.TryParse(detected.Insert(4, "/").Insert(7, "/"), out DateTime _);
                    }
                }

                // Sale con el buleano de retorno
                return _return;
            }

            // Sale como false por defecto
            return false;
        }

        private static bool FindNumericSequenceInCharArray(char[] inputArray)
        {
            // Declaramos un entero para memorizar último dígito
            double lastDigit = -1;

            // Declaramos un contador de secuencia
            byte sequenceCounter = 0;

            // Iteramos cada caracter del array
            foreach (char ch in inputArray)
            {
                // Si el caracter no es un dígito sale del método
                if (!char.IsDigit(ch))
                {
                    // Reinicia el contador
                    sequenceCounter = 0;

                    // Reinicia el lastDigit
                    lastDigit = -1;

                    // Pasa de ciclo
                    continue;
                }

                // Si el último dígito memorizado es positivo
                if (lastDigit >= 0)
                {
                    // Recorre todas las secuencias posible
                    for (byte i = 1; i <= 2; i++)
                    {
                        // Si el digito actual es igual al digito anterior + clave de secuencia
                        if (char.GetNumericValue(ch) == lastDigit + i)
                        {
                            // Incrementa el contador de secuencia
                            sequenceCounter++;
                        }
                    }
                }

                // Si el contador de secuencia llega al target retorna true indicando que se ha detectado una secuencia
                if (sequenceCounter == SEQUENCE_TARGET) { return true; }

                // Memoriza el último dígito
                lastDigit = char.GetNumericValue(ch);
            }

            // Retorna falso por defecto
            return false;
        }

        private static bool FindCharSequenceInCharArray(char[] inputArray)
        {
            // Declaramos un caracter para memorizar el ultimo caracter iterado
            char lastChar = char.MinValue;

            // Declaramos un contador de secuencia
            byte sequenceCounter = 0;

            // Iteramos cada caracter del array
            foreach (char ch in inputArray)
            {
                // Si el caracter que se esta iterando es el mismo que el anterior, se incrementa el contador de secuencia
                if (ch == lastChar) { sequenceCounter++; }

                // Si el contador de secuencia llega al target retorna true indicando que se ha detectado una secuencia
                if (sequenceCounter == SEQUENCE_TARGET) { return true; }

                // Memoriza el último caracter
                lastChar = ch;
            }

            // Retorna falso por defecto
            return false;
        }

        private static void ChackPassphrasePattern(char[] passphrase, int passphraseSolidity)
        {
            // Se hace una seleccion por solidez de passphrase
            switch (passphraseSolidity)
            {
                // Negligente, sale directamente sin errores
                case PatternSolidity.Negligent: return;

                // Por defecto interpreta la opción de Evitar patrones, sale sin errores si no se detectan secuencias o fechas
                default: if (!FindCharSequenceInCharArray(passphrase) && !FindDateInCharArray(passphrase) && !FindNumericSequenceInCharArray(passphrase)) { return; } break;

                // Permitir fechas, sale sin errores si detecta una fecha pero no detecta secuencias
                case PatternSolidity.AllowDates: if (!FindCharSequenceInCharArray(passphrase) && FindDateInCharArray(passphrase) && !FindNumericSequenceInCharArray(passphrase)) { return; } break;

                // Permitir fechas y secuencias numericas, sale sin errores si detecta una fecha o una secuencia numerica pero no detectan secuencias de caracteres
                case PatternSolidity.AllowDates | PatternSolidity.AllowNumericSecuences: if (!FindCharSequenceInCharArray(passphrase) && (FindDateInCharArray(passphrase) || FindNumericSequenceInCharArray(passphrase))) { return; } break;

                // Permitir fechas y secuencias de caracteres, sale sin errores si detecta una fecha o una secuencia de caracteres pero no detectan secuencias numericas
                case PatternSolidity.AllowDates | PatternSolidity.AllowCharacterSequece: if ((FindCharSequenceInCharArray(passphrase) || FindDateInCharArray(passphrase)) && !FindNumericSequenceInCharArray(passphrase)) { return; } break;

                // Permitir secuencias numericas, sale sin error cuando se detecta una secuencia numerica pero no se detectan secuencias de caracteres o fechas
                case PatternSolidity.AllowNumericSecuences: if (!FindCharSequenceInCharArray(passphrase) && !FindDateInCharArray(passphrase) && FindNumericSequenceInCharArray(passphrase)) { return; } break;

                // Permitir secuencias numericas o de caracteres, sale sin error cuando se detecta una secuencia pero no se detectan fechas
                case PatternSolidity.AllowNumericSecuences | PatternSolidity.AllowCharacterSequece: if ((FindCharSequenceInCharArray(passphrase) || FindNumericSequenceInCharArray(passphrase)) && !FindDateInCharArray(passphrase)) { return; } break;

                // Permitir secuencias de caracteres, sale sin error cuando se detecta una secuencia de caracteres pero no se detectan secuencias numericas o fechas
                case PatternSolidity.AllowCharacterSequece: if (FindCharSequenceInCharArray(passphrase) && !FindDateInCharArray(passphrase) && !FindNumericSequenceInCharArray(passphrase)) { return; } break;

                // Permitir secuencias y fechas, sale sin errores cuando se detectan fechas o secuencias
                case PatternSolidity.AllowNumericSecuences | PatternSolidity.AllowCharacterSequece | PatternSolidity.AllowDates: if (FindCharSequenceInCharArray(passphrase) || FindNumericSequenceInCharArray(passphrase) || FindDateInCharArray(passphrase)) { return; } break;
            }

            // Lanza excepción de patrón ilegal encontrado
            throw new ArgumentException("Detected an ilegal pattern. Passphrase does not meet the solidity requirements.");
        }

        private static bool CheckAllowedCharsInArray(char[] inputArray, char[] allowedChars, bool isSearching = false)
        {
            // Itera cada caracter del passphrase
            for (int i = 0; i < inputArray.Length; i++)
            {
                // Si la baliza 'isSearching' esta marcada como 'True'
                if (isSearching)
                {
                    // Si el caracter existe en la lista de permitidos, sale con 'True'
                    if (allowedChars.Contains(inputArray[i])) { return true; }
                    // Si el caracter no existe en la lista de permitidos y es el último ciclo, sale con false
                    else if (!allowedChars.Contains(inputArray[i]) && (i + 1) == inputArray.Length) { return false; }

                    // Pasa de ciclo
                    continue;
                }

                // Si el caracter no existe en la lista de permitidos, sale con 'False'
                if (!allowedChars.Contains(inputArray[i])) { return false; }
            }

            // Sale con 'True'
            return true;
        }

        private static void CheckPassphraseChar(char[] passphrase, CharSolidity passphraseSolidityMinimal, CharSolidity passphraseSolidityMaximum)
        {
            // Si esta activado el caso negligente, sale del metodo directamente
            if (passphraseSolidityMinimal == CharSolidity.Negligent) { return; }

            // Si el nivel de solidez mínimo es mas exigente que el máximo, lanzará error de operación inválida
            if ((int)passphraseSolidityMinimal > (int)passphraseSolidityMaximum) { throw new InvalidOperationException("The maximum character solidity cannot be less reliable than minimum required."); }

            // Si el passphrase tiene algun caracter no valido segun el nivel maximo de solidez, lanza excepcion
            if (!CheckAllowedCharsInArray(passphrase, charAllowdPerSolidity[passphraseSolidityMaximum])) { throw new ArgumentException("Ilegal character founded. The passphrase does not meet the maximum solidity requirements."); }

            // Se hace una selección por solidez de passphrase
            switch (passphraseSolidityMinimal)
            {
                // Caracteres numericos
                case CharSolidity.Numerical:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.Numerical, passphrase, true)) { throw new ArgumentException("No required numerical characters present in the passphrase. It does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfabeticos
                case CharSolidity.Alphabetical:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.LowerAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.UpperAlphabetical, passphrase, true))
                    { throw new ArgumentException("No required alphabetical characters in lower and upper case present in the passphrase. It does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfabeticos en minúsculas
                case CharSolidity.LowerAlphabetical:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.LowerAlphabetical, passphrase, true)) { throw new ArgumentException("No required alphabetical characters in lower case present in the passphrase. It does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfabeticos en mayúsculas
                case CharSolidity.UpperAlphabetical:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.UpperAlphabetical, passphrase, true)) { throw new ArgumentException("No required alphabetical characters in upper case present in the passphrase. It does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfanumericos
                case CharSolidity.Alphanumerical:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.UpperAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.LowerAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.Numerical, passphrase, true))
                    { throw new ArgumentException("No required alphanumerical characters in upper and lower case present in the passphrase. It does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfanumericos en minúsculas
                case CharSolidity.LowerAlphanumerical:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.LowerAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.Numerical, passphrase, true))
                    { throw new ArgumentException("No required alphanumerical characters in lower case present in the passphrase. It does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfanumericos en mayúsculas
                case CharSolidity.UpperAlphanumerical:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.UpperAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.Numerical, passphrase, true))
                    { throw new ArgumentException("No required alphanumerical characters in upper case present in the passphrase. It does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfanumericos con carácteres especiales
                case CharSolidity.AlphanumericWithSpecialChars:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.LowerAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.UpperAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.Numerical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.SpecialChars, passphrase, true))
                    { throw new ArgumentException("No required alphanumerical and special characters in upper and lower case present in the passphrase. It  does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfanumericos con caracteres especiales en minúsculas
                case CharSolidity.LowerAlphanumericWithSpecialChars:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.LowerAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.Numerical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.SpecialChars, passphrase, true))
                    { throw new ArgumentException("No required alphanumerical and special characters in lower case present in the passphrase. It  does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfanumericos con caracteres especiales en minúsculas
                case CharSolidity.UpperAlphanumericWithSpecialChars:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.UpperAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.Numerical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.SpecialChars, passphrase, true))
                    { throw new ArgumentException("No required alphanumerical and special characters in upper case present in the passphrase. It  does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfabeticos con caracteres especiales
                case CharSolidity.AlphabeticalWithSpecialChars:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.LowerAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.UpperAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.SpecialChars, passphrase, true))
                    { throw new ArgumentException("No required alphabetical and special characters in lower and upper case present in the passphrase. It  does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfabéticos con caracteres especiales en minúsculas
                case CharSolidity.LowerAlphabeticalWithSpecialChars:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.LowerAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.SpecialChars, passphrase, true))
                    { throw new ArgumentException("No required alphabetical and special characters in lower case present in the passphrase. It  does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres alfabéticos con caracteres especiales en mayúsculas
                case CharSolidity.UpperAlphabeticalWithSpecialChars:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.UpperAlphabetical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.SpecialChars, passphrase, true))
                    { throw new ArgumentException("No required alphabetical and special characters in upper case present in the passphrase. It  does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres numéricos con caracteres especiales
                case CharSolidity.NumericalWithSpecialChars:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.Numerical, passphrase, true)
                        || !CheckAllowedCharsInArray(CharacterSolidity.SpecialChars, passphrase, true))
                    { throw new ArgumentException("No required numerical and special characters present in the passphrase. It  does not meet the minimum solidity requirements."); }
                    break;

                // Caracteres numéricos con caracteres especiales
                case CharSolidity.SpecialChars:
                    // Busca los carácteres que el passphrase debería tener como mínimo según este nivel de solidez, si no lo cumple, lanzará una excepción
                    if (!CheckAllowedCharsInArray(CharacterSolidity.SpecialChars, passphrase, true)) { throw new ArgumentException("No required numerical and special characters present in the passphrase. It  does not meet the minimum solidity requirements."); }
                    break;
            }

        }

        private static void CheckPassphraseLength(char[] passphrase, int minimumLengthRequired, int maximumLengthAllowed)
        {
            // Si el maximo permitido inferior al minimo requerido, lanzará excepción de operación no válida
            if (minimumLengthRequired > maximumLengthAllowed) { throw new InvalidOperationException("Maximum length allowed cannot be less than minimum required."); }

            // Si el passphrase excede el máximo permitido
            if (passphrase.Length > maximumLengthAllowed) { throw new ArgumentException("Passphrase length is more big than the maximum length allowed."); }

            // Si se ha determinado el nivel de solidez negligente
            if (minimumLengthRequired == LengthSolidity.Negligent)
            {
                // Si el passphrase tiene al menos 1 caracter, saldra sin error
                if (passphrase.Length > 0) { return; }
            }
            // Si se ha determinado otro nivel de solidez
            else
            {
                // Si la longitud del passphrase es igual o superior a la que determina el nivel de solidez, saldrá sin error
                if (passphrase.Length >= minimumLengthRequired) { return; }
            }

            // Lanza excepción de longitud no válida
            throw new ArgumentException("Passphrase length does not meet the passphrase solidity requirements.");
        }
    }
}
