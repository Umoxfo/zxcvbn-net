using System;
using System.Globalization;
using System.Linq;

namespace Zxcvbn
{
    /// <summary>
    /// A few useful extension methods used through the Zxcvbn project
    /// </summary>
    static class Utility
    {
        private struct TimeUnit
        {
            internal const long Minute = 60;
            internal const long Hour = Minute * 60;
            internal const long Day = Hour * 24;
            internal const long Month = Day * 31;
            internal const long Year = Day * 365;
            internal const long Century = Year * 100;
        }

        /// <summary>
        /// Convert a number of seconds into a human-friendly form. Rounds up.
        /// To be consistent with zxcvbn, it returns the unit + 1 (i.e. 60 * 10 seconds = 10 minutes would come out as "11 minutes")
        /// this is probably to avoid ever needing to deal with plurals
        /// </summary>
        /// <param name="seconds">The time in seconds</param>
        /// <param name="translation">The language in which the string is returned</param>
        /// <returns>A human-friendly time string</returns>
        public static string DisplayTime(double seconds, in Translation translation = Translation.English)
        {
            SetTranslation(translation);

            if (seconds < 1) return Properties.Resources.Instant;
            else if (seconds < TimeUnit.Minute) return $"{1 + Math.Ceiling(seconds)} {Properties.Resources.Seconds}";
            else if (seconds < TimeUnit.Hour) return $"{1 + Divide(seconds, TimeUnit.Minute)} {Properties.Resources.Minutes}";
            else if (seconds < TimeUnit.Day) return $"{1 + Divide(seconds, TimeUnit.Hour)} {Properties.Resources.Hours}";
            else if (seconds < TimeUnit.Month) return $"{1 + Divide(seconds, TimeUnit.Day)} {Properties.Resources.Days}";
            else if (seconds < TimeUnit.Year) return $"{1 + Divide(seconds, TimeUnit.Month)} {Properties.Resources.Months}";
            else if (seconds < TimeUnit.Century) return $"{1 + Divide(seconds, TimeUnit.Year)} {Properties.Resources.Years}";
            else return $"{Divide(seconds, TimeUnit.Century)} {Properties.Resources.Centuries}";
        }//DisplayTime

        private static void SetTranslation(in Translation translation)
        {
            string cultureName;

            switch (translation)
            {
                case Translation.German:
                    cultureName = "de-DE";
                    break;
                case Translation.France:
                    cultureName = "fr-FR";
                    break;
                case Translation.English:
                default:
                    cultureName = "en-US";
                    break;
            }//switch

            Properties.Resources.Culture = CultureInfo.GetCultureInfo(cultureName);
        }//SetTranslation

        private static long Divide(double dividend, double divisor) =>
            decimal.ToInt64(decimal.Round((decimal)dividend / (decimal)divisor));

        /// <summary>
        /// Shortcut for string.Format
        /// </summary>
        /// <param name="args">Format args</param>
        /// <param name="str">Format string</param>
        /// <returns>Formatted string</returns>
        public static string F(this string str, params object[] args) => string.Format(str, args);

        /// <summary>
        /// Reverse a string in one call
        /// </summary>
        /// <param name="str">String to reverse</param>
        /// <returns>String in reverse</returns>
        public static string StringReverse(this string str) => new string(str.Reverse().ToArray());

        /// <summary>
        /// A convenience for parsing a substring as an int and returning the results. Uses TryParse, and so returns zero where there is no valid int
        /// </summary>
        /// <param name="r">Substring parsed as int or zero</param>
        /// <param name="length">Length of substring to parse</param>
        /// <param name="startIndex">Start index of substring to parse</param>
        /// <param name="str">String to get substring of</param>
        /// <returns>True if the parse succeeds</returns>
        public static bool IntParseSubstring(this string str, int startIndex, int length, out int r) => int.TryParse(str.Substring(startIndex, length), out r);

        /// <summary>
        /// Quickly convert a string to an integer, uses TryParse so any non-integers will return zero
        /// </summary>
        /// <param name="str">String to parse into an int</param>
        /// <returns>Parsed int or zero</returns>
        public static int ToInt(this string str)
        {
            int.TryParse(str, out int r);
            return r;
        }

        /// <summary>
        /// Get a translated string of the Warning
        /// </summary>
        /// <param name="warning">Warning enum to get the string from</param>
        /// <param name="translation">Language in which to return the string to. Default is English.</param>
        /// <returns>Warning string in the right language</returns>
        public static string GetWarning(Warning warning, in Translation translation = Translation.English)
        {
            SetTranslation(translation);

            string message;
            switch (warning)
            {
                case Warning.StraightRow:
                    message = Properties.Resources.Warning_StraightRow;
                    break;

                case Warning.ShortKeyboardPatterns:
                    message = Properties.Resources.Warning_ShortKeyboardPatterns;
                    break;

                case Warning.RepeatsLikeAaaEasy:
                    message = Properties.Resources.Warning_RepeatsLikeAaaEasy;
                    break;

                case Warning.RepeatsLikeAbcSlighterHarder:
                    message = Properties.Resources.Warning_RepeatsLikeAbcSlighterHarder;
                    break;
                case Warning.SequenceAbcEasy:
                    message = Properties.Resources.Warning_SequenceAbcEasy;
                    break;
                case Warning.RecentYearsEasy:
                    message = Properties.Resources.Warning_RecentYearsEasy;
                    break;
                case Warning.DatesEasy:
                    message = Properties.Resources.Warning_DatesEasy;
                    break;
                case Warning.Top10Passwords:
                    message = Properties.Resources.Warning_Top10Passwords;
                    break;
                case Warning.Top100Passwords:
                    message = Properties.Resources.Warning_Top100Passwords;
                    break;
                case Warning.CommonPasswords:
                    message = Properties.Resources.Warning_CommonPasswords;
                    break;
                case Warning.SimilarCommonPasswords:
                    message = Properties.Resources.Warning_SimilarCommonPasswords;
                    break;
                case Warning.WordEasy:
                    message = Properties.Resources.Warning_WordEasy;
                    break;
                case Warning.NameSurnamesEasy:
                    message = Properties.Resources.Warning_NameSurnamesEasy;
                    break;
                case Warning.CommonNameSurnamesEasy:
                    message = Properties.Resources.Warning_CommonNameSurnamesEasy;
                    break;
                case Warning.Empty:
                    message = Properties.Resources.Warning_Empty;
                    break;
                default:
                    message = "";
                    break;
            }//switch

            return message;
        }//GetWarning

        /// <summary>
        /// Get a translated string of the Warning
        /// </summary>
        /// <param name="suggestion">Suggestion enum to get the string from</param>
        /// <param name="translation">Language in which to return the string to. Default is English.</param>
        /// <returns>Suggestion string in the right language</returns>
        public static string GetSuggestion(Suggestion suggestion, Translation translation = Translation.English)
        {
            SetTranslation(translation);

            string message;
            switch (suggestion)
            {
                case Suggestion.AddAnotherWordOrTwo:
                    message = Properties.Resources.Suggestion_AddAnotherWordOrTwo;
                    break;
                case Suggestion.UseLongerKeyboardPattern:
                    message = Properties.Resources.Suggestion_UseLongerKeyboardPattern;
                    break;
                case Suggestion.AvoidRepeatedWordsAndChars:
                    message = Properties.Resources.Suggestion_AvoidRepeatedWordsAndChars;
                    break;
                case Suggestion.AvoidSequences:
                    message = Properties.Resources.Suggestion_AvoidSequences;
                    break;
                case Suggestion.AvoidYearsAssociatedYou:
                    message = Properties.Resources.Suggestion_AvoidYearsAssociatedYou;
                    break;
                case Suggestion.AvoidDatesYearsAssociatedYou:
                    message = Properties.Resources.Suggestion_AvoidDatesYearsAssociatedYou;
                    break;
                case Suggestion.CapsDontHelp:
                    message = Properties.Resources.Suggestion_CapsDontHelp;
                    break;
                case Suggestion.AllCapsEasy:
                    message = Properties.Resources.Suggestion_AllCapsEasy;
                    break;
                case Suggestion.ReversedWordEasy:
                    message = Properties.Resources.Suggestion_ReversedWordEasy;
                    break;
                case Suggestion.PredictableSubstitutionsEasy:
                    message = Properties.Resources.Suggestion_PredictableSubstitutionsEasy;
                    break;
                case Suggestion.Empty:
                    message = Properties.Resources.Suggestion_Empty;
                    break;
                default:
                    message = "Use a few words, avoid common phrases \n No need for symbols, digits, or uppercase letters";
                    break;
            }//switch

            return message;
        }//GetSuggestion
    }
}
