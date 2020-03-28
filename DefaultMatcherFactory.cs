using System;
using System.Collections.Generic;
using System.Linq;

using Zxcvbn.Matcher;

namespace Zxcvbn
{
    /// <summary>
    /// <para>This matcher factory will use all of the default password matchers.</para>
    ///
    /// <para>Default dictionary matchers use the built-in word lists:
    /// passwords, english, male_names, female_names, surnames</para>
    /// <para>Also matching against: user data, all dictionaries with l33t substitutions</para>
    /// <para>Other default matchers: repeats, sequences, digits, years, dates, spatial</para>
    ///
    /// <para>See <see cref="IMatcher"/> and the classes that implement it for more information on each kind of pattern matcher.</para>
    /// </summary>
    class DefaultMatcherFactory : IMatcherFactory
    {
        List<IMatcher> matchers;

        /// <summary>
        /// Create a matcher factory that uses the default list of pattern matchers and userInputs
        /// </summary>
        public DefaultMatcherFactory(IEnumerable<string> userInputs = null)
        {
            List<DictionaryMatcher> dictionaryMatchers = new List<DictionaryMatcher>() {
                new DictionaryMatcher("passwords",
                    Properties.Resources.Passwords.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)),
                new DictionaryMatcher("english",
                    Properties.Resources.English.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)),
                new DictionaryMatcher("male_names",
                    Properties.Resources.MaleNames.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)),
                new DictionaryMatcher("female_names",
                    Properties.Resources.FemaleNames.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)),
                new DictionaryMatcher("surnames",
                    Properties.Resources.Surnames.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)),
                new DictionaryMatcher("user_inputs", userInputs ?? new string[0])
            };

            matchers = new List<IMatcher> {
                new RepeatMatcher(),
                new SequenceMatcher(),
                new RegexMatcher("\\d{3,}", 10, true, "digits"),
                new RegexMatcher("19\\d{2}|20[01]\\d", 119, false, "year"),
                new DateMatcher(),
                new SpatialMatcher()
            };

            matchers.AddRange(dictionaryMatchers);
            matchers.Add(new L33tMatcher(dictionaryMatchers));
        }

        /// <summary>
        /// Get instances of pattern matchers, adding in per-password matchers on userInputs (and userInputs with l33t substitutions)
        /// </summary>
        /// <param name="userInputs">Enumerable of user information</param>
        /// <returns>Enumerable of matchers to use</returns>
        public IEnumerable<IMatcher> CreateMatchers(IEnumerable<string> userInputs)
        {
            DictionaryMatcher userInputDict = new DictionaryMatcher("user_inputs", userInputs);
            L33tMatcher leetUser = new L33tMatcher(userInputDict);

            return matchers.Union(new List<IMatcher> { userInputDict, leetUser });
        }
    }
}
