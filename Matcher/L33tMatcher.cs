﻿using System;
using System.Collections.Generic;
using System.Linq;

namespace Zxcvbn.Matcher
{
    /// <summary>
    /// This matcher applies some known l33t character substitutions and then attempts to match against passed in dictionary matchers.
    /// This detects passwords like 4pple which has a '4' substituted for an 'a'
    /// </summary>
    public class L33tMatcher : IMatcher
    {
        private List<DictionaryMatcher> dictionaryMatchers;
        private Dictionary<char, string> substitutions;

        /// <summary>
        /// Create a l33t matcher that applies substitutions and then matches again the passed in list of dictionary matchers.
        /// </summary>
        /// <param name="dictionaryMatchers">The list of dictionary matchers to check transformed passwords against</param>
        public L33tMatcher(List<DictionaryMatcher> dictionaryMatchers)
        {
            this.dictionaryMatchers = dictionaryMatchers;
            substitutions = BuildSubstitutionsMap();
        }

        /// <summary>
        /// Create a l33t matcher that applies substitutions and then matches again a single dictionary matcher.
        /// </summary>
        /// <param name="dictionaryMatcher">The dictionary matcher to check transformed passwords against</param>
        public L33tMatcher(DictionaryMatcher dictionaryMatcher) : this(new List<DictionaryMatcher> { dictionaryMatcher })
        {
        }

        /// <summary>
        /// Apply applicable l33t transformations and check <paramref name="password"/> against the dictionaries.
        /// </summary>
        /// <param name="password">The password to check</param>
        /// <returns>A list of match objects where l33t substitutions match dictionary words</returns>
        /// <seealso cref="L33tDictionaryMatch"/>
        public IEnumerable<Match> MatchPassword(string password)
        {
            List<Dictionary<char, char>> subs = EnumerateSubtitutions(GetRelevantSubstitutions(password));

            List<L33tDictionaryMatch> matches = (from subDict in subs
                                                 let sub_password = TranslateString(subDict, password)
                                                 from matcher in dictionaryMatchers
                                                 from match in matcher.MatchPassword(sub_password).OfType<DictionaryMatch>()
                                                 let token = password.Substring(match.i, match.j - match.i + 1)
                                                 let usedSubs = subDict.Where(kv => token.Contains(kv.Key)) // Count subs used in matched token
                                                 where usedSubs.Count() > 0 // Only want matches where substitutions were used
                                                 select new L33tDictionaryMatch(match)
                                                 {
                                                     Token = token,
                                                     Subs = usedSubs.ToDictionary(kv => kv.Key, kv => kv.Value)
                                                 }).ToList();

            foreach (L33tDictionaryMatch match in matches) CalulateL33tEntropy(match);

            return matches;
        }

        private void CalulateL33tEntropy(L33tDictionaryMatch match)
        {
            // I'm a bit dubious about this function, but I have duplicated zxcvbn functionality regardless

            int possibilities = 0;

            foreach (KeyValuePair<char, char> kvp in match.Subs)
            {
                int subbedChars = match.Token.Where(c => c == kvp.Key).Count();
                int unsubbedChars = match.Token.Where(c => c == kvp.Value).Count(); // Won't this always be zero?

                possibilities += Enumerable.Range(0, Math.Min(subbedChars, unsubbedChars) + 1).Sum(i => (int)PasswordScoring.Binomial(subbedChars + unsubbedChars, i));
            }

            double entropy = Math.Log(possibilities, 2);

            // In the case of only a single substitution (e.g. 4pple) this would otherwise come out as zero, so give it one bit
            match.L33tEntropy = (entropy < 1 ? 1 : entropy);
            match.Entropy += match.L33tEntropy;

            // We have to recalculate the uppercase entropy -- the password matcher will have used the subbed password not the original text
            match.Entropy -= match.UppercaseEntropy;
            match.UppercaseEntropy = PasswordScoring.CalculateUppercaseEntropy(match.Token);
            match.Entropy += match.UppercaseEntropy;
        }

        private string TranslateString(Dictionary<char, char> charMap, string str)
        {
            // Make substitutions from the character map wherever possible
            return new string(str.Select(c => charMap.ContainsKey(c) ? charMap[c] : c).ToArray());
        }

        private Dictionary<char, string> GetRelevantSubstitutions(string password)
        {
            // Return a map of only the useful substitutions,
            // i.e. only characters that the password contains a substituted form of
            return substitutions.Where(kv => kv.Value.Any(lc => password.Contains(lc)))
                                .ToDictionary(kv => kv.Key, kv => new string(kv.Value.Where(lc => password.Contains(lc)).ToArray()));
        }

        private List<Dictionary<char, char>> EnumerateSubtitutions(Dictionary<char, string> table)
        {
            // Produce a list of maps from l33t character to normal character.
            // Some substitutions can be more than one normal character though,
            // so we have to produce an entry that maps from the l33t char to both possibilities

            //XXX: This function produces different combinations to the original in zxcvbn. It may require some more work to get identical.

            //XXX: The function is also limited in that it only ever considers one substitution for each l33t character
            // (e.g. ||ke could feasibly match 'like' but this method would never show this).
            // My understanding is that this is also a limitation in zxcvbn and so I feel no need to correct it here.

            List<Dictionary<char, char>> subs = new List<Dictionary<char, char>>();
            subs.Add(new Dictionary<char, char>()); // Must be at least one mapping dictionary to work

            foreach (KeyValuePair<char, string> mapPair in table)
            {
                char normalChar = mapPair.Key;

                foreach (char l33tChar in mapPair.Value)
                {
                    // Can't add while enumerating so store here
                    List<Dictionary<char, char>> addedSubs = new List<Dictionary<char, char>>();

                    foreach (Dictionary<char, char> subDict in subs)
                    {
                        if (subDict.ContainsKey(l33tChar))
                        {
                            // This mapping already contains a corresponding normal character for this character,
                            // so keep the existing one as is but add a duplicate with the mapping replaced with this normal character
                            Dictionary<char, char> newSub = new Dictionary<char, char>(subDict);
                            newSub[l33tChar] = normalChar;
                            addedSubs.Add(newSub);
                        }
                        else
                        {
                            subDict[l33tChar] = normalChar;
                        }
                    }

                    subs.AddRange(addedSubs);
                }
            }

            return subs;
        }

        private Dictionary<char, string> BuildSubstitutionsMap()
        {
            // Is there an easier way of building this table?
            Dictionary<char, string> subs = new Dictionary<char, string>
            {
                ['a'] = "4@",
                ['b'] = "8",
                ['c'] = "({[<",
                ['e'] = "3",
                ['g'] = "69",
                ['i'] = "1!|",
                ['l'] = "1|7",
                ['o'] = "0",
                ['s'] = "$5",
                ['t'] = "+7",
                ['x'] = "%",
                ['z'] = "2"
            };

            return subs;
        }
    }

    /// <summary>
    /// L33tMatcher results are like dictionary match results with some extra information
    /// that pertains to the extra entropy that is garnered by using substitutions.
    /// </summary>
    public class L33tDictionaryMatch : DictionaryMatch
    {
        /// <summary>
        /// The extra entropy from using l33t substitutions
        /// </summary>
        public double L33tEntropy { get; set; }

        /// <summary>
        /// The character mappings that are in use for this match
        /// </summary>
        public Dictionary<char, char> Subs { get; set; }

        /// <summary>
        /// Create a new l33t match from a dictionary match
        /// </summary>
        /// <param name="dm">The dictionary match to initialize the l33t match from</param>
        public L33tDictionaryMatch(DictionaryMatch dm)
        {
            BaseEntropy = dm.BaseEntropy;
            Cardinality = dm.Cardinality;
            DictionaryName = dm.DictionaryName;
            Entropy = dm.Entropy;
            i = dm.i;
            j = dm.j;
            MatchedWord = dm.MatchedWord;
            Pattern = dm.Pattern;
            Rank = dm.Rank;
            Token = dm.Token;
            UppercaseEntropy = dm.UppercaseEntropy;

            Subs = new Dictionary<char, char>();
        }

        /// <summary>
        /// Create an empty l33t match
        /// </summary>
        public L33tDictionaryMatch() => Subs = new Dictionary<char, char>();
    }
}
