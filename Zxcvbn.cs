using System;
using System.Collections.Generic;
using System.Linq;

using Zxcvbn.Matcher;

namespace Zxcvbn
{
    /// <summary>
    /// <para>Zxcvbn is used to estimate the strength of passwords. </para>
    ///
    /// <para>This implementation is a port of the Zxcvbn JavaScript library by Dan Wheeler:
    /// https://github.com/lowe/zxcvbn</para>
    ///
    /// <para>To quickly evaluate a password, use the <see cref="MatchPassword"/> static function.</para>
    ///
    /// <para>To evaluate a number of passwords, create an instance of this object and repeatedly call
    /// the <see cref="EvaluatePassword"/> function.
    /// Reusing the Zxcvbn instance will ensure that pattern matchers will only be created once
    /// rather than being recreated for each password evaluated.</para>
    /// </summary>
    public class Zxcvbn
    {
        private const string BruteforcePattern = "bruteforce";

        private readonly IMatcherFactory matcherFactory;
        private readonly Translation translation;

        /// <summary>
        /// Create a new instance of Zxcvbn that uses the default matchers and user inputs list.
        /// </summary>
        public Zxcvbn(IEnumerable<string> userInputs = null, Translation translation = Translation.English)
            : this(new DefaultMatcherFactory(userInputs), translation)
        {
        }

        /// <summary>
        /// Create an instance of Zxcvbn that will use the given matcher factory to create matchers to use
        /// to find password weakness.
        /// </summary>
        /// <param name="matcherFactory">The factory used to create the pattern matchers used</param>
        /// <param name="translation">The language in which the strings are returned</param>
        public Zxcvbn(IMatcherFactory matcherFactory, Translation translation = Translation.English)
        {
            this.matcherFactory = matcherFactory;
            this.translation = translation;
        }

        /// <summary>
        /// <para>A static function to match a password against the default matchers without having to create
        /// an instance of Zxcvbn yourself, with supplied user data. </para>
        ///
        /// <para>Supplied user data will be treated as another kind of dictionary matching.</para>
        /// </summary>
        /// <param name="password">the password to test</param>
        /// <param name="userInputs">optionally, the user inputs list</param>
        /// <returns>The results of the password evaluation</returns>
        public static Result MatchPassword(string password, IEnumerable<string> userInputs = null) =>
            new Zxcvbn(new DefaultMatcherFactory()).EvaluatePassword(password, userInputs);

        /// <summary>
        /// <para>Perform the password matching on the given password and user inputs,
        /// returning the result structure with information on the lowest entropy match found.</para>
        ///
        /// <para>User data will be treated as another kind of dictionary matching,
        /// but can be different for each password being evaluated.</para>
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="userInputs">Optionally, an enumerable of user data</param>
        /// <returns>Result for lowest entropy match</returns>
        public Result EvaluatePassword(string password, IEnumerable<string> userInputs = null)
        {
            userInputs = userInputs ?? new string[0];

            IEnumerable<Match> matches = new List<Match>();

            System.Diagnostics.Stopwatch timer = System.Diagnostics.Stopwatch.StartNew();

            foreach (IMatcher matcher in matcherFactory.CreateMatchers(userInputs))
            {
                matches = matches.Union(matcher.MatchPassword(password));
            }

            Result result = FindMinimumEntropyMatch(password, matches);

            timer.Stop();
            result.CalcTime = timer.ElapsedMilliseconds;

            return result;
        }

        /// <summary>
        /// Returns a new result structure initialized with data for the lowest entropy result of all of the matches passed in, adding brute-force matches where there are no lesser entropy found pattern matches.
        /// </summary>
        /// <param name="matches">Password being evaluated</param>
        /// <param name="password">List of matches found against the password</param>
        /// <returns>A result object for the lowest entropy match sequence</returns>
        private Result FindMinimumEntropyMatch(string password, IEnumerable<Match> matches)
        {
            int bruteforce_cardinality = PasswordScoring.PasswordCardinality(password);

            // Minimum entropy up to position k in the password
            double[] minimumEntropyToIndex = new double[password.Length];
            Match[] bestMatchForIndex = new Match[password.Length];

            for (int k = 0; k < password.Length; k++)
            {
                // Start with brute-force scenario added to previous sequence to beat
                minimumEntropyToIndex[k] = (k == 0 ? 0 : minimumEntropyToIndex[k - 1]) + Math.Log(bruteforce_cardinality, 2);

                // All matches that end at the current character, test to see if the entropy is less
                foreach (Match match in matches.Where(m => m.j == k))
                {
                    double candidate_entropy = (match.i <= 0 ? 0 : minimumEntropyToIndex[match.i - 1]) + match.Entropy;
                    if (candidate_entropy < minimumEntropyToIndex[k])
                    {
                        minimumEntropyToIndex[k] = candidate_entropy;
                        bestMatchForIndex[k] = match;
                    }
                }
            }


            // Walk backwards through lowest entropy matches, to build the best password sequence
            List<Match> matchSequence = new List<Match>();
            for (int k = password.Length - 1; k >= 0; k--)
            {
                if (bestMatchForIndex[k] != null)
                {
                    matchSequence.Add(bestMatchForIndex[k]);
                    k = bestMatchForIndex[k].i; // Jump back to start of match
                }
            }
            matchSequence.Reverse();


            // The match sequence might have gaps, fill in with brute-force matching
            // After this the matches in matchSequence must cover the whole string (i.e. match[k].j == match[k + 1].i - 1)
            if (matchSequence.Count == 0)
            {
                // To make things easy, we'll separate out the case where there are no matches so everything is brute-forced
                matchSequence.Add(new Match()
                {
                    i = 0,
                    j = password.Length,
                    Token = password,
                    Cardinality = bruteforce_cardinality,
                    Pattern = BruteforcePattern,
                    Entropy = Math.Log(Math.Pow(bruteforce_cardinality, password.Length), 2)
                });
            }
            else
            {
                // There are matches, so find the gaps and fill them in
                List<Match> matchSequenceCopy = new List<Match>();
                for (int k = 0; k < matchSequence.Count; k++)
                {
                    Match m1 = matchSequence[k];
                    Match m2 = (k < matchSequence.Count - 1 ? matchSequence[k + 1] : new Match() { i = password.Length }); // Next match, or a match past the end of the password

                    matchSequenceCopy.Add(m1);
                    if (m1.j < m2.i - 1)
                    {
                        // Fill in gap
                        int ns = m1.j + 1;
                        int ne = m2.i - 1;
                        matchSequenceCopy.Add(new Match()
                        {
                            i = ns,
                            j = ne,
                            Token = password.Substring(ns, ne - ns + 1),
                            Cardinality = bruteforce_cardinality,
                            Pattern = BruteforcePattern,
                            Entropy = Math.Log(Math.Pow(bruteforce_cardinality, ne - ns + 1), 2)
                        });
                    }
                }

                matchSequence = matchSequenceCopy;
            }


            double minEntropy = (password.Length == 0 ? 0 : minimumEntropyToIndex[password.Length - 1]);
            double crackTime = PasswordScoring.EntropyToCrackTime(minEntropy);

            Result result = new Result
            {
                Password = password,
                Entropy = minEntropy,
                MatchSequence = matchSequence,
                CrackTime = crackTime,
                CrackTimeDisplay = Utility.DisplayTime(crackTime, translation),
                Score = PasswordScoring.CrackTimeToScore(crackTime)
            };

            //starting feedback
            if ((matchSequence == null) || (matchSequence.Count() == 0))
            {
                result.Warning = Warning.Default;
                result.Suggestions.Clear();
                result.Suggestions.Add(Suggestion.Default);
            }
            else
            {
                //no Feedback if score is good or great
                if (result.Score > 2)
                {
                    result.Warning = Warning.Empty;
                    result.Suggestions.Clear();
                    result.Suggestions.Add(Suggestion.Empty);
                }
                else
                {
                    //tie feedback to the longest match for longer sequences
                    Match longestMatch = GetLongestMatch(matchSequence);
                    GetMatchFeedback(longestMatch, matchSequence.Count() == 1, result);
                    result.Suggestions.Insert(0, Suggestion.AddAnotherWordOrTwo);
                }


            }
            return result;
        }

        private static Match GetLongestMatch(List<Match> matchSequence)
        {
            Match longestMatch;

            if ((matchSequence != null) && (matchSequence.Count() > 0))
            {
                longestMatch = matchSequence[0];
                foreach (Match match in matchSequence)
                {
                    if (match.Token.Length > longestMatch.Token.Length)
                        longestMatch = match;
                }
            }
            else
            {
                longestMatch = new Match();
            }

            return longestMatch;
        }

        private void GetMatchFeedback(Match match, bool isSoleMatch, Result result)
        {
            switch (match.Pattern)
            {
                case "dictionary":
                    GetDictionaryMatchFeedback((DictionaryMatch)match, isSoleMatch, result);
                    break;

                case "spatial":
                    SpatialMatch spatialMatch = (SpatialMatch)match;

                    if (spatialMatch.Turns == 1)
                        result.Warning = Warning.StraightRow;
                    else
                        result.Warning = Warning.ShortKeyboardPatterns;

                    result.Suggestions.Clear();
                    result.Suggestions.Add(Suggestion.UseLongerKeyboardPattern);
                    break;

                case "repeat":
                    //todo: add support for repeated sequences longer than 1 char
                  //  if(match.Token.Length == 1)
                        result.warning = Warning.RepeatsLikeAaaEasy;
                  //  else
                 //       result.warning = Warning.RepeatsLikeAbcSlighterHarder;

                    result.Suggestions.Clear();
                    result.Suggestions.Add(Suggestion.AvoidRepeatedWordsAndChars);
                    break;

                case "sequence":
                    result.Warning = Warning.SequenceAbcEasy;

                    result.Suggestions.Clear();
                    result.Suggestions.Add(Suggestion.AvoidSequences);
                    break;

                //todo: add support for recent_year, however not example exist on https://dl.dropboxusercontent.com/u/209/zxcvbn/test/index.html


                case "date":
                    result.Warning = Warning.DatesEasy;

                    result.Suggestions.Clear();
                    result.Suggestions.Add(Suggestion.AvoidDatesYearsAssociatedYou);
                    break;
            }
        }

        private static void GetDictionaryMatchFeedback(DictionaryMatch match, bool isSoleMatch, Result result)
        {
            if (match.DictionaryName.Equals("passwords"))
            {
                //todo: add support for reversed words
                if (isSoleMatch == true && !(match is L33tDictionaryMatch))
                {
                    if (match.Rank <= 10)
                        result.Warning = Warning.Top10Passwords;
                    else if (match.Rank <= 100)
                        result.Warning = Warning.Top100Passwords;
                    else
                        result.Warning = Warning.CommonPasswords;
                }
                else if (PasswordScoring.CrackTimeToScore(PasswordScoring.EntropyToCrackTime(match.Entropy)) <= 1)
                {
                    result.Warning = Warning.SimilarCommonPasswords;
                }
            }
            else if (match.DictionaryName == "english")
            {
                if (isSoleMatch)
                    result.Warning = Warning.WordEasy;
            }
            else if (match.DictionaryName == "surnames" ||
                     match.DictionaryName == "male_names" ||
                     match.DictionaryName == "female_names")
            {
                result.Warning = isSoleMatch ? Warning.NameSurnamesEasy : Warning.CommonNameSurnamesEasy;

                if (isSoleMatch)
                    result.Warning = Warning.NameSurnamesEasy;
                else
                    result.Warning = Warning.CommonNameSurnamesEasy;
            }
            else
            {
                result.Warning = Warning.Empty;
            }

            string word = match.Token;
            if (word.FirstOrDefault() >= 'A' && word.FirstOrDefault() <= 'Z')
            {
                result.Suggestions.Add(Suggestion.CapsDontHelp);
            }
            else if (word == word.ToUpper() && word != word.ToLowerInvariant())
            {
                result.Suggestions.Add(Suggestion.AllCapsEasy);
            }

            //todo: add support for reversed words
            //if match.reversed and match.token.length >= 4
            //    suggestions.push "Reversed words aren't much harder to guess"

            if (match is L33tDictionaryMatch)
            {
                result.Suggestions.Add(Suggestion.PredictableSubstitutionsEasy);
            }
        }


    }
}
