// Filename tidying for module_name(): strip the suffixes Windows adds when a file is duplicated,
// " - Copy" and " (2)". This replaced two std::regex_replace calls -- <regex> is a very large
// header and a slow engine to drag in for two fixed suffixes.
//
// Deliberately depends on kstl and nothing else, no IDA SDK, so it can be unit-tested on its own.
#pragma once
#include "kstl/string.hpp"

namespace hexport {

// Index of the first character of the run of trailing spaces ending at `end`.
inline unsigned skip_spaces_back(const kstl::string &s, unsigned end) noexcept
{
  while ( end > 0 && s[end - 1] == ' ' )
    --end;
  return end;
}

// If s[..end) ends in "(digits)", return the index just past the text before it (spaces trimmed).
// Returns `end` unchanged when there is no such suffix. Matches the regex \s*\(\d+\)\s*$.
inline unsigned trim_paren_number(const kstl::string &s, unsigned end) noexcept
{
  unsigned i = skip_spaces_back(s, end);
  if ( i == 0 || s[i - 1] != ')' )
    return end;
  unsigned digits_end = i - 1;
  unsigned j = digits_end;
  while ( j > 0 && s[j - 1] >= '0' && s[j - 1] <= '9' )
    --j;
  if ( j == digits_end || j == 0 || s[j - 1] != '(' )
    return end;                          // needs at least one digit and an opening paren
  return skip_spaces_back(s, j - 1);
}

// Matches \s*-\s*copy(\s*\(\d+\))?\s*$, case-insensitive, and returns the index to cut at.
// Returns `end` unchanged when it does not match.
inline unsigned trim_copy_suffix(const kstl::string &s, unsigned end) noexcept
{
  unsigned i = trim_paren_number(s, end);          // the optional "(n)" after "copy"
  i = skip_spaces_back(s, i);
  if ( i < 4 )
    return end;
  const char *word = "copy";
  for ( unsigned k = 0; k < 4; ++k )
    if ( (s[i - 4 + k] | 0x20) != word[k] )
      return end;
  unsigned j = skip_spaces_back(s, i - 4);
  if ( j == 0 || s[j - 1] != '-' )
    return end;
  return skip_spaces_back(s, j - 1);
}

// "C:\path\My Tool - Copy (2).exe" -> "My Tool.exe". Never returns empty: falls back to "target",
// which is also what a null or empty path gives.
inline kstl::string clean_module_name(const char *path)
{
  kstl::string s(path);
  if ( s.empty() )
    return kstl::string("target");

  unsigned slash = s.find_last_of("\\/");
  if ( slash != kstl::string::npos )
    s = s.substr(slash + 1);

  kstl::string stem = s;
  kstl::string ext;
  unsigned dot = s.rfind('.');
  if ( dot != kstl::string::npos && dot != 0 )
  {
    stem = s.substr(0, dot);
    ext = s.substr(dot);
  }

  stem.resize(trim_copy_suffix(stem, stem.size()));     // " - Copy", optionally " - Copy (2)"
  stem.resize(trim_paren_number(stem, stem.size()));    // a bare " (2)"
  stem.resize(skip_spaces_back(stem, stem.size()));
  if ( stem.empty() )
    stem = "target";                                    // ...and the extension is still kept

  return stem + ext;
}

}  // namespace hexport
