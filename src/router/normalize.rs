//! Path normalization applied before route matching, filesystem access and
//! upstream forwarding: percent-decoding, dot-segment resolution and
//! duplicate-slash collapsing, per RFC 3986 §5.2.4 semantics with the twist
//! that `%2F` decodes into a real separator (like nginx).
//!
//! The result is always an absolute path starting with exactly one `/`.
//! Traversal above the root is clamped — `/a/../../b` normalizes to `/b`,
//! and percent-encoded dot segments are treated like literal ones.

/// A path that could not be normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    /// Path contains a NUL byte (possibly percent-encoded).
    Nul,
    /// Path contains an ASCII/control character (possibly
    /// percent-encoded) — `%09`-style bytes are legal in a request
    /// target but meaningless in a filesystem path and dangerous in
    /// generated markup.
    Control,
    /// The path bytes were not valid UTF-8 after percent-decoding.
    Utf8,
}

impl std::fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nul => write!(f, "path contains NUL"),
            Self::Control => write!(f, "path contains a control character"),
            Self::Utf8 => write!(f, "path is not valid UTF-8"),
        }
    }
}

impl std::error::Error for NormalizeError {}

/// Normalize a request path (the part before `?`).
pub fn normalize_path(raw: &str) -> Result<String, NormalizeError> {
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| NormalizeError::Utf8)?;
    if decoded.contains('\0') {
        return Err(NormalizeError::Nul);
    }
    if decoded.chars().any(|c| c.is_control()) {
        return Err(NormalizeError::Control);
    }
    let had_trailing_slash = decoded.ends_with('/') && decoded.len() > 1;
    let mut out: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            seg => out.push(seg),
        }
    }
    let mut path = String::with_capacity(decoded.len());
    path.push('/');
    path.push_str(&out.join("/"));
    if had_trailing_slash && !path.ends_with('/') {
        path.push('/');
    }
    Ok(path)
}

/// One `path_deny` list entry, normalized exactly like a request path
/// so `/%2e%2e/`, `%2F` and `//` spellings hit the same entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DenyEntry {
    /// Exact normalized path match (`/.env`).
    Exact(String),
    /// Literal prefix match — a trailing `*` in the entry makes it a
    /// prefix (`/admin*` also catches `/administrator`, Caddy `path`
    /// parity). `/admin/*` matches `/admin/` and below, not `/admin`.
    Prefix(String),
}

impl DenyEntry {
    /// Parse one entry: a trailing `*` marks a literal prefix match;
    /// `*` anywhere else is rejected (no suffix or infix globs). The
    /// literal part normalizes like a request path — a bare `*` becomes
    /// `Prefix("/")`, which denies everything. Errors name the *reason*
    /// — callers add the entry's position (`entry "x":`, `line N:`).
    pub fn parse(token: &str) -> Result<Self, String> {
        if token.is_empty() {
            return Err("empty entry".into());
        }
        let (stem, prefix) = match token.strip_suffix('*') {
            Some(s) => (s, true),
            None => (token, false),
        };
        if stem.contains('*') {
            return Err(
                "`*` may only appear at the end (prefix match) — e.g. \"/admin*\" or \"/admin/*\""
                    .into(),
            );
        }
        let norm = normalize_path(stem).map_err(|e| e.to_string())?;
        Ok(if prefix {
            Self::Prefix(norm)
        } else {
            Self::Exact(norm)
        })
    }

    /// Spelling used in diagnostics — `"/.env"` or `"/admin*"`.
    pub fn describe(&self) -> String {
        match self {
            Self::Exact(p) => format!("{p:?}"),
            Self::Prefix(p) => format!("{p:?}*"),
        }
    }
}

/// Parse a `path_deny` list file: one entry per line; blank lines and
/// `#` comments are skipped (a ` #` tail is an inline comment — `#`
/// can't appear unencoded in a request path, so nothing real is lost);
/// a leading `path ` per line is tolerated so Caddy-exported lists work
/// verbatim. Parse failures name the line.
pub fn parse_deny_list(text: &str) -> Result<Vec<DenyEntry>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .split_once(" #")
            .map(|(head, _)| head.trim_end())
            .unwrap_or(line);
        let token = line
            .strip_prefix("path")
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .map(str::trim_start)
            .unwrap_or(line);
        out.push(DenyEntry::parse(token).map_err(|e| format!("line {}: {token:?}: {e}", i + 1))?);
    }
    Ok(out)
}

/// Shorten a normalized path to its parent prefix: `/a/b/c` → `/a/b`,
/// `/a` → `/`. Used to enumerate progressively less-specific prefix matches.
pub fn parent_prefix(path: &str) -> &str {
    if path == "/" {
        "/"
    } else {
        match path.rfind('/') {
            Some(0) => "/",
            Some(i) => &path[..i],
            None => "/",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_duplicate_slashes() {
        assert_eq!(normalize_path("//a///b").unwrap(), "/a/b");
    }

    #[test]
    fn resolves_dot_segments() {
        assert_eq!(normalize_path("/a/./b").unwrap(), "/a/b");
        assert_eq!(normalize_path("/a/../b").unwrap(), "/b");
        assert_eq!(normalize_path("/a/b/../../c").unwrap(), "/c");
    }

    #[test]
    fn traversal_clamps_at_root() {
        assert_eq!(normalize_path("/../a").unwrap(), "/a");
        assert_eq!(normalize_path("/../../x").unwrap(), "/x");
        assert_eq!(normalize_path("/a/../../../b").unwrap(), "/b");
    }

    #[test]
    fn decodes_percent_encoding() {
        assert_eq!(normalize_path("/a%20b/c").unwrap(), "/a b/c");
        assert_eq!(normalize_path("/%2e%2e/secret").unwrap(), "/secret");
        assert_eq!(normalize_path("/a%2Fb").unwrap(), "/a/b");
    }

    #[test]
    fn preserves_trailing_slash() {
        assert_eq!(normalize_path("/a/b/").unwrap(), "/a/b/");
        assert_eq!(normalize_path("/a//b/").unwrap(), "/a/b/");
        assert_eq!(normalize_path("/").unwrap(), "/");
    }

    #[test]
    fn rejects_nul_and_bad_utf8() {
        assert_eq!(normalize_path("/a%00b"), Err(NormalizeError::Nul));
        assert_eq!(normalize_path("/%ff"), Err(NormalizeError::Utf8));
    }

    #[test]
    fn rejects_decoded_control_chars() {
        assert_eq!(normalize_path("/a%09b"), Err(NormalizeError::Control));
        assert_eq!(normalize_path("/a%1fb"), Err(NormalizeError::Control));
        assert_eq!(normalize_path("/a%7fb"), Err(NormalizeError::Control));
        // raw space is fine — it is not a control character
        assert_eq!(normalize_path("/a b").unwrap(), "/a b");
    }

    #[test]
    fn parent_prefix_climbs() {
        assert_eq!(parent_prefix("/a/b/c"), "/a/b");
        assert_eq!(parent_prefix("/a"), "/");
        assert_eq!(parent_prefix("/"), "/");
    }

    #[test]
    fn deny_entry_exact_and_prefix() {
        assert_eq!(
            DenyEntry::parse("/.env").unwrap(),
            DenyEntry::Exact("/.env".into())
        );
        assert_eq!(
            DenyEntry::parse("/admin*").unwrap(),
            DenyEntry::Prefix("/admin".into())
        );
        // a bare `*` normalizes to "deny everything"
        assert_eq!(
            DenyEntry::parse("*").unwrap(),
            DenyEntry::Prefix("/".into())
        );
        // entries normalize like request paths — encoded, traversal and
        // duplicate-slash spellings land on the same entry
        assert_eq!(
            DenyEntry::parse("/%2e%2e/etc").unwrap(),
            DenyEntry::Exact("/etc".into())
        );
        assert_eq!(
            DenyEntry::parse("//a//b").unwrap(),
            DenyEntry::Exact("/a/b".into())
        );
        assert_eq!(
            DenyEntry::parse("/a%2Fb").unwrap(),
            DenyEntry::Exact("/a/b".into())
        );
        // a bare name gets a leading slash like a request path would
        assert_eq!(
            DenyEntry::parse("wp-config.php").unwrap(),
            DenyEntry::Exact("/wp-config.php".into())
        );
    }

    #[test]
    fn deny_entry_rejects_mid_and_leading_star() {
        assert!(DenyEntry::parse("*.php").is_err());
        assert!(DenyEntry::parse("/a*b").is_err());
        assert!(DenyEntry::parse("*/").is_err());
        assert!(DenyEntry::parse("").is_err());
        // normalization failures surface as entry errors
        assert!(DenyEntry::parse("/a%09b").is_err());
        assert!(DenyEntry::parse("/%ff").is_err());
    }

    #[test]
    fn deny_list_skips_comments_blanks_and_path_token() {
        let text = "\
# a comment
/.env

   \t
path /admin*
wp-config.php
   # indented comment
";
        let entries = parse_deny_list(text).unwrap();
        assert_eq!(
            entries,
            vec![
                DenyEntry::Exact("/.env".into()),
                DenyEntry::Prefix("/admin".into()),
                DenyEntry::Exact("/wp-config.php".into()),
            ]
        );
    }

    #[test]
    fn deny_list_errors_name_the_line() {
        let err = parse_deny_list("/.env\n*.php\n").unwrap_err();
        assert!(err.contains("line 2"), "{err}");
        // `pathname` is an entry, not the `path ` keyword
        let entries = parse_deny_list("pathname\n").unwrap();
        assert_eq!(entries, vec![DenyEntry::Exact("/pathname".into())]);
        // a ` #` tail is an inline comment; `/a#b` stays literal
        let entries = parse_deny_list("/.env # the probe\n/a#b\n").unwrap();
        assert_eq!(
            entries,
            vec![
                DenyEntry::Exact("/.env".into()),
                DenyEntry::Exact("/a#b".into()),
            ]
        );
    }
}
