//! Small value types used by the configuration model: [`ByteSize`] for
//! human sizes like `16KiB` and [`RateSpec`] for rates like `100/s`.

use std::fmt;
use std::time::Duration;

use fundu::{CustomDurationParser, CustomDurationParserBuilder, CustomTimeUnit, TimeUnit};
use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serde adapter for `Vec<T>` fields: `x = "v"` parses as `["v"]` —
/// scalar sugar for the common single-entry case (see
/// `docs/config-grammar.md`; `include` deliberately stays strict).
/// Serializes as the list form — canonical output is always an array.
pub mod one_or_many {
    use std::fmt;
    use std::marker::PhantomData;

    use serde::de::value::{MapAccessDeserializer, SeqAccessDeserializer};
    use serde::de::{self, IntoDeserializer, Visitor};
    use serde::{Deserialize, Deserializer};

    /// Deserialize `v` or `[v, …]` into `Vec<T>`.
    ///
    /// An array is always the list form: a `T` that is a
    /// struct-with-defaults would otherwise positionally accept `[]` and
    /// produce a bogus single element. Any other value is handed to `T`
    /// directly — one pass, no `#[serde(untagged)]` buffering, and `T`'s
    /// own error (with its path) reaches the user.
    pub fn deserialize<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        d.deserialize_any(OneOrMany(PhantomData))
    }

    struct OneOrMany<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> OneOrMany<T> {
        fn one<D: Deserializer<'de>>(d: D) -> Result<Vec<T>, D::Error> {
            T::deserialize(d).map(|v| vec![v])
        }
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for OneOrMany<T> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a value or a list of values")
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, seq: A) -> Result<Vec<T>, A::Error> {
            Vec::deserialize(SeqAccessDeserializer::new(seq))
        }

        fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Vec<T>, A::Error> {
            Self::one(MapAccessDeserializer::new(map))
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Vec<T>, E> {
            Self::one(v.into_deserializer())
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Vec<T>, E> {
            Self::one(v.into_deserializer())
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Vec<T>, E> {
            Self::one(v.into_deserializer())
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Vec<T>, E> {
            Self::one(v.into_deserializer())
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<T>, E> {
            Self::one(v.into_deserializer())
        }

        fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Vec<T>, E> {
            Self::one(de::value::BorrowedStrDeserializer::new(v))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Vec<T>, E> {
            Self::one(v.into_deserializer())
        }

        fn visit_unit<E: de::Error>(self) -> Result<Vec<T>, E> {
            Self::one(().into_deserializer())
        }
    }

    struct List<T>(Vec<T>);

    impl<'de, T: Deserialize<'de>> Deserialize<'de> for List<T> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_any(OneOrMany(PhantomData)).map(List)
        }
    }

    /// `v` or `[v, …]` or none into `Option<Vec<T>>` — same sugar for
    /// optional list fields.
    pub mod option {
        use serde::{Deserialize, Deserializer};

        /// Deserialize `v`, `[v, …]`, or none into `Option<Vec<T>>`.
        pub fn deserialize<'de, D, T>(d: D) -> Result<Option<Vec<T>>, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de>,
        {
            Option::<super::List<T>>::deserialize(d).map(|o| o.map(|l| l.0))
        }
    }
}

/// Serde adapter for `Vec<IpNet>`/`Option<Vec<IpNet>>` fields: the
/// same scalar-or-list sugar as `one_or_many`, plus bare IPs — a
/// `"10.0.0.1"` entry parses as the host route `10.0.0.1/32` (and
/// `::1` as `/128`), since a prefix is almost never what an operator
/// means to omit.
pub mod cidr {
    use std::net::IpAddr;

    use ipnet::IpNet;
    use serde::Deserializer;
    use serde::de::Error;

    /// Parse a CIDR or a bare IP (interpreted as a host route).
    pub fn parse(s: &str) -> Result<IpNet, String> {
        s.parse::<IpNet>().or_else(|_| {
            s.parse::<IpAddr>()
                .map(|ip| match ip {
                    IpAddr::V4(a) => IpNet::V4(ipnet::Ipv4Net::from(a)),
                    IpAddr::V6(a) => IpNet::V6(ipnet::Ipv6Net::from(a)),
                })
                .map_err(|_| {
                    format!("invalid network {s:?} — expected a CIDR (\"10.0.0.0/8\") or IP (\"10.0.0.1\")")
                })
        })
    }

    /// Deserialize `v` or `[v, …]` into `Vec<IpNet>`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<IpNet>, D::Error> {
        let raw: Vec<String> = super::one_or_many::deserialize(d)?;
        raw.iter()
            .map(|s| parse(s).map_err(Error::custom))
            .collect()
    }

    /// Same sugar for `Option<Vec<IpNet>>` fields.
    pub mod option {
        use ipnet::IpNet;
        use serde::Deserializer;
        use serde::de::Error;

        /// Deserialize `v`, `[v, …]`, or none into `Option<Vec<IpNet>>`.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<Vec<IpNet>>, D::Error> {
            let raw: Option<Vec<String>> =
                crate::config::values::one_or_many::option::deserialize(d)?;
            raw.map(|v| {
                v.iter()
                    .map(|s| super::parse(s).map_err(Error::custom))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
        }
    }
}

/// The duration-string grammar: `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`,
/// `d`, `w`, `M` (month, year/12), `y` (year, 365.25d) plus word
/// aliases — in compound (`"2h 37m"`) or fractional (`"1.5h"`) form.
/// A unit is required; the bare string `"0"` is the only unit-less
/// exception.
fn duration_parser() -> &'static CustomDurationParser<'static> {
    static PARSER: std::sync::LazyLock<CustomDurationParser<'static>> =
        std::sync::LazyLock::new(|| {
            use TimeUnit::*;
            CustomDurationParserBuilder::new()
                .time_units(&[
                    CustomTimeUnit::with_default(NanoSecond, &["ns", "nsec", "nanos"]),
                    CustomTimeUnit::with_default(MicroSecond, &["us", "usec", "µs"]),
                    CustomTimeUnit::with_default(MilliSecond, &["ms", "msec", "millis"]),
                    CustomTimeUnit::with_default(
                        Second,
                        &["s", "sec", "secs", "second", "seconds"],
                    ),
                    CustomTimeUnit::with_default(
                        Minute,
                        &["m", "min", "mins", "minute", "minutes"],
                    ),
                    CustomTimeUnit::with_default(Hour, &["h", "hr", "hrs", "hour", "hours"]),
                    CustomTimeUnit::with_default(Day, &["d", "day", "days"]),
                    CustomTimeUnit::with_default(Week, &["w", "wk", "wks", "week", "weeks"]),
                    CustomTimeUnit::with_default(Month, &["M", "month", "months"]),
                    CustomTimeUnit::with_default(Year, &["y", "yr", "yrs", "year", "years"]),
                ])
                .allow_time_unit_delimiter()
                .parse_multiple(None)
                .disable_infinity()
                .disable_exponent()
                .build()
        });
    &PARSER
}

/// Parse a duration string like `"180d"` or `"1.5h"`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    // fundu defaults a unit-less number to seconds — here every
    // number must carry a unit (`"0"` above stays the exception)
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if !c.is_ascii_digit() {
            continue;
        }
        // consume the rest of the number incl. any fraction
        while matches!(chars.peek(), Some(d) if d.is_ascii_digit()) {
            chars.next();
        }
        if matches!(chars.peek(), Some('.')) {
            chars.next();
            while matches!(chars.peek(), Some(d) if d.is_ascii_digit()) {
                chars.next();
            }
        }
        // whitespace may separate the number and its unit ("15 min")
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        if !matches!(chars.peek(), Some(c) if c.is_alphabetic()) {
            return Err(format!(
                "invalid duration {s:?} — every number needs a unit, e.g. \"30s\", \"5m\", \"1h\" (a bare \"0\" means zero)"
            ));
        }
    }
    let d = duration_parser()
        .parse(s)
        .map_err(|e| format!("invalid duration {s:?}: {e}"))?;
    // fundu saturates overflowing input at Duration::MAX — reject it
    // like humantime did, so a typo can't pin a timeout forever
    let d = Duration::try_from(d).map_err(|_| format!("invalid duration {s:?}"))?;
    if d == Duration::MAX {
        return Err(format!(
            "duration {s:?} is too large to represent — check the unit for a typo"
        ));
    }
    Ok(d)
}

/// Canonical short form for a [`Duration`]: the largest unit that
/// divides it evenly (`"180d"`, `"2h"`, `"9001500ms"`). Used when
/// serializing durations back out (`verd config`, schema defaults).
pub fn format_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    const UNITS: [(u128, &str); 7] = [
        (86_400_000_000_000, "d"),
        (3_600_000_000_000, "h"),
        (60_000_000_000, "m"),
        (1_000_000_000, "s"),
        (1_000_000, "ms"),
        (1_000, "us"),
        (1, "ns"),
    ];
    for (unit_ns, suffix) in UNITS {
        if ns >= unit_ns && ns.is_multiple_of(unit_ns) {
            return format!("{}{}", ns / unit_ns, suffix);
        }
    }
    // every nonzero duration is an exact multiple of `ns` — only
    // Duration::ZERO falls through
    "0s".to_string()
}

/// Serde adapter for [`Duration`] fields: duration strings only
/// (`"30s"`, `"180d"`). Serializes as the compact canonical string.
pub mod duration {
    use std::time::Duration;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Deserialize a duration string like `"180d"`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        super::parse_duration(&s).map_err(Error::custom)
    }

    /// Serialize as `"180d"`.
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::format_duration(*d))
    }

    /// Same for `Option<Duration>` fields.
    pub mod option {
        use std::time::Duration;

        use serde::de::Error;
        use serde::{Deserialize, Deserializer, Serializer};

        /// Deserialize `null` or a duration string.
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
            Option::<String>::deserialize(d)?
                .map(|s| super::super::parse_duration(&s).map_err(Error::custom))
                .transpose()
        }

        /// Serialize `null` or `"180d"`.
        pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
            match d {
                Some(d) => s.serialize_str(&super::super::format_duration(*d)),
                None => s.serialize_none(),
            }
        }
    }
}

/// A byte size parsed from `123`, `"123B"`, `"16KiB"`, `"10MB"`, `"4GiB"`.
/// Unit-less strings and integers mean bytes. `K`/`M`/`G` suffixes are
/// decimal (×1000); `Ki`/`Mi`/`Gi` are binary (×1024).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// Construct a size in bytes.
    pub const fn bytes(n: u64) -> Self {
        Self(n)
    }
    /// Construct a size in kibibytes.
    pub const fn kib(n: u64) -> Self {
        Self(n * 1024)
    }
    /// Construct a size in mebibytes.
    pub const fn mib(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }
    /// Construct a size in gibibytes.
    pub const fn gib(n: u64) -> Self {
        Self(n * 1024 * 1024 * 1024)
    }

    /// Parse a human size string.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(n) = s.parse::<u64>() {
            return Ok(Self(n));
        }
        let split = s
            .find(|c: char| c.is_ascii_alphabetic())
            .ok_or_else(|| {
                format!("invalid byte size {s:?} — expected a byte count or a size like \"512KiB\" or \"10MB\"")
            })?;
        let (num, unit) = s.split_at(split);
        let num: f64 = num.trim().parse().map_err(|_| {
            format!(
                "invalid byte size {s:?} — the number must be numeric, e.g. \"512KiB\" or \"10MB\""
            )
        })?;
        let factor: u64 = match unit.trim().to_ascii_lowercase().as_str() {
            "b" => 1,
            "k" | "kb" => 1000,
            "m" | "mb" => 1000 * 1000,
            "g" | "gb" => 1000 * 1000 * 1000,
            "t" | "tb" => 1000 * 1000 * 1000 * 1000,
            "kib" => 1024,
            "mib" => 1024 * 1024,
            "gib" => 1024 * 1024 * 1024,
            "tib" => 1024 * 1024 * 1024 * 1024,
            _ => {
                return Err(format!(
                    "invalid byte size {s:?} — unknown unit; use B, KB, MB, GB, TB or KiB, MiB, GiB, TiB (e.g. \"16MiB\")"
                ));
            }
        };
        Ok(Self((num * factor as f64) as u64))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: u64 = 1024;
        const MIB: u64 = KIB * 1024;
        const GIB: u64 = MIB * 1024;
        if self.0.is_multiple_of(GIB) && self.0 >= GIB {
            write!(f, "{}GiB", self.0 / GIB)
        } else if self.0.is_multiple_of(MIB) && self.0 >= MIB {
            write!(f, "{}MiB", self.0 / MIB)
        } else if self.0.is_multiple_of(KIB) && self.0 >= KIB {
            write!(f, "{}KiB", self.0 / KIB)
        } else {
            write!(f, "{}B", self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        super::model::shorthand(d)
    }
}

impl<'de> super::model::Shorthand<'de> for ByteSize {
    const EXPECTING: &'static str = "a byte count or a size string like \"10MiB\"";
    fn from_int(n: i64) -> Option<Self> {
        u64::try_from(n).ok().map(Self)
    }
    fn from_uint(n: u64) -> Option<Self> {
        Some(Self(n))
    }
    fn from_str(s: &str) -> Option<Self> {
        Self::parse(s).ok()
    }
    fn from_map<A: serde::de::MapAccess<'de>>(_: A) -> Result<Self, A::Error> {
        Err(serde::de::Error::custom(Self::EXPECTING))
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// A rate like `100/s`, `600/m`, `10000/h`, `50000/day`, or `10/30s`
/// for arbitrary periods. Units: `s`, `m`, `h`, `d` or the words
/// `second`, `minute`, `hour`, `day` (also plural), or a duration
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
pub struct RateSpec {
    /// Number of permits granted per `period`.
    pub permits: u64,
    /// Length of one period.
    pub period: Duration,
}

impl RateSpec {
    /// Tokens granted per second, as a float.
    pub fn per_second(&self) -> f64 {
        self.permits as f64 / self.period.as_secs_f64()
    }

    /// Parse a rate string.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (num, unit) = s.split_once('/').ok_or_else(|| {
            format!("invalid rate {s:?} — expected a count/period like \"100/s\", \"600/m\", or \"10/30s\"")
        })?;
        let permits: u64 = num.trim().parse().map_err(|_| {
            format!("invalid rate {s:?} — the count must be a positive integer, e.g. \"100/s\"")
        })?;
        let period = match unit.trim().to_ascii_lowercase().as_str() {
            "s" | "sec" | "second" | "seconds" => Duration::from_secs(1),
            "m" | "min" | "minute" | "minutes" => Duration::from_secs(60),
            "h" | "hr" | "hour" | "hours" => Duration::from_secs(3600),
            "d" | "day" | "days" => Duration::from_secs(86400),
            other => parse_duration(other).map_err(|_| {
                format!("invalid rate {s:?} — the period must be s, m, h, d, or a duration like \"30s\" (e.g. \"10/30s\")")
            })?,
        };
        Ok(Self { permits, period })
    }
}

impl fmt::Display for RateSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unit = match self.period.as_secs() {
            1 => "s",
            60 => "m",
            3600 => "h",
            86400 => "d",
            secs => return write!(f, "{}/{}s", self.permits, secs),
        };
        write!(f, "{}/{}", self.permits, unit)
    }
}

impl<'de> Deserialize<'de> for RateSpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(D::Error::custom)
    }
}

impl Serialize for RateSpec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parses_unit_matrix() {
        // the full unit set with its aliases — the grammar documented
        // in docs/book/src/configuration.md
        for (s, want) in [
            ("33ns", Duration::new(0, 33)),
            ("17nsec", Duration::new(0, 17)),
            ("17nanos", Duration::new(0, 17)),
            ("78us", Duration::new(0, 78_000)),
            ("3usec", Duration::new(0, 3_000)),
            ("163µs", Duration::new(0, 163_000)),
            ("6ms", Duration::new(0, 6_000_000)),
            ("31msec", Duration::new(0, 31_000_000)),
            ("3000s", Duration::new(3000, 0)),
            ("300sec", Duration::new(300, 0)),
            ("50seconds", Duration::new(50, 0)),
            ("100m", Duration::new(6000, 0)),
            ("12min", Duration::new(720, 0)),
            ("1minute", Duration::new(60, 0)),
            ("2h", Duration::new(7200, 0)),
            ("7hr", Duration::new(25200, 0)),
            ("24hours", Duration::new(86400, 0)),
            ("1day", Duration::new(86400, 0)),
            ("365d", Duration::new(31_536_000, 0)),
            ("52w", Duration::new(31_449_600, 0)),
            ("2weeks", Duration::new(1_209_600, 0)),
            ("12M", Duration::new(31_557_600, 0)),
            ("1month", Duration::new(2_629_800, 0)),
            ("17y", Duration::new(536_479_200, 0)),
            ("1year", Duration::new(31_557_600, 0)),
        ] {
            assert_eq!(parse_duration(s).unwrap(), want, "{s}");
        }
    }

    #[test]
    fn duration_compound_fractional_and_rejects() {
        // compound with and without separators, fractions
        assert_eq!(parse_duration("2h37m").unwrap(), Duration::new(9420, 0));
        assert_eq!(parse_duration("2h 37m").unwrap(), Duration::new(9420, 0));
        assert_eq!(
            parse_duration("20 min 17 nsec").unwrap(),
            Duration::new(1200, 17)
        );
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::new(5400, 0));
        assert_eq!(
            parse_duration("4.2s").unwrap(),
            Duration::new(4, 200_000_000)
        );
        // bare "0" is the only unit-less value
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert!(parse_duration("30").is_err());
        assert!(parse_duration("1 5h").is_err());
        assert!(parse_duration("2h30").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("h").is_err());
        // overflow errors rather than pinning a duration forever
        assert!(parse_duration("100000000000000000000s").is_err());
        assert!(parse_duration("10000000000000y").is_err());
    }

    #[test]
    fn duration_format_roundtrips() {
        // canonical form stays single-unit; compounds must re-parse
        for d in [
            Duration::ZERO,
            Duration::from_secs(30),
            Duration::from_secs(180 * 86400),
            Duration::new(9420, 0),
            Duration::new(9001, 500_000_000),
            Duration::new(31_557_600 + 2_629_800 + 90, 123_456_789),
        ] {
            assert_eq!(parse_duration(&format_duration(d)).unwrap(), d);
        }
        // largest exact unit wins
        assert_eq!(format_duration(Duration::new(9420, 0)), "157m");
        assert_eq!(
            format_duration(Duration::new(9001, 500_000_000)),
            "9001500ms"
        );
        assert_eq!(format_duration(Duration::ZERO), "0s");
    }

    #[test]
    fn byte_size_parses_units() {
        assert_eq!(ByteSize::parse("1024").unwrap().0, 1024);
        assert_eq!(ByteSize::parse("1KiB").unwrap().0, 1024);
        assert_eq!(ByteSize::parse("16KiB").unwrap().0, 16 * 1024);
        assert_eq!(ByteSize::parse("1MB").unwrap().0, 1_000_000);
        assert_eq!(ByteSize::parse("1.5GiB").unwrap().0, 1610612736);
        assert!(ByteSize::parse("banana").is_err());
    }

    #[test]
    fn byte_size_displays() {
        assert_eq!(ByteSize::kib(16).to_string(), "16KiB");
        assert_eq!(ByteSize::bytes(100).to_string(), "100B");
    }

    #[test]
    fn rate_spec_parses() {
        let r = RateSpec::parse("100/s").unwrap();
        assert_eq!(r.permits, 100);
        assert_eq!(r.period, Duration::from_secs(1));
        let r = RateSpec::parse("600/minute").unwrap();
        assert_eq!(r.period, Duration::from_secs(60));
        assert!((r.per_second() - 10.0).abs() < 1e-9);
        assert!(RateSpec::parse("100").is_err());
        assert!(RateSpec::parse("x/s").is_err());
    }

    #[test]
    fn byte_size_remaining_units_and_errors() {
        assert_eq!(ByteSize::parse("2T").unwrap().0, 2_000_000_000_000);
        assert_eq!(ByteSize::parse("2TiB").unwrap().0, 2 * 1024_u64.pow(4));
        assert_eq!(ByteSize::parse("1K").unwrap().0, 1000);
        assert_eq!(ByteSize::parse("2 G").unwrap().0, 2_000_000_000);
        assert!(ByteSize::parse("1PB").is_err());
        assert!(ByteSize::parse("xB").is_err());
        // serde paths: integer and string forms, plus a deserialize error
        assert_eq!(
            toml::from_str::<ByteSizeHolder>("v = 4096").unwrap().v.0,
            4096
        );
        assert!(toml::from_str::<ByteSizeHolder>("v = \"bogus\"").is_err());
        // Serialize round-trips through Display
        let mut out = String::new();
        serde::Serialize::serialize(&ByteSize::mib(1), toml::ser::ValueSerializer::new(&mut out))
            .unwrap();
        assert_eq!(out, "\"1MiB\"");
    }

    #[derive(serde::Deserialize)]
    struct ByteSizeHolder {
        v: ByteSize,
    }

    #[test]
    fn byte_size_full_u64_range() {
        // TOML integers are i64; unsigned-capable formats drive
        // `visit_u64`, which used to narrow through i64 and reject
        // everything past `i64::MAX` — the full range must parse.
        for n in [u64::MAX, i64::MAX as u64 + 1] {
            let b = ByteSize::deserialize(serde::de::value::U64Deserializer::<
                serde::de::value::Error,
            >::new(n))
            .unwrap();
            assert_eq!(b.0, n);
        }
    }

    #[test]
    fn byte_size_display_all_brackets() {
        assert_eq!(ByteSize::gib(4).to_string(), "4GiB");
        assert_eq!(ByteSize::mib(10).to_string(), "10MiB");
        assert_eq!(ByteSize::kib(16).to_string(), "16KiB");
        assert_eq!(ByteSize::bytes(513).to_string(), "513B");
        // not an exact multiple falls through to bytes
        assert_eq!(ByteSize::bytes(1025).to_string(), "1025B");
    }

    #[test]
    fn rate_spec_all_units_and_display() {
        assert_eq!(RateSpec::parse("1/sec").unwrap().period.as_secs(), 1);
        assert_eq!(RateSpec::parse("1/hour").unwrap().period.as_secs(), 3600);
        assert_eq!(RateSpec::parse("5/day").unwrap().period.as_secs(), 86400);
        assert!(RateSpec::parse("1/fortnight").is_err());
        // Display: each canonical unit plus the seconds fallback
        assert_eq!(RateSpec::parse("100/s").unwrap().to_string(), "100/s");
        assert_eq!(RateSpec::parse("5/m").unwrap().to_string(), "5/m");
        assert_eq!(RateSpec::parse("5/h").unwrap().to_string(), "5/h");
        assert_eq!(RateSpec::parse("5/d").unwrap().to_string(), "5/d");
        let odd = RateSpec {
            permits: 7,
            period: Duration::from_secs(90),
        };
        assert_eq!(odd.to_string(), "7/90s");
        let mut out = String::new();
        serde::Serialize::serialize(
            &RateSpec::parse("1/s").unwrap(),
            toml::ser::ValueSerializer::new(&mut out),
        )
        .unwrap();
        assert_eq!(out, "\"1/s\"");
        assert!(toml::from_str::<RateHolder>("r = \"nope\"").is_err());
    }

    #[derive(serde::Deserialize)]
    struct RateHolder {
        #[allow(dead_code)]
        r: RateSpec,
    }
}
