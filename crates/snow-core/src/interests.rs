//! Interest tags and ephemeral profiles: what goes into the bucket, the PSI and
//! the profile message, including the compile-time adult-content gate.
use crate::api::{Config, UserProfile};
use snow_proto::{Profile, MAX_PROFILE_FIELD};

/// Adult tags live in their own namespace, so they only match other adult tags.
pub const ADULT_PREFIX: &str = "18+:";
/// "No bucket": random matching.
pub const RANDOM_BUCKET: u8 = 255;

pub const ADULT_ENABLED: bool = cfg!(feature = "adult_tags");

/// Everything we compare in the PSI, normalized; adult tags only if enabled.
pub fn psi_tags(cfg: &Config) -> Vec<String> {
    let mut out: Vec<String> = cfg
        .tags
        .iter()
        .filter_map(|t| snow_psi::normalize(t))
        .collect();
    if ADULT_ENABLED {
        out.extend(
            cfg.adult_tags
                .iter()
                .filter_map(|t| snow_psi::normalize(t))
                .map(|t| format!("{ADULT_PREFIX}{t}")),
        );
    }
    out
}

/// The server-visible bucket: explicit `bucket`, else the first tag's, else random.
///
/// Known limit: two people who share only a *secondary* tag land in different
/// buckets and won't meet; the primary tag is the one that drives matching.
pub fn bucket(cfg: &Config, unix_secs: u64) -> u8 {
    cfg.bucket.unwrap_or_else(|| {
        psi_tags(cfg).first().map_or(RANDOM_BUCKET, |t| {
            snow_psi::bucket(t, snow_psi::epoch(unix_secs))
        })
    })
}

fn field(s: &Option<String>) -> Option<String> {
    let s = s.as_deref()?.trim();
    if s.is_empty() {
        return None;
    }
    // Truncate on a char boundary to the wire limit.
    let mut end = s.len().min(MAX_PROFILE_FIELD);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Some(s[..end].to_string())
}

pub fn to_wire(p: &UserProfile) -> Profile {
    Profile {
        nickname: field(&p.nickname),
        mbti: field(&p.mbti),
        mood: field(&p.mood),
        adult_ok: ADULT_ENABLED && p.adult_ok,
    }
}

pub fn from_wire(p: Profile) -> UserProfile {
    UserProfile {
        nickname: field(&p.nickname),
        mbti: field(&p.mbti),
        mood: field(&p.mood),
        // A build without adult content never shows the flag, whatever the peer sent.
        adult_ok: ADULT_ENABLED && p.adult_ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(tags: &[&str], adult: &[&str]) -> Config {
        Config {
            server_url: String::new(),
            bucket: None,
            rotation_secs: None,
            paranoid: false,
            chaff_ms: None,
            tags: tags.iter().map(|s| s.to_string()).collect(),
            adult_tags: adult.iter().map(|s| s.to_string()).collect(),
            require_common_tag: true,
            profile: None,
            pins: vec![],
            tor_dir: None,
        }
    }

    #[test]
    fn bucket_comes_from_the_primary_tag() {
        let now = 1_800_000_000;
        assert_eq!(bucket(&cfg(&[], &[]), now), RANDOM_BUCKET);
        let b = bucket(&cfg(&["#Cats", "jazz"], &[]), now);
        assert_eq!(b, snow_psi::bucket("cats", snow_psi::epoch(now)));
        let mut c = cfg(&["cats"], &[]);
        c.bucket = Some(7);
        assert_eq!(bucket(&c, now), 7);
    }

    #[test]
    fn adult_tags_follow_the_build_flag() {
        let t = psi_tags(&cfg(&["Cats"], &["X"]));
        if ADULT_ENABLED {
            assert_eq!(t, vec!["cats".to_string(), "18+:x".to_string()]);
        } else {
            assert_eq!(t, vec!["cats".to_string()]);
        }
        let p = UserProfile {
            adult_ok: true,
            ..Default::default()
        };
        assert_eq!(to_wire(&p).adult_ok, ADULT_ENABLED);
        let incoming = Profile {
            adult_ok: true,
            ..Default::default()
        };
        assert_eq!(from_wire(incoming).adult_ok, ADULT_ENABLED);
    }

    #[test]
    fn profile_fields_are_trimmed_and_bounded() {
        let p = to_wire(&UserProfile {
            nickname: Some("  ".into()),
            mbti: Some(" INTJ ".into()),
            mood: Some("雪".repeat(40)),
            adult_ok: false,
        });
        assert_eq!(p.nickname, None);
        assert_eq!(p.mbti.as_deref(), Some("INTJ"));
        let mood = p.mood.unwrap();
        assert!(mood.len() <= MAX_PROFILE_FIELD && mood.chars().all(|c| c == '雪'));
    }
}
