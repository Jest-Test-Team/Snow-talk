//! Interest tags users pick from (Tinder "Passions"-style chips), shared by
//! both apps so everyone selects the same canonical strings. The `key` (the
//! zh-Hant label) is what goes into the PSI and the bucket hash; `zh` / `en`
//! are display labels only, so a zh and an en user picking "咖啡" / "Coffee"
//! still match.
//!
//! No "investing" / money tags on purpose: those are exactly the scam openers
//! `snow-safety` warns about.
//!
//! **Adult tags** ([`adult_tag_catalog`]) exist only in builds with the
//! `adult_tags` feature (Android / sideload; the iOS build compiles them out
//! for App Store rules). The apps show them only after an explicit 18+
//! confirmation and pass them in `Config::adult_tags`, where the core puts them
//! in their own `18+:` namespace: they only ever match other adult tags.
//! Modeled on mainstream adult-site category names, but restricted to legal
//! content between consenting adults: nothing involving minors or "teen"
//! framing, no incest/"step" themes, no non-consent, and no paid sex or
//! solicitation (which `snow-safety` also flags).

/// How many tags a user may pick (the core accepts up to 16).
pub const MAX_TAGS: u32 = 10;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TagInfo {
    /// Canonical value: pass this in `Config::tags`.
    pub key: String,
    pub zh: String,
    pub en: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TagCategory {
    pub zh: String,
    pub en: String,
    /// Pick at most one tag from this category (e.g. what you're looking for).
    pub single_choice: bool,
    /// 18+ content: show only after an age confirmation; pass in `adult_tags`.
    pub adult: bool,
    pub tags: Vec<TagInfo>,
}

/// `(zh, en)` display labels; the zh label is also the canonical key.
type Labels = &'static [(&'static str, &'static str)];

/// What you're looking for, Tinder "relationship goals" style, plus our own:
/// someone to keep in touch with long-term with maximum privacy (the
/// persistent-channel feature, Phase 14). Single choice; matched only via the PSI.
const LOOKING_FOR: (&str, &str, Labels) = (
    "交往目標",
    "Looking for",
    &[
        ("長期伴侶", "Long-term partner"),
        ("長期為主，短期也可", "Long-term, open to short"),
        ("短期為主，長期也可", "Short-term, open to long"),
        ("短期關係", "Short-term fun"),
        ("新朋友", "New friends"),
        ("還在想", "Still figuring it out"),
        (
            "極致隱私的長久聯繫",
            "Ultimate-privacy long-term connection",
        ),
    ],
);

const ADULT: &[(&str, &str, Labels)] = &[
    (
        "18+ 聊天",
        "18+ chat",
        &[
            ("曖昧調情", "Flirting"),
            ("性愛話題", "Sex talk"),
            ("深夜色色", "Late-night spicy talk"),
            ("分享性幻想", "Sharing fantasies"),
            ("性教育", "Sex ed"),
            ("安全性行為", "Safer sex"),
        ],
    ),
    (
        "18+ 喜好",
        "18+ preferences",
        &[
            ("成人影片", "Adult videos"),
            ("業餘自拍", "Amateur"),
            ("角色扮演", "Role-play"),
            ("制服", "Uniforms"),
            ("成人Cosplay", "Adult cosplay"),
            ("情趣用品", "Toys"),
            ("情趣內衣", "Lingerie"),
            ("BDSM", "BDSM"),
            ("綑綁", "Bondage"),
            ("支配與服從", "Dom / sub"),
            ("戀足", "Feet"),
            ("戀物", "Fetish"),
            ("露出幻想", "Exhibitionism fantasy"),
            ("多人", "Threesome / group"),
            ("熟男熟女", "MILF / DILF"),
            ("成人動漫", "Hentai"),
            ("成人ASMR", "Erotic ASMR"),
        ],
    ),
    (
        "18+ 取向與關係",
        "18+ orientation & arrangements",
        &[
            ("異性戀", "Straight"),
            ("男同志", "Gay"),
            ("女同志", "Lesbian"),
            ("雙性戀", "Bisexual"),
            ("跨性別", "Trans"),
            ("酷兒", "Queer"),
            ("開放式關係", "Open relationship"),
            ("換伴", "Swinging"),
            ("只在線上", "Online only"),
        ],
    ),
];

const CATALOG: &[(&str, &str, Labels)] = &[
    (
        "聊天心情",
        "Vibe",
        &[
            ("交朋友", "Making friends"),
            ("純聊天", "Just chatting"),
            ("深夜談心", "Late-night talks"),
            ("找飯友", "Food buddy"),
            ("抒發心情", "Venting"),
            ("一起打電動", "Gaming buddy"),
        ],
    ),
    (
        "生活",
        "Lifestyle",
        &[
            ("咖啡", "Coffee"),
            ("美食", "Foodie"),
            ("手搖飲", "Bubble tea"),
            ("夜市", "Night markets"),
            ("烘焙", "Baking"),
            ("品酒", "Wine"),
            ("貓派", "Cat person"),
            ("狗派", "Dog person"),
            ("植物", "Plants"),
            ("夜貓子", "Night owl"),
            ("早起", "Early bird"),
        ],
    ),
    (
        "運動",
        "Sports",
        &[
            ("健身", "Gym"),
            ("跑步", "Running"),
            ("爬山", "Hiking"),
            ("瑜珈", "Yoga"),
            ("游泳", "Swimming"),
            ("籃球", "Basketball"),
            ("棒球", "Baseball"),
            ("羽球", "Badminton"),
            ("單車", "Cycling"),
            ("衝浪", "Surfing"),
            ("露營", "Camping"),
        ],
    ),
    (
        "娛樂",
        "Entertainment",
        &[
            ("電影", "Movies"),
            ("追劇", "TV series"),
            ("韓劇", "K-drama"),
            ("動漫", "Anime"),
            ("綜藝", "Variety shows"),
            ("Podcast", "Podcasts"),
            ("脫口秀", "Stand-up"),
            ("桌遊", "Board games"),
            ("電玩", "Video games"),
            ("手遊", "Mobile games"),
            ("密室逃脫", "Escape rooms"),
        ],
    ),
    (
        "音樂",
        "Music",
        &[
            ("流行音樂", "Pop"),
            ("K-pop", "K-pop"),
            ("獨立音樂", "Indie"),
            ("搖滾", "Rock"),
            ("嘻哈", "Hip-hop"),
            ("爵士", "Jazz"),
            ("古典樂", "Classical"),
            ("音樂祭", "Music festivals"),
            ("唱歌", "Karaoke"),
            ("樂器", "Playing music"),
        ],
    ),
    (
        "藝文",
        "Arts",
        &[
            ("閱讀", "Reading"),
            ("寫作", "Writing"),
            ("攝影", "Photography"),
            ("繪畫", "Drawing"),
            ("設計", "Design"),
            ("看展", "Exhibitions"),
            ("劇場", "Theatre"),
            ("手作", "Crafts"),
        ],
    ),
    (
        "旅行",
        "Travel",
        &[
            ("旅行", "Travel"),
            ("自由行", "Backpacking"),
            ("日本", "Japan"),
            ("韓國", "Korea"),
            ("歐洲", "Europe"),
            ("環島", "Round-Taiwan trips"),
            ("公路旅行", "Road trips"),
            ("潛水", "Diving"),
        ],
    ),
    (
        "學習與話題",
        "Learning & topics",
        &[
            ("語言交換", "Language exchange"),
            ("英文", "English"),
            ("日文", "Japanese"),
            ("程式", "Coding"),
            ("科技", "Tech"),
            ("心理學", "Psychology"),
            ("星座", "Astrology"),
            ("MBTI", "MBTI"),
            ("塔羅", "Tarot"),
        ],
    ),
];

/// The tag picker's categories, in display order.
#[uniffi::export]
pub fn tag_catalog() -> Vec<TagCategory> {
    std::iter::once((&LOOKING_FOR, true))
        .chain(CATALOG.iter().map(|c| (c, false)))
        .map(|(c, single)| category(c, single, false))
        .collect()
}

/// Adult categories: empty unless this build has the `adult_tags` feature.
#[uniffi::export]
pub fn adult_tag_catalog() -> Vec<TagCategory> {
    if !crate::interests::ADULT_ENABLED {
        return Vec::new();
    }
    ADULT.iter().map(|c| category(c, false, true)).collect()
}

/// Whether this build may show adult content at all (false on iOS builds).
#[uniffi::export]
pub fn adult_content_enabled() -> bool {
    crate::interests::ADULT_ENABLED
}

fn category(c: &(&str, &str, Labels), single_choice: bool, adult: bool) -> TagCategory {
    let (zh, en, tags) = c;
    TagCategory {
        zh: zh.to_string(),
        en: en.to_string(),
        single_choice,
        adult,
        tags: tags
            .iter()
            .map(|(zh, en)| TagInfo {
                key: zh.to_string(),
                zh: zh.to_string(),
                en: en.to_string(),
            })
            .collect(),
    }
}

#[uniffi::export]
pub fn max_tags() -> u32 {
    MAX_TAGS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adult_catalog_is_gated() {
        assert_eq!(
            adult_tag_catalog().is_empty(),
            !cfg!(feature = "adult_tags")
        );
        assert_eq!(adult_content_enabled(), cfg!(feature = "adult_tags"));
        let c = tag_catalog();
        assert!(c[0].single_choice && !c.iter().any(|c| c.adult));
        assert!(c[0].tags.iter().any(|t| t.key == "極致隱私的長久聯繫"));
    }

    #[test]
    fn keys_are_unique_and_survive_normalization() {
        let mut seen = std::collections::HashSet::new();
        let adult = ADULT.iter().map(|c| category(c, false, true));
        for c in tag_catalog().into_iter().chain(adult) {
            for t in c.tags {
                // The key must already be in normalized form, or two users
                // picking the same chip could hash differently.
                let n = snow_psi::normalize(&t.key).expect("normalizes");
                assert!(seen.insert(n.clone()), "duplicate tag {n}");
            }
        }
        assert!(seen.len() > 60);
    }
}
