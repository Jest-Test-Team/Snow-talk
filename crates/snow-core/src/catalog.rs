//! Interest tags users pick from (Tinder "Passions"-style chips), shared by
//! both apps so everyone selects the same canonical strings. The `key` (the
//! zh-Hant label) is what goes into the PSI and the bucket hash; `zh` / `en`
//! are display labels only, so a zh and an en user picking "咖啡" / "Coffee"
//! still match.
//!
//! No "investing" / money tags on purpose: those are exactly the scam openers
//! `snow-safety` warns about.

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
    pub tags: Vec<TagInfo>,
}

/// `(zh, en)` display labels; the zh label is also the canonical key.
type Labels = &'static [(&'static str, &'static str)];

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
    CATALOG
        .iter()
        .map(|(zh, en, tags)| TagCategory {
            zh: zh.to_string(),
            en: en.to_string(),
            tags: tags
                .iter()
                .map(|(zh, en)| TagInfo {
                    key: zh.to_string(),
                    zh: zh.to_string(),
                    en: en.to_string(),
                })
                .collect(),
        })
        .collect()
}

#[uniffi::export]
pub fn max_tags() -> u32 {
    MAX_TAGS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_and_survive_normalization() {
        let mut seen = std::collections::HashSet::new();
        for c in tag_catalog() {
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
