//! On-device message screening. Runs on received text only; nothing leaves the phone.
//!
//! This is the rule-based first stage: it catches the common funnels of
//! romance/investment scams on anonymous chat in Taiwan — moving the victim
//! off-platform (LINE / Telegram / phone), links and URL shorteners, crypto
//! wallets, "guaranteed profit" pitches, payment / game-card requests, online
//! gambling and paid-sex solicitation. A downloaded ML model can be layered on
//! top later; [`Verdict`] already carries a score so the two can be combined.
//!
//! Text is normalized first (NFKC, lowercase, zero-width characters removed) and
//! also checked in a "squashed" form with separators removed and Chinese digits
//! converted, so `０９１２ ３４５ ６７８`, `零九一二三四五六七八` and `l i n e` are caught.
//!
//! The result never blocks a message; the UI blurs it ([`Level::Blur`]) or adds
//! a warning ([`Level::Caution`]) and the user can still tap to read.
use regex::{Regex, RegexSet};
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    Link,
    Shortener,
    LineId,
    Telegram,
    Phone,
    Email,
    Crypto,
    /// A crypto wallet address (ETH / TRON).
    Wallet,
    Investment,
    MoneyTransfer,
    /// Game points / gift cards: the classic stranger scam in Taiwan.
    GiftCard,
    Gambling,
    Solicitation,
}

impl Flag {
    fn weight(self) -> f32 {
        match self {
            Flag::Link | Flag::Email => 0.3,
            Flag::Phone => 0.35,
            Flag::MoneyTransfer => 0.35,
            Flag::Crypto | Flag::Investment => 0.4,
            Flag::Wallet => 0.5,
            Flag::LineId | Flag::Telegram => 0.45,
            Flag::Shortener | Flag::Gambling => 0.5,
            Flag::Solicitation | Flag::GiftCard => 0.65,
        }
    }

    /// Moves the conversation somewhere else.
    fn is_contact(self) -> bool {
        matches!(
            self,
            Flag::Link
                | Flag::Shortener
                | Flag::LineId
                | Flag::Telegram
                | Flag::Phone
                | Flag::Email
        )
    }

    /// Involves money.
    fn is_money(self) -> bool {
        matches!(
            self,
            Flag::Crypto
                | Flag::Wallet
                | Flag::Investment
                | Flag::MoneyTransfer
                | Flag::GiftCard
                | Flag::Gambling
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Clean,
    /// Show with a warning banner.
    Caution,
    /// Blur until the user taps to reveal.
    Blur,
}

pub const CAUTION_AT: f32 = 0.3;
pub const BLUR_AT: f32 = 0.6;

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Sorted, de-duplicated.
    pub flags: Vec<Flag>,
    /// 0..1, combined from the flags.
    pub score: f32,
}

impl Verdict {
    pub fn level(&self) -> Level {
        if self.score >= BLUR_AT {
            Level::Blur
        } else if self.score >= CAUTION_AT {
            Level::Caution
        } else {
            Level::Clean
        }
    }
}

struct Rules {
    /// Checked on the normalized text.
    text: Vec<(Flag, Regex)>,
    /// Checked on the squashed text (no separators, ASCII digits).
    squashed: Vec<(Flag, Regex)>,
    keywords: Vec<(Flag, RegexSet)>,
}

fn rules() -> &'static Rules {
    static R: OnceLock<Rules> = OnceLock::new();
    R.get_or_init(|| {
        let re = |s: &str| Regex::new(s).expect("static regex");
        let shorteners = r"(?:bit\.ly|reurl\.cc|tinyurl\.com|lihi\d?\.(?:cc|com)|pse\.is|ppt\.cc|is\.gd|cutt\.ly|shorturl\.at|t\.co|goo\.gl|rb\.gy|s\.id|0rz\.tw)/";
        let tlds = "com|net|org|io|tw|cc|xyz|top|me|ly|gl|link|app|site|vip|shop|info|biz|club|online|live|fun|asia|hk|cn|co|ai";
        Rules {
            text: vec![
                (Flag::Shortener, re(shorteners)),
                (Flag::Link, re(r"(?:https?://|www\.)\S+")),
                (
                    Flag::Link,
                    re(&format!(r"\b[a-z0-9][a-z0-9-]{{1,62}}\.(?:{tlds})\b(?:/\S*)?")),
                ),
                (Flag::LineId, re(r"line\.me/|lin\.ee/")),
                (
                    Flag::LineId,
                    re(r"(?:\bline|賴)\s*(?:id)?\s*[:：]\s*@?[a-z0-9._-]{3,}"),
                ),
                (Flag::Telegram, re(r"t\.me/|telegram|\btg\s*[:：@]|飛機\s*[:：@]")),
                (Flag::Email, re(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")),
                (Flag::Wallet, re(r"\b0x[0-9a-f]{40}\b|\bt[1-9a-z]{33}\b")),
            ],
            squashed: vec![
                (Flag::Phone, re(r"(?:\+?886|0)9\d{8}")),
                (Flag::LineId, re(r"加賴|加我賴|加line|私賴|賴我|lineid|加我line|加個賴")),
                (Flag::Telegram, re(r"加飛機|telegram")),
                (Flag::Link, re(r"https?://")),
                (Flag::Shortener, re(shorteners)),
            ],
            keywords: [
                (
                    Flag::Crypto,
                    &[
                        "usdt", "泰達幣", "比特幣", "虛擬貨幣", "加密貨幣", "幣安", "trc20", "erc20",
                        "錢包地址", "挖礦", "交易所",
                    ][..],
                ),
                (
                    Flag::Investment,
                    &[
                        "保證獲利", "穩賺", "高報酬", "投資群", "帶單", "帶你賺", "老師帶", "飆股",
                        "內線", "代操", "被動收入", "翻倍", "零風險", "日賺", "月入", "保本",
                    ][..],
                ),
                (
                    Flag::MoneyTransfer,
                    &[
                        "匯款", "轉帳", "解除分期", "atm", "保證金", "手續費", "押金", "借錢", "先付",
                        "儲值",
                    ][..],
                ),
                (
                    Flag::GiftCard,
                    &["點數卡", "遊戲點數", "mycard", "gash", "代購點數", "禮物卡", "itunes卡"][..],
                ),
                (
                    Flag::Gambling,
                    &["博弈", "娛樂城", "百家樂", "運彩", "下注", "賭場", "彩金", "老虎機"][..],
                ),
                (
                    Flag::Solicitation,
                    &["外約", "援交", "包養", "約砲", "買春", "魚訊", "茶訊", "定點服務"][..],
                ),
            ]
            .into_iter()
            .map(|(f, words)| {
                let pats: Vec<String> = words.iter().map(|w| regex::escape(w)).collect();
                (f, RegexSet::new(pats).expect("static keywords"))
            })
            .collect(),
        }
    })
}

fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}' | '\u{00AD}')
}

pub fn normalize(text: &str) -> String {
    text.nfkc()
        .filter(|c| !is_invisible(*c))
        .collect::<String>()
        .to_lowercase()
}

/// Separators dropped, Chinese digits mapped, `點`/`dot` → `.`.
fn squash(norm: &str) -> String {
    let s = norm.replace("點", ".").replace("dot", ".");
    s.chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '_' | '·' | '、' | '*' | '~' | '|'))
        .map(|c| match c {
            '零' | '〇' | '洞' => '0',
            '一' | '壹' | '么' => '1',
            '二' | '貳' | '兩' => '2',
            '三' | '參' => '3',
            '四' | '肆' => '4',
            '五' | '伍' => '5',
            '六' | '陸' => '6',
            '七' | '柒' | '拐' => '7',
            '八' | '捌' => '8',
            '九' | '玖' | '勾' => '9',
            c => c,
        })
        .collect()
}

pub fn check(text: &str) -> Verdict {
    let r = rules();
    let norm = normalize(text);
    let sq = squash(&norm);
    let mut flags: Vec<Flag> = Vec::new();
    for (f, re) in &r.text {
        if re.is_match(&norm) {
            flags.push(*f);
        }
    }
    for (f, re) in &r.squashed {
        if re.is_match(&sq) {
            flags.push(*f);
        }
    }
    for (f, set) in &r.keywords {
        if set.is_match(&norm) || set.is_match(&sq) {
            flags.push(*f);
        }
    }
    flags.sort();
    flags.dedup();
    // A LINE / Telegram / shortener / e-mail match usually *is* the link; don't
    // count the same thing twice.
    let implied_link = flags.iter().any(|f| {
        matches!(
            f,
            Flag::Shortener | Flag::LineId | Flag::Telegram | Flag::Email
        )
    });
    let mut score = 1.0
        - flags
            .iter()
            .filter(|f| !(implied_link && **f == Flag::Link))
            .map(|f| 1.0 - f.weight())
            .product::<f32>();
    // Off-platform contact + money is the classic scam pattern.
    if flags.iter().any(|f| f.is_contact()) && flags.iter().any(|f| f.is_money()) {
        score = score.max(0.85);
    }
    Verdict { flags, score }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Flag::*;

    fn flags(t: &str) -> Vec<Flag> {
        check(t).flags
    }

    #[test]
    fn ordinary_chat_is_clean() {
        for t in [
            "你好～今天天氣好冷",
            "我住台北，平常喜歡爬山跟看電影",
            "哈哈哈 真的假的 😂",
            "下班了 好累",
            "我在學英文，想投資自己",
            "這部電影第2集比第1集好看",
            "我的號碼牌是 12 號",
            "Hi! I like jazz and hiking.",
            "2025年我去了日本三次",
        ] {
            let v = check(t);
            assert_eq!(v.level(), Level::Clean, "{t}: {v:?}");
        }
    }

    #[test]
    fn off_platform_contact() {
        assert_eq!(flags("加我賴 abc123"), vec![LineId]);
        assert_eq!(flags("line id: snow_girl88"), vec![LineId]);
        assert_eq!(flags("ＬＩＮＥ：ｓｎｏｗ８８"), vec![LineId]);
        assert_eq!(flags("https://line.me/ti/p/xyz"), vec![Link, LineId]);
        assert_eq!(flags("加 l i n e 聊"), vec![LineId]);
        assert_eq!(flags("tg: @snowman"), vec![Telegram]);
        assert_eq!(flags("t.me/scamgroup"), vec![Telegram]);
        assert_eq!(flags("我電話 0912-345-678"), vec![Phone]);
        assert_eq!(flags("０９１２ ３４５ ６７８"), vec![Phone]);
        assert_eq!(flags("零九一二三四五六七八"), vec![Phone]);
        assert_eq!(flags("+886 912 345 678"), vec![Phone]);
        assert_eq!(flags("寄到 a.b@example.com"), vec![Link, Email]);
        assert_eq!(flags("加\u{200B}賴"), vec![LineId]);
    }

    #[test]
    fn links_and_shorteners() {
        assert_eq!(flags("看這個 reurl.cc/abc"), vec![Link, Shortener]);
        assert_eq!(flags("bit點ly/xyz"), vec![Shortener]);
        assert_eq!(check("www.example.com").level(), Level::Caution);
        assert_eq!(check("lihi1.cc/AbCd 免費領").level(), Level::Caution);
    }

    #[test]
    fn scams_are_blurred() {
        for t in [
            "老師帶單保證獲利，加賴 abc",
            "USDT 轉到 TRC20 錢包地址 T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
            "儲值遊戲點數給我，我先付你一半",
            "娛樂城首儲送彩金 line.me/ti/p/abc",
            "外約 包養 私訊",
            "0912345678 投資群 日賺五千",
        ] {
            let v = check(t);
            assert_eq!(v.level(), Level::Blur, "{t}: {v:?}");
        }
    }

    #[test]
    fn single_money_mention_is_only_a_caution() {
        assert_eq!(check("我昨天去ATM領錢").level(), Level::Caution);
        assert_eq!(check("比特幣最近跌好多").level(), Level::Caution);
    }

    #[test]
    fn eth_address() {
        assert_eq!(
            flags("0x52908400098527886E0F7030069857D2E4169EE7"),
            vec![Wallet]
        );
        assert_eq!(check("https://line.me/ti/p/xyz").level(), Level::Caution);
    }
}
