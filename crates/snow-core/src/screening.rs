//! Maps `snow-safety` verdicts to the FFI types. Only received text is screened.
use crate::api::{SafetyFlag, SafetyLevel};
use snow_safety::{Flag, Level};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Safety {
    pub level: SafetyLevel,
    pub flags: Vec<SafetyFlag>,
}

impl Safety {
    pub fn clean() -> Self {
        Self {
            level: SafetyLevel::Clean,
            flags: Vec::new(),
        }
    }
}

pub fn screen(text: &str) -> Safety {
    let v = snow_safety::check(text);
    Safety {
        level: match v.level() {
            Level::Clean => SafetyLevel::Clean,
            Level::Caution => SafetyLevel::Caution,
            Level::Blur => SafetyLevel::Blur,
        },
        flags: v
            .flags
            .into_iter()
            .map(|f| match f {
                Flag::Link => SafetyFlag::Link,
                Flag::Shortener => SafetyFlag::Shortener,
                Flag::LineId => SafetyFlag::LineId,
                Flag::Telegram => SafetyFlag::Telegram,
                Flag::Phone => SafetyFlag::Phone,
                Flag::Email => SafetyFlag::Email,
                Flag::Crypto => SafetyFlag::Crypto,
                Flag::Wallet => SafetyFlag::Wallet,
                Flag::Investment => SafetyFlag::Investment,
                Flag::MoneyTransfer => SafetyFlag::MoneyTransfer,
                Flag::GiftCard => SafetyFlag::GiftCard,
                Flag::Gambling => SafetyFlag::Gambling,
                Flag::Solicitation => SafetyFlag::Solicitation,
            })
            .collect(),
    }
}
