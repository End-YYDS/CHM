use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum Month {
    Jan,
    Feb,
    Mar,
    Apr,
    May,
    Jun,
    Jul,
    Aug,
    Sep,
    Oct,
    Nov,
    Dec,
}

#[derive(Debug, Serialize)]
pub struct Login_Time {
    #[serde(rename = "Year")]
    pub year:  i64,
    #[serde(rename = "Month")]
    pub month: Month, // e.g., "Jan", "Feb", etc.
    #[serde(rename = "Day")]
    pub day:   i64,
    #[serde(rename = "Hour")]
    pub hour:  i64,
    #[serde(rename = "Min")]
    pub min:   i64,
}

// "Year": Int,
// "Month": enum (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec),
// "Day": Int,
// "Hour": Int,
// "Min": Int
