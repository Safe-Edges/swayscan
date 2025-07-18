use std::path::Path;
use std::time::{Duration, Instant};

pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    
    if secs > 0 {
        format!("{}.{:03}s", secs, millis)
    } else {
        format!("{}ms", millis)
    }
}

pub fn is_sway_file<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("sw"))
        .unwrap_or(false)
}

pub fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{} {}", count, singular)
    } else {
        format!("{} {}", count, plural)
    }
}

pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
    
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
    
    pub fn elapsed_ms(&self) -> u128 {
        self.elapsed().as_millis()
    }
}

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
} 