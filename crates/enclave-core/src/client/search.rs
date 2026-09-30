//! Local message search (`docs/16-features.md`). Everything happens on the
//! device over the sealed store; nothing about a search leaves it.

use super::Client;
use crate::Result;

/// Where a hit is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// A 1:1 conversation.
    Contact([u8; 64]),
    /// A group.
    Group([u8; 32]),
}

/// A message that matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// Conversation.
    pub place: Place,
    /// Conversation name.
    pub name: String,
    /// Position in the conversation.
    pub seq: u64,
    /// Text around the first match.
    pub snippet: String,
    /// When it was sent or received.
    pub at: u64,
    /// Ours.
    pub outgoing: bool,
}

/// Characters of context on each side of the match.
const CONTEXT: usize = 40;

/// Whether every term of the query occurs in `text` (case-insensitive), and
/// if so a snippet around the first term.
fn matches(text: &str, terms: &[String]) -> Option<String> {
    let lower = text.to_lowercase();
    if !terms.iter().all(|t| lower.contains(t.as_str())) {
        return None;
    }
    // Lowercasing can change byte offsets, so find the match by characters.
    let chars: Vec<char> = text.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();
    let first: Vec<char> = terms[0].chars().collect();
    let at = if lower_chars.len() == chars.len() {
        lower_chars
            .windows(first.len())
            .position(|w| w == first.as_slice())
            .unwrap_or(0)
    } else {
        0
    };
    let start = at.saturating_sub(CONTEXT);
    let end = (at + first.len() + CONTEXT).min(chars.len());
    let mut s: String = chars[start..end].iter().collect();
    s = s.replace('\n', " ");
    if start > 0 {
        s.insert(0, '…');
    }
    if end < chars.len() {
        s.push('…');
    }
    Some(s)
}

impl Client {
    /// Messages containing every word of `query`, newest first, at most
    /// `limit`. Queries shorter than two characters find nothing.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Hit>> {
        let terms: Vec<String> = query
            .to_lowercase()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if terms.is_empty() || query.trim().chars().count() < 2 {
            return Ok(Vec::new());
        }
        let mut hits = Vec::new();
        for c in self.contacts() {
            for m in self.messages(&c.root)? {
                if m.deleted {
                    continue;
                }
                let text = match &m.attachment {
                    Some(a) if m.text.is_empty() => a.name.clone(),
                    Some(a) => format!("{} {}", a.name, m.text),
                    None => m.text.clone(),
                };
                if let Some(snippet) = matches(&text, &terms) {
                    hits.push(Hit {
                        place: Place::Contact(c.root),
                        name: c.name.clone(),
                        seq: m.seq,
                        snippet,
                        at: m.at,
                        outgoing: m.outgoing,
                    });
                }
            }
        }
        for g in self.groups() {
            for m in self.group_messages(&g.id)? {
                if let Some(snippet) = matches(&m.text, &terms) {
                    hits.push(Hit {
                        place: Place::Group(g.id),
                        name: g.name.clone(),
                        seq: m.seq,
                        snippet,
                        at: m.at,
                        outgoing: m.from.is_none(),
                    });
                }
            }
        }
        hits.sort_by(|a, b| b.at.cmp(&a.at).then(b.seq.cmp(&a.seq)));
        hits.truncate(limit);
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn terms_and_snippets() {
        let t = |q: &str| -> Vec<String> { q.split_whitespace().map(str::to_string).collect() };
        assert_eq!(
            matches("See you at the Café", &t("café")).as_deref(),
            Some("See you at the Café")
        );
        assert!(matches("See you at the café", &t("café tomorrow")).is_none());
        let long = format!("{}needle{}", "a".repeat(100), "b".repeat(100));
        let s = matches(&long, &t("needle")).unwrap();
        assert!(s.starts_with('…') && s.ends_with('…') && s.contains("needle"));
        assert!(s.chars().count() <= 2 * 40 + 6 + 2);
    }
}
