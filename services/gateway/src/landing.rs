//! The page a browser gets when it visits the gateway itself.
//!
//! A gateway is an API, so every browser navigation to it used to answer an empty 404: the operator
//! pasting their tunnel URL to check the box is up, the console's own gateway link, anyone clicking
//! through from the installer. A blank 404 reads as broken, and the one thing the visitor actually
//! wants, the console, is nowhere on it.
//!
//! What this page says is deliberately all it says. No version, no build, no counts: `/health`
//! withholds exactly those from an unauthenticated caller because they fingerprint the install, and
//! a landing page printing them would hand back what that guard exists to hold.

use crate::notify::console_base;

const TEMPLATE: &str = include_str!("../assets/landing.html");

/// The rendered page, pointed at the console this gateway is configured against.
///
/// `note` renders under the message when there is one: the fallback uses it to say the address was
/// not found without turning the page into an error page.
pub fn page(note: Option<&str>) -> String {
    page_against(&console_base(), note)
}

/// The rendering itself, with the console origin passed in so it can be tested without racing every
/// other test in the process over one environment variable.
fn page_against(console: &str, note: Option<&str>) -> String {
    let note_html = note.map(|n| format!("<p class=\"note\">{}</p>", escape(n))).unwrap_or_default();
    TEMPLATE
        .replace("{{CONSOLE_URL}}", &escape(&format!("{console}/console")))
        .replace("{{NOTE}}", &note_html)
}

/// Escape for both attribute and text position. The console origin is operator-supplied
/// (`PERMAURA_CONSOLE_URL`), so it reaches an `href` as data, never as markup.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_links_the_console_and_leaves_no_placeholder_behind() {
        let html = page_against("https://permaura.com", None);
        assert!(html.contains("href=\"https://permaura.com/console\""), "{html}");
        assert!(!html.contains("{{"), "an unsubstituted placeholder reached the page");
        assert!(!html.contains("class=\"note\""), "no note was asked for");
    }

    #[test]
    fn a_note_renders_and_is_escaped() {
        let html = page_against("https://permaura.com", Some("<script>x</script>"));
        assert!(html.contains("<p class=\"note\">&lt;script&gt;"), "{html}");
        assert!(!html.contains("<script>"), "a note reached the page as markup");
    }

    /// The console origin comes from the environment, so it is the one value on this page an
    /// operator can put a quote into.
    #[test]
    fn a_hostile_console_origin_cannot_break_out_of_the_href() {
        let html = page_against("https://x.example\" onmouseover=\"evil()", None);
        assert!(!html.contains("onmouseover=\"evil()"), "{html}");
        assert!(html.contains("&quot; onmouseover=&quot;"), "{html}");
    }
}
