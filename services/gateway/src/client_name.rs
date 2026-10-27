//! The name an MCP client gives itself in `initialize` (`params.clientInfo`), made fit to show an operator.
//!
//! It is the client's own claim and it is shown in approval prompts, so nothing in it may make what the operator reads differ from what it is: control characters, bidi embeddings, overrides and isolates, and characters that render as nothing are dropped.

use serde_json::Value;

/// The longest client name kept, in characters.
pub const CLIENT_NAME_MAX_CHARS: usize = 64;

/// Client ids whose display name is not their id title-cased.
const KNOWN_CLIENTS: &[(&str, &str)] = &[
    ("claude-code", "Claude Code"),
    ("claude-ai", "Claude"),
    ("cursor-vscode", "Cursor"),
    ("codex-mcp-client", "Codex"),
    ("gemini-cli-mcp-client", "Gemini CLI"),
];

/// The display name for `client_info`, an `initialize` request's `params.clientInfo`: its `title` (MCP 2025-06-18) when that leaves anything to show, else its `name`, else `None`.
pub fn client_display_name(client_info: &Value) -> Option<String> {
    ["title", "name"].iter().find_map(|field| client_info.get(field)?.as_str().and_then(display_name))
}

fn display_name(raw: &str) -> Option<String> {
    let clean = sanitized(raw);
    if clean.is_empty() {
        return None;
    }
    let named = match KNOWN_CLIENTS.iter().find(|(id, _)| clean.eq_ignore_ascii_case(id)) {
        Some((_, name)) => (*name).to_string(),
        None if is_lowercase_id(&clean) => title_cased(&clean),
        None => clean,
    };
    let capped: String = named.chars().take(CLIENT_NAME_MAX_CHARS).collect();
    let capped = capped.trim_end();
    (!capped.is_empty()).then(|| capped.to_string())
}

/// `raw` with every run of whitespace made one space, the ends trimmed, and control and invisible characters dropped.
fn sanitized(raw: &str) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in raw.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
        } else if !c.is_control() && !invisible(c) {
            if space {
                out.push(' ');
                space = false;
            }
            out.push(c);
        }
    }
    out
}

/// Characters that render as nothing or reorder the text around them: bidi embeddings, overrides, isolates and marks, zero-width spaces and joiners, invisible operators, blank fillers, variation selectors, tag characters and the other format controls.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Whether `s` reads as a client id rather than a name: lowercase ASCII words joined by `-` or `_`.
fn is_lowercase_id(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_lowercase()) && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// `my-ci-bot` as `My Ci Bot`.
fn title_cased(id: &str) -> String {
    id.split(['-', '_'])
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map(|first| first.to_ascii_uppercase().to_string() + chars.as_str()).unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn named(name: &str) -> Option<String> {
        client_display_name(&json!({ "name": name, "version": "1.0.0" }))
    }

    #[test]
    fn the_title_is_preferred_and_the_name_stands_in_for_one_that_shows_nothing() {
        let info = json!({ "name": "claude-code", "title": "Claude Code (beta)", "version": "2.0.0" });
        assert_eq!(client_display_name(&info).as_deref(), Some("Claude Code (beta)"));
        for blank in ["", "   ", "\u{200B}\u{202E}"] {
            let info = json!({ "name": "claude-code", "title": blank, "version": "2.0.0" });
            assert_eq!(client_display_name(&info).as_deref(), Some("Claude Code"), "title {blank:?}");
        }
        let info = json!({ "name": "claude-code", "title": 7, "version": "2.0.0" });
        assert_eq!(client_display_name(&info).as_deref(), Some("Claude Code"), "a title that is not a string is not one");
    }

    #[test]
    fn well_known_client_ids_get_their_proper_names() {
        for (id, name) in [
            ("claude-code", "Claude Code"),
            ("claude-ai", "Claude"),
            ("cursor-vscode", "Cursor"),
            ("codex-mcp-client", "Codex"),
            ("gemini-cli-mcp-client", "Gemini CLI"),
            ("Claude-Code", "Claude Code"),
            ("Visual Studio Code", "Visual Studio Code"),
        ] {
            assert_eq!(named(id).as_deref(), Some(name), "{id}");
        }
    }

    #[test]
    fn another_lowercase_id_is_title_cased_and_anything_else_is_kept_as_given() {
        for (id, name) in [
            ("my-ci-bot", "My Ci Bot"),
            ("my_ci_bot", "My Ci Bot"),
            ("cline", "Cline"),
            ("agent-2", "Agent 2"),
            ("--deploy--bot--", "Deploy Bot"),
            ("Zed", "Zed"),
            ("com.example.App", "com.example.App"),
            ("Release Bot 3", "Release Bot 3"),
            ("2024", "2024"),
        ] {
            assert_eq!(named(id).as_deref(), Some(name), "{id}");
        }
    }

    #[test]
    fn what_could_disguise_the_name_is_dropped() {
        for (raw, name) in [
            ("\u{202E}edoC edualC", "edoC edualC"),
            ("Deploy\u{202D} Bot\u{202C}", "Deploy Bot"),
            ("\u{2066}Deploy Bot\u{2069}", "Deploy Bot"),
            ("\u{2067}Deploy\u{2068} Bot", "Deploy Bot"),
            ("Deploy\u{0007}Bot\u{007F}\u{009B}", "DeployBot"),
            ("Deploy\u{200B}Bot\u{200D}\u{FEFF}\u{2060}", "DeployBot"),
            ("Deploy Bot\u{E0041}\u{E0042}", "Deploy Bot"),
            ("  Deploy \t\n\r  Bot \u{00A0}\u{3000} ", "Deploy Bot"),
            ("Deploy\u{200B} \u{200B} Bot", "Deploy Bot"),
            ("Deploy\nBot", "Deploy Bot"),
            ("\u{200E}claude-code\u{200F}", "Claude Code"),
        ] {
            assert_eq!(named(raw).as_deref(), Some(name), "{raw:?}");
        }
    }

    /// The set the web console's and the phone's `cleanAgentName` drop, so a name reads the same wherever it was given; a control that is whitespace stands as a space, as it does there.
    #[test]
    fn every_character_the_console_and_phone_drop_is_dropped_here() {
        let ranges = [
            ('\u{0000}', '\u{001F}'),
            ('\u{007F}', '\u{009F}'),
            ('\u{00AD}', '\u{00AD}'),
            ('\u{061C}', '\u{061C}'),
            ('\u{180E}', '\u{180E}'),
            ('\u{200B}', '\u{200F}'),
            ('\u{202A}', '\u{202E}'),
            ('\u{2060}', '\u{2064}'),
            ('\u{2066}', '\u{206F}'),
            ('\u{FEFF}', '\u{FEFF}'),
        ];
        for c in ranges.iter().flat_map(|&(from, to)| from..=to) {
            let want = if c.is_whitespace() { "Deploy Bot" } else { "DeployBot" };
            assert_eq!(named(&format!("Deploy{c}Bot")).as_deref(), Some(want), "U+{:04X}", c as u32);
        }
    }

    #[test]
    fn the_name_is_capped_at_64_characters_not_bytes() {
        let long = "A".repeat(200);
        assert_eq!(named(&long).map(|n| n.chars().count()), Some(CLIENT_NAME_MAX_CHARS));
        let wide = "\u{00C9}".repeat(100);
        let capped = named(&wide).expect("a name");
        assert_eq!(capped.chars().count(), CLIENT_NAME_MAX_CHARS);
        assert_eq!(capped.len(), 2 * CLIENT_NAME_MAX_CHARS, "cut on a character boundary");
        let at_a_space = format!("{} B", "A".repeat(CLIENT_NAME_MAX_CHARS - 1));
        assert_eq!(named(&at_a_space), Some("A".repeat(CLIENT_NAME_MAX_CHARS - 1)), "a cut that leaves a space ends before it");
    }

    #[test]
    fn nothing_to_show_is_none() {
        for info in [
            json!(null),
            json!({}),
            json!("claude-code"),
            json!({ "version": "1.0.0" }),
            json!({ "name": "" }),
            json!({ "name": "   \t\n" }),
            json!({ "name": "\u{200B}\u{202E}\u{2066}\u{0000}" }),
            json!({ "name": 42 }),
            json!({ "name": null, "title": null }),
        ] {
            assert_eq!(client_display_name(&info), None, "{info}");
        }
    }
}
