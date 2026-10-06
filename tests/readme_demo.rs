//! SHA-340 T3: the README shows the recorded demo.
//!
//! The README embeds `docs/demo/demo.gif` with alt text that names the
//! steps it shows, and the image stays under 2 MB so the README loads
//! quickly. Re-render it with `vhs docs/demo/demo.tape` (see the tape).

use regex::Regex;

const README: &str = include_str!("../README.md");
const GIF: &str = "docs/demo/demo.gif";
const MAX_BYTES: u64 = 2 * 1024 * 1024;

#[test]
fn t3_readme_embeds_the_demo_with_alt_text_and_the_gif_is_small() {
    let image = Regex::new(r"!\[([^\]]*)\]\(docs/demo/demo\.gif\)").unwrap();
    let alt = image
        .captures(README)
        .expect("README.md embeds docs/demo/demo.gif")
        .get(1)
        .unwrap()
        .as_str()
        .to_lowercase();
    for step in ["plan", "apply", "status", "audit log"] {
        assert!(
            alt.contains(step),
            "the demo alt text does not name {step}: {alt}"
        );
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GIF);
    let size = std::fs::metadata(&path)
        .unwrap_or_else(|e| panic!("{GIF}: {e}"))
        .len();
    assert!(size > 0, "{GIF} is empty");
    assert!(
        size < MAX_BYTES,
        "{GIF} is {size} bytes, over the 2 MB limit"
    );
}
