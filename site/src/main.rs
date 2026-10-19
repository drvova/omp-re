//! Builds the omp-re GitHub Pages site.
//!
//! Renders the repository's README and docs (Markdown) into a small static
//! site: one HTML page per document, a shared navigation bar, an "On this
//! page" outline, and GitHub-style heading anchors so links like
//! `README.md#prerequisites` keep working. Links between rendered documents
//! are rewritten to the generated pages; links to anything else in the repo
//! (source files, LICENSE, …) point at the file on GitHub.
//!
//! Usage (from anywhere): `cargo run --release --manifest-path site/Cargo.toml -- [--out <dir>]`
//! The output defaults to `site/dist`.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use pulldown_cmark::{CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd, html};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// A rendered document: its Markdown source (relative to the repo root), its
/// output file, and its label in the navigation bar.
struct PageSpec {
    source: &'static str,
    output: &'static str,
    nav: &'static str,
}

/// Every document on the site, in navigation order.
const PAGES: &[PageSpec] = &[
    PageSpec {
        source: "README.md",
        output: "index.html",
        nav: "Overview",
    },
    PageSpec {
        source: "docs/install.md",
        output: "install.html",
        nav: "Install",
    },
    PageSpec {
        source: "docs/workflow.md",
        output: "workflow.html",
        nav: "Workflow",
    },
    PageSpec {
        source: "docs/tools.md",
        output: "tools.html",
        nav: "Tools",
    },
    PageSpec {
        source: "docs/ARCHITECTURE.md",
        output: "architecture.html",
        nav: "Architecture",
    },
    PageSpec {
        source: "docs/testing.md",
        output: "testing.html",
        nav: "Testing",
    },
    PageSpec {
        source: "SECURITY.md",
        output: "security.html",
        nav: "Security",
    },
    PageSpec {
        source: "CONTRIBUTING.md",
        output: "contributing.html",
        nav: "Contributing",
    },
    PageSpec {
        source: "CHANGELOG.md",
        output: "changelog.html",
        nav: "Changelog",
    },
];

/// Images referenced as `docs/img/...` are copied to `img/...`.
const IMAGE_DIR: &str = "docs/img";

/// Used when `GITHUB_REPOSITORY` is unset (local builds); Actions sets it, so forks link to themselves.
const DEFAULT_REPO: &str = "drvova/omp-re";

const TAGLINE: &str = "A reverse-engineering plugin for omp: rizin behind 64 agent tools, an evidence store, and a report writer that refuses claims it cannot back.";

const TEMPLATE: &str = include_str!("../assets/template.html");
const STYLE: &str = include_str!("../assets/style.css");

/// A heading kept for the page outline.
struct OutlineEntry {
    level: HeadingLevel,
    id: String,
    text: String,
}

/// One page after Markdown rendering, before it is placed in the template.
struct Rendered {
    title: String,
    body: String,
    outline: Vec<OutlineEntry>,
}

fn main() -> Result<()> {
    let site_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = site_dir.parent().ok_or("site/ has no parent directory")?;
    let out_dir = parse_out_dir()?.unwrap_or_else(|| site_dir.join("dist"));
    let repo = std::env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| DEFAULT_REPO.to_owned());
    let links = LinkRewriter::new(&repo);

    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)?;
    }
    fs::create_dir_all(&out_dir)?;

    for page in PAGES {
        let markdown = fs::read_to_string(repo_root.join(page.source))
            .map_err(|e| format!("reading {}: {e}", page.source))?;
        let rendered = render_markdown(&markdown, page, &links);
        let html = fill_template(page, &rendered, &repo);
        fs::write(out_dir.join(page.output), html)?;
    }

    fs::write(out_dir.join("404.html"), not_found_page(&repo))?;
    fs::write(out_dir.join("style.css"), STYLE)?;
    // Serve files as-is: no Jekyll processing on GitHub Pages.
    fs::write(out_dir.join(".nojekyll"), "")?;
    copy_dir(&repo_root.join(IMAGE_DIR), &out_dir.join("img"))?;

    println!("site: wrote {} pages to {}", PAGES.len(), out_dir.display());
    Ok(())
}

/// `--out <dir>`; anything else is an error.
fn parse_out_dir() -> Result<Option<PathBuf>> {
    let mut args = std::env::args().skip(1);
    let mut out = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = Some(PathBuf::from(args.next().ok_or("--out needs a directory")?)),
            other => {
                return Err(format!("unknown argument {other:?} (usage: [--out <dir>])").into());
            }
        }
    }
    Ok(out)
}

/// Renders one document: GitHub-style heading ids, rewritten links, and the
/// outline. On the index page the leading `# omp-re` heading is dropped (the
/// hero shows the name instead).
fn render_markdown(markdown: &str, page: &PageSpec, links: &LinkRewriter) -> Rendered {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_GFM;
    let events: Vec<Event> = Parser::new_ext(markdown, options).collect();

    let mut out: Vec<Event> = Vec::with_capacity(events.len());
    let mut outline = Vec::new();
    let mut slugs = SlugCounter::default();
    let mut title = None;
    let is_index = page.output == "index.html";

    let mut i = 0;
    while i < events.len() {
        match &events[i] {
            Event::Start(Tag::Heading {
                level,
                classes,
                attrs,
                ..
            }) => {
                // Gather the heading's inline events up to its end tag.
                let end = events[i..]
                    .iter()
                    .position(|e| matches!(e, Event::End(TagEnd::Heading(_))))
                    .map_or(events.len() - 1, |offset| i + offset);
                let inner = &events[i + 1..end];
                let text = plain_text(inner);
                let id = slugs.unique(&slugify(&text));
                let first_h1 = *level == HeadingLevel::H1 && title.is_none();
                if first_h1 {
                    title = Some(text.clone());
                }
                if matches!(level, HeadingLevel::H2 | HeadingLevel::H3) {
                    outline.push(OutlineEntry {
                        level: *level,
                        id: id.clone(),
                        text: text.clone(),
                    });
                }
                if !(is_index && first_h1) {
                    out.push(Event::Start(Tag::Heading {
                        level: *level,
                        id: Some(CowStr::from(id.clone())),
                        classes: classes.clone(),
                        attrs: attrs.clone(),
                    }));
                    out.extend(inner.iter().cloned().map(|e| links.rewrite(e, page.source)));
                    out.push(Event::Html(CowStr::from(format!(
                        "<a class=\"anchor\" href=\"#{id}\" aria-label=\"Link to this section\">#</a>"
                    ))));
                    out.push(events[end].clone());
                }
                i = end + 1;
            }
            event => {
                out.push(links.rewrite(event.clone(), page.source));
                i += 1;
            }
        }
    }

    let mut body = String::new();
    html::push_html(&mut body, out.into_iter());
    Rendered {
        title: title.unwrap_or_else(|| page.nav.to_owned()),
        body,
        outline,
    }
}

/// The visible text of a run of inline events (for slugs and the outline).
fn plain_text(events: &[Event]) -> String {
    let mut text = String::new();
    for event in events {
        if let Event::Text(t) | Event::Code(t) = event {
            text.push_str(t);
        }
    }
    text
}

/// GitHub's anchor algorithm: lowercase; keep letters, digits, `-` and `_`;
/// spaces become `-`; everything else is dropped.
fn slugify(text: &str) -> String {
    text.trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

/// Repeated slugs get `-1`, `-2`, … like on GitHub.
#[derive(Default)]
struct SlugCounter(HashMap<String, usize>);

impl SlugCounter {
    fn unique(&mut self, slug: &str) -> String {
        let seen = self.0.entry(slug.to_owned()).or_insert(0);
        let id = if *seen == 0 {
            slug.to_owned()
        } else {
            format!("{slug}-{seen}")
        };
        *seen += 1;
        id
    }
}

/// Maps repo-relative link targets to site pages, copied images, or GitHub.
struct LinkRewriter {
    pages: HashMap<&'static str, &'static str>,
    blob_base: String,
}

impl LinkRewriter {
    fn new(repo: &str) -> Self {
        Self {
            pages: PAGES.iter().map(|p| (p.source, p.output)).collect(),
            blob_base: format!("https://github.com/{repo}/blob/main/"),
        }
    }

    fn rewrite<'a>(&self, event: Event<'a>, source: &str) -> Event<'a> {
        match event {
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                id,
            }) => Event::Start(Tag::Link {
                link_type,
                dest_url: self.target(&dest_url, source),
                title,
                id,
            }),
            Event::Start(Tag::Image {
                link_type,
                dest_url,
                title,
                id,
            }) => Event::Start(Tag::Image {
                link_type,
                dest_url: self.target(&dest_url, source),
                title,
                id,
            }),
            other => other,
        }
    }

    fn target(&self, url: &str, source: &str) -> CowStr<'static> {
        let external = url.contains("://") || url.starts_with("mailto:") || url.starts_with('#');
        if external || url.is_empty() {
            return CowStr::from(url.to_owned());
        }
        let (path, fragment) = match url.split_once('#') {
            Some((path, fragment)) => (path, format!("#{fragment}")),
            None => (url, String::new()),
        };
        let resolved = resolve(source, path);
        if let Some(output) = self.pages.get(resolved.as_str()) {
            return CowStr::from(format!("{output}{fragment}"));
        }
        if let Some(image) = resolved.strip_prefix(&format!("{IMAGE_DIR}/")) {
            return CowStr::from(format!("img/{image}"));
        }
        CowStr::from(format!("{}{resolved}{fragment}", self.blob_base))
    }
}

/// Resolves `path` relative to the directory of `source` (both repo-relative), folding `.` and `..`.
fn resolve(source: &str, path: &str) -> String {
    let mut parts: Vec<&str> = source.split('/').collect();
    parts.pop();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

fn fill_template(page: &PageSpec, rendered: &Rendered, repo: &str) -> String {
    let is_index = page.output == "index.html";
    let title = if is_index {
        "omp-re — reverse engineering for omp".to_owned()
    } else {
        format!("{} — omp-re", rendered.title)
    };
    let hero = if is_index {
        hero_html(repo)
    } else {
        String::new()
    };
    // The 404 page has no source document.
    let edit = if page.source.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"edit\"><a href=\"https://github.com/{repo}/blob/main/{}\">View this page's source on GitHub</a></p>",
            page.source
        )
    };
    TEMPLATE
        .replace("{{title}}", &escape(&title))
        .replace("{{description}}", &escape(TAGLINE))
        .replace("{{nav}}", &nav_html(page.output))
        .replace("{{repo_url}}", &format!("https://github.com/{repo}"))
        .replace("{{edit}}", &edit)
        .replace("{{hero}}", &hero)
        .replace("{{outline}}", &outline_html(&rendered.outline))
        .replace("{{content}}", &rendered.body)
}

fn nav_html(current: &str) -> String {
    let mut nav = String::new();
    for page in PAGES {
        let aria = if page.output == current {
            " aria-current=\"page\""
        } else {
            ""
        };
        let _ = write!(nav, "<a href=\"{}\"{aria}>{}</a>", page.output, page.nav);
    }
    nav
}

fn outline_html(outline: &[OutlineEntry]) -> String {
    if outline.is_empty() {
        return String::new();
    }
    let mut list =
        String::from("<nav class=\"outline\" aria-label=\"On this page\"><p>On this page</p><ul>");
    for entry in outline {
        let class = if entry.level == HeadingLevel::H3 {
            " class=\"sub\""
        } else {
            ""
        };
        let _ = write!(
            list,
            "<li{class}><a href=\"#{}\">{}</a></li>",
            entry.id,
            escape(&entry.text)
        );
    }
    list.push_str("</ul></nav>");
    list
}

fn hero_html(repo: &str) -> String {
    format!(
        "<section class=\"hero\">\
<h1>omp-re</h1>\
<p class=\"tagline\">{tagline}</p>\
<pre class=\"install\"><code>omp plugin marketplace add {repo}\nomp plugin install omp-re@drvova</code></pre>\
<p class=\"actions\"><a class=\"button primary\" href=\"install.html\">Get started</a>\
<a class=\"button\" href=\"https://github.com/{repo}\">View on GitHub</a></p>\
</section>",
        tagline = escape(TAGLINE),
    )
}

fn not_found_page(repo: &str) -> String {
    let page = PageSpec {
        source: "",
        output: "404.html",
        nav: "Not found",
    };
    let rendered = Rendered {
        title: "Page not found".to_owned(),
        body: "<h1>Page not found</h1><p>That page does not exist. Try the <a href=\"index.html\">overview</a>.</p>"
            .to_owned(),
        outline: Vec::new(),
    };
    fill_template(&page, &rendered, repo)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::copy(entry.path(), to.join(entry.file_name()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_match_github() {
        assert_eq!(slugify("What's omp-native"), "whats-omp-native");
        assert_eq!(slugify("rizin_debug"), "rizin_debug");
        assert_eq!(
            slugify("Decompiler: whatever you have"),
            "decompiler-whatever-you-have"
        );
    }

    #[test]
    fn repeated_slugs_are_numbered() {
        let mut slugs = SlugCounter::default();
        assert_eq!(slugs.unique("usage"), "usage");
        assert_eq!(slugs.unique("usage"), "usage-1");
    }

    #[test]
    fn links_resolve_to_pages_images_or_github() {
        let links = LinkRewriter::new("o/r");
        assert_eq!(
            &*links.target("docs/install.md", "README.md"),
            "install.html"
        );
        assert_eq!(
            &*links.target("../README.md#install", "docs/tools.md"),
            "index.html#install"
        );
        assert_eq!(
            &*links.target("docs/img/hero.png", "README.md"),
            "img/hero.png"
        );
        assert_eq!(
            &*links.target("LICENSE", "README.md"),
            "https://github.com/o/r/blob/main/LICENSE"
        );
        assert_eq!(
            &*links.target("#prerequisites", "README.md"),
            "#prerequisites"
        );
        assert_eq!(
            &*links.target("https://rizin.re", "README.md"),
            "https://rizin.re"
        );
    }
}
