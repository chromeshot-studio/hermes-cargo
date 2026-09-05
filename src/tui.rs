//! The interactive mode: `hermes` with no arguments.
//!
//! Running the bare binary used to print clap's help and exit with code 2,
//! which - when the binary is double-clicked from a file manager - looks
//! exactly like a crash: a console window appears and vanishes. Now it opens a
//! keyboard-driven list of everything HERMES tracks and stays put until the
//! user leaves.
//!
//! Deliberately not a full TUI framework. This is a list, a detail pane and a
//! help pane, drawn with `crossterm` directly, so the dependency tree stays
//! small and there is no layout engine to reason about.
//!
//! Anything that needs the ordinary terminal - an update's consent prompt, a
//! browser login, a dropped file path - runs through [`Screen::suspend`],
//! which drops back to the normal screen so the existing code paths print and
//! read exactly as they do from the command line. The security prompts are
//! never reimplemented here.

use crate::auth;
use crate::install;
use crate::net::HttpClient;
use crate::paths;
use crate::registry::{self, OriginState};
use crate::schema::{OriginFile, Release};
use crate::security::safepath::display_path;
use crate::update::{self, Available, UpdateOptions};
use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{cursor, execute, queue};
use std::collections::VecDeque;
use std::io::{stdout, IsTerminal, Stdout, Write};
use std::time::Duration;

const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGrey;
const GOOD: Color = Color::Green;
const WARN: Color = Color::Yellow;
const BAD: Color = Color::Red;

// ---------------------------------------------------------------------------
// Terminal guard
// ---------------------------------------------------------------------------

/// Owns raw mode and the alternate screen, and gives both back on drop -
/// including on panic, so a bug never leaves the user with a dead terminal.
struct Screen {
    out: Stdout,
    /// Set by [`Screen::suspend`]: the ordinary terminal has been used, so any
    /// input queued since is stale and must not be replayed as hotkeys.
    resumed: bool,
}

impl Screen {
    fn enter() -> Result<Self> {
        // The release profile sets `panic = "abort"`, so `Drop` does *not* run
        // on a panic. Without this hook a bug in the drawing code would leave
        // the user staring at a dead terminal in raw mode with no echo.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(stdout(), LeaveAlternateScreen, cursor::Show);
            previous(info);
        }));

        enable_raw_mode().context("entering raw mode")?;
        let mut out = stdout();
        execute!(out, EnterAlternateScreen, cursor::Hide)?;
        Ok(Self {
            out,
            resumed: false,
        })
    }

    /// Drop back to the normal screen, run `body`, then come back.
    fn suspend<T>(&mut self, body: impl FnOnce() -> T) -> Result<T> {
        execute!(self.out, LeaveAlternateScreen, cursor::Show)?;
        disable_raw_mode()?;
        let outcome = body();
        press_any_key();
        enable_raw_mode()?;
        execute!(self.out, EnterAlternateScreen, cursor::Hide)?;
        self.resumed = true;
        Ok(outcome)
    }

    fn take_resumed(&mut self) -> bool {
        std::mem::take(&mut self.resumed)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.out, LeaveAlternateScreen, cursor::Show);
    }
}

fn press_any_key() {
    print!("\n  Press Enter to return to HERMES...");
    let _ = stdout().flush();
    let mut discard = String::new();
    let _ = std::io::stdin().read_line(&mut discard);
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct Row {
    origin: OriginFile,
    state: OriginState,
    available: Option<Available>,
    error: Option<String>,
}

impl Row {
    /// Everything the studio offers, newest first. Empty until the row has
    /// been checked - the catalogue arrives with the signed manifest.
    fn releases(&self) -> Vec<Release> {
        self.available
            .as_ref()
            .and_then(|a| a.manifest.releases().ok())
            .unwrap_or_default()
    }

    fn status(&self) -> (String, Color) {
        if let Some(error) = &self.error {
            return (truncate(error, 46), BAD);
        }
        if let Some(available) = &self.available {
            if available.is_newer {
                return (format!("update -> {}", available.manifest.latest_version), WARN);
            }
            return (
                format!("up to date ({})", available.manifest.latest_version),
                GOOD,
            );
        }
        match &self.state.installed_version {
            Some(version) => (format!("v{version}"), Color::Reset),
            None => ("not installed".into(), MUTED),
        }
    }
}

#[derive(PartialEq)]
enum View {
    List,
    Detail,
    Help,
    /// Every version the studio offers, to look through and pick from.
    Versions,
}

struct App {
    rows: Vec<Row>,
    selected: usize,
    view: View,
    status: String,
    client: Option<HttpClient>,
    /// Which entry the version picker is on.
    version_index: usize,
}

impl App {
    fn load() -> Result<Self> {
        let rows = registry::list_origins()?
            .into_iter()
            .map(|entry| Row {
                origin: entry.origin,
                state: entry.state,
                available: None,
                error: None,
            })
            .collect();
        Ok(Self {
            rows,
            selected: 0,
            view: View::List,
            status: "Press ? for keys, q to quit".into(),
            client: None,
            version_index: 0,
        })
    }

    fn reload(&mut self) -> Result<()> {
        let selected_id = self.current().map(|r| r.origin.id.clone());
        let fresh = App::load()?;
        self.rows = fresh.rows;
        self.selected = selected_id
            .and_then(|id| self.rows.iter().position(|r| r.origin.id == id))
            .unwrap_or(0);
        Ok(())
    }

    fn current(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    /// The HTTP client is built on first use, so the UI opens instantly and an
    /// offline user never pays for TLS setup they did not ask for.
    fn client(&mut self) -> Result<&HttpClient> {
        if self.client.is_none() {
            self.client = Some(HttpClient::new()?);
        }
        Ok(self.client.as_ref().expect("client built"))
    }

    fn check_selected(&mut self, screen: &mut Screen) -> Result<()> {
        let Some(index) = self.rows.get(self.selected).map(|_| self.selected) else {
            return Ok(());
        };
        self.status = format!("checking {}...", self.rows[index].origin.name);
        self.draw(screen)?;

        let origin = self.rows[index].origin.clone();
        let result = self.client().and_then(|client| update::check(client, &origin));
        match result {
            Ok(available) => {
                let message = update::describe_available(&origin, &available);
                self.rows[index].available = Some(available);
                self.rows[index].error = None;
                self.status = message;
            }
            Err(e) => {
                self.rows[index].error = Some(format!("{e:#}"));
                self.status = format!("{}: {e:#}", origin.name);
            }
        }
        self.rows[index].state = registry::load_state(&origin.id).unwrap_or_default();
        Ok(())
    }

    fn check_all(&mut self, screen: &mut Screen) -> Result<()> {
        for index in 0..self.rows.len() {
            self.selected = index;
            self.check_selected(screen)?;
            self.draw(screen)?;
        }
        let updates = self
            .rows
            .iter()
            .filter(|r| r.available.as_ref().is_some_and(|a| a.is_newer))
            .count();
        self.status = match updates {
            0 => "everything is up to date".into(),
            1 => "1 update available".into(),
            n => format!("{n} updates available"),
        };
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run() -> Result<()> {
    let mut app = App::load()?;
    let mut screen = Screen::enter()?;
    let mut reader = Reader::new();

    loop {
        app.draw(&mut screen)?;
        let key = match reader.next()? {
            None => continue,
            // A file was dragged onto the window. Adding it is the only thing
            // that could reasonably mean, whichever pane is showing.
            Some(Input::Dropped(path)) => {
                app.view = View::List;
                act_add(&mut app, &mut screen, Some(path))?;
                reader.drain();
                continue;
            }
            Some(Input::Key(key)) => key,
        };

        // Ctrl-C leaves, wherever we are.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c'))
        {
            break;
        }

        match app.view {
            View::Help => match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') => {
                    app.view = View::List
                }
                _ => {}
            },
            View::Detail => match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Left | KeyCode::Backspace => {
                    app.view = View::List
                }
                KeyCode::Char('u') => act_update(&mut app, &mut screen, None)?,
                KeyCode::Char('c') => app.check_selected(&mut screen)?,
                KeyCode::Char('l') => act_login(&mut app, &mut screen)?,
                KeyCode::Char('v') => app.open_versions(),
                KeyCode::Char('?') => app.view = View::Help,
                _ => {}
            },
            View::Versions => {
                let count = app.current().map(|r| r.releases().len()).unwrap_or(0);
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc | KeyCode::Left | KeyCode::Backspace => {
                        app.view = View::Detail
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.version_index = app.version_index.saturating_sub(1)
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.version_index = (app.version_index + 1).min(count.saturating_sub(1))
                    }
                    KeyCode::Home | KeyCode::Char('g') => app.version_index = 0,
                    KeyCode::End | KeyCode::Char('G') => {
                        app.version_index = count.saturating_sub(1)
                    }
                    KeyCode::Enter | KeyCode::Char('u') => {
                        let chosen = app
                            .current()
                            .and_then(|r| r.releases().get(app.version_index).cloned());
                        if let Some(release) = chosen {
                            act_update(&mut app, &mut screen, Some(release.version))?;
                        }
                    }
                    KeyCode::Char('?') => app.view = View::Help,
                    _ => {}
                }
            }
            View::List => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
                KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
                KeyCode::Home | KeyCode::Char('g') => app.selected = 0,
                KeyCode::End | KeyCode::Char('G') => {
                    app.selected = app.rows.len().saturating_sub(1)
                }
                KeyCode::Enter | KeyCode::Right => {
                    if app.current().is_some() {
                        app.view = View::Detail;
                    }
                }
                KeyCode::Char('c') => app.check_selected(&mut screen)?,
                KeyCode::Char('C') => app.check_all(&mut screen)?,
                KeyCode::Char('u') => act_update(&mut app, &mut screen, None)?,
                KeyCode::Char('v') => app.open_versions(),
                KeyCode::Char('a') => act_add(&mut app, &mut screen, None)?,
                KeyCode::Char('l') => act_login(&mut app, &mut screen)?,
                KeyCode::Char('L') => act_logout(&mut app)?,
                KeyCode::Char('r') => act_remove(&mut app, &mut screen)?,
                KeyCode::Char('n') => {
                    if app.current().is_some() {
                        app.view = View::Detail;
                    }
                }
                KeyCode::Char('?') | KeyCode::Char('h') => app.view = View::Help,
                _ => {}
            },
        }

        if screen.take_resumed() {
            reader.drain();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// One key press, or a path that was dragged onto the window.
enum Input {
    Key(KeyEvent),
    Dropped(String),
}

/// Terminal input, with a dropped file told apart from a keystroke.
///
/// A console has no separate "paste" event: dragging a file onto the window
/// arrives as an ordinary burst of character key presses. Fed straight into
/// the key map that is a disaster, and it was a real one - dropping
/// `D:\Developing\CascadeProjects\...` scrolled the list, ran a check, and
/// then hit the `a` of `Ca`, which opened the add prompt *half way through
/// the path*. The prompt read the rest, `scadeProjects\...`, and reported a
/// file that did not exist. The path was never mangled; it was eaten.
///
/// The tell is timing. A person cannot produce two key presses with no
/// measurable gap between them, so characters already queued when the first
/// is handled came from a paste. A burst that does not look like a path -
/// holding `j` to scroll - is replayed key by key, so nothing is lost either
/// way.
struct Reader {
    pending: VecDeque<KeyEvent>,
}

/// Windows reports both press and release; acting on both would make every
/// keystroke fire twice.
fn press(event: Event) -> Option<KeyEvent> {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => Some(key),
        _ => None,
    }
}

impl Reader {
    fn new() -> Self {
        Self {
            pending: VecDeque::new(),
        }
    }

    fn next(&mut self) -> Result<Option<Input>> {
        if let Some(key) = self.pending.pop_front() {
            return Ok(Some(Input::Key(key)));
        }

        let Some(first) = press(event::read().context("reading a key")?) else {
            return Ok(None);
        };
        let mut burst = vec![first];

        // Only a printable character can begin a path, so only a printable
        // character is worth waiting on. Arrows and Enter act immediately.
        if starts_text(&first) {
            // Wait a moment for a second character. Do not assume the rest of
            // the paste is already queued - it is not, on every terminal, and
            // an earlier version of this that only drained what was already
            // waiting simply never fired. A person cannot follow one key with
            // another inside this window; a paste always does.
            if event::poll(FIRST_GAP)? {
                if let Some(key) = press(event::read()?) {
                    burst.push(key);
                }
            }
            // From here it is a burst. Keep taking characters while they keep
            // coming, but only for something that still looks like a path, so
            // holding a key down never stalls the redraw.
            while burst.len() > 1
                && burst.len() < MAX_DROPPED_KEYS
                && could_be_path(&burst)
                && event::poll(BURST_GAP)?
            {
                if let Some(key) = press(event::read()?) {
                    burst.push(key);
                }
            }
        }

        if let Some(path) = dropped_path(&burst) {
            return Ok(Some(Input::Dropped(path)));
        }
        self.pending.extend(burst);
        Ok(self.pending.pop_front().map(Input::Key))
    }

    /// Throw away input queued while the terminal was somewhere else.
    fn drain(&mut self) {
        self.pending.clear();
        while matches!(event::poll(Duration::ZERO), Ok(true)) {
            if event::read().is_err() {
                break;
            }
        }
    }
}

/// How long to wait after one printable key for a second one. Long enough
/// that a paste always lands inside it, short enough to be invisible when it
/// was really just a keystroke - which is the cost paid on every hotkey.
const FIRST_GAP: Duration = Duration::from_millis(30);
/// How long to keep collecting once a burst has been detected.
const BURST_GAP: Duration = Duration::from_millis(40);
/// Longer than any path a filesystem will hand out; stops a stuck terminal
/// from collecting forever.
const MAX_DROPPED_KEYS: usize = 8192;

/// Could this key be the first character of a dropped path?
fn starts_text(key: &KeyEvent) -> bool {
    !key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char(_))
}

/// Should we keep waiting for more of this burst?
///
/// Key repeat produces a burst too, and stalling the redraw for one would make
/// the list feel stuck. Three rules, in order of how quickly they settle it:
///
/// * anything that is not a plain character ends it outright;
/// * a run of the *same* character is someone holding a key down, never a path;
/// * otherwise collect a few characters before judging, because the separator
///   that identifies a path is not always the first thing to arrive - a quoted
///   `"C:\...` does not reach one until the third character.
fn could_be_path(burst: &[KeyEvent]) -> bool {
    let plain = burst.iter().all(|key| {
        !key.modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && matches!(key.code, KeyCode::Char(_) | KeyCode::Enter)
    });
    if !plain {
        return false;
    }
    let chars: Vec<char> = burst
        .iter()
        .filter_map(|key| match key.code {
            KeyCode::Char(c) => Some(c),
            _ => None,
        })
        .collect();
    if chars.len() > 1 && chars.iter().all(|c| *c == chars[0]) {
        return false;
    }
    chars.len() < SEPARATOR_WINDOW || chars.iter().any(|c| matches!(c, '/' | '\\' | ':' | '~'))
}

/// How many characters to collect before insisting a burst looks path-shaped.
const SEPARATOR_WINDOW: usize = 8;

/// Is this burst a pasted path rather than someone leaning on a key?
fn dropped_path(burst: &[KeyEvent]) -> Option<String> {
    if burst.len() < 4 {
        return None;
    }
    let mut text = String::new();
    for key in burst {
        // Ctrl- and Alt-chords are commands, never part of a pasted path.
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return None;
        }
        match key.code {
            KeyCode::Char(c) => text.push(c),
            // Some terminals append a newline to a drop; anything else in the
            // middle of the burst means this was not one.
            KeyCode::Enter => {}
            _ => return None,
        }
    }
    let text = text.trim();
    looks_like_path(text).then(|| text.to_string())
}

/// A deliberately loose test - it only decides whether to *offer* to add the
/// file, and `hermes add` still parses and validates whatever comes through.
fn looks_like_path(text: &str) -> bool {
    let text = text.trim_matches(['"', '\'']);
    if text.chars().count() < 4 {
        return false;
    }
    text.starts_with("file://")
        || text.contains('/')
        || text.contains('\\')
        // A bare `C:something` - a drive-relative path.
        || text.chars().nth(1) == Some(':')
}

impl App {
    /// Open the version picker, which needs a checked row to have anything in
    /// it: the catalogue arrives with the signed manifest, not from disk.
    fn open_versions(&mut self) {
        match self.current() {
            None => self.status = "nothing selected".into(),
            Some(row) if row.available.is_none() => {
                self.status = "press c to check first - the versions come with the manifest".into()
            }
            Some(row) if row.releases().len() <= 1 => {
                self.status = "this studio offers one version".into();
                self.version_index = 0;
                self.view = View::Versions;
            }
            Some(_) => {
                self.version_index = 0;
                self.view = View::Versions;
            }
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let last = self.rows.len() as isize - 1;
        let next = (self.selected as isize + delta).clamp(0, last);
        self.selected = next as usize;
    }
}

// ---------------------------------------------------------------------------
// Actions - all of these suspend the TUI and reuse the normal code paths
// ---------------------------------------------------------------------------

/// `version` is `Some` when the user picked one out of the version list;
/// `None` takes whatever is newest.
fn act_update(
    app: &mut App,
    screen: &mut Screen,
    version: Option<semver::Version>,
) -> Result<()> {
    let Some(row) = app.current() else {
        app.status = "nothing selected".into();
        return Ok(());
    };
    let origin = row.origin.clone();
    let known = row.available.is_some();
    let name = origin.name.clone();

    let chosen = version.clone();
    let outcome = screen.suspend(move || -> Result<()> {
        let client = HttpClient::new()?;
        if !known {
            println!("\n  Checking {}...", origin.name);
        }
        let available = update::check(&client, &origin)?;
        if chosen.is_none() && !available.is_newer {
            println!(
                "\n  {} is already up to date ({}).",
                origin.name, available.manifest.latest_version
            );
            return Ok(());
        }
        // Every prompt inside `apply` - the folder scope, and the downgrade
        // warning when an older version was picked - is the real one on the
        // real terminal. The interactive mode never approves anything itself.
        let options = UpdateOptions {
            version: chosen,
            ..UpdateOptions::default()
        };
        update::apply(&client, &origin, &available, &options)
    })?;

    match outcome {
        Ok(()) => {
            app.status = match &version {
                Some(v) => format!("{name} is now on {v}"),
                None => format!("{name} finished"),
            };
            app.view = View::List;
        }
        Err(e) => app.status = format!("{name}: {e:#}"),
    }
    app.reload()?;
    Ok(())
}

/// `dropped` is `Some` when the path arrived by drag-and-drop onto the list,
/// in which case there is nothing left to ask for.
fn act_add(app: &mut App, screen: &mut Screen, dropped: Option<String>) -> Result<()> {
    let outcome = screen.suspend(move || -> Result<String> {
        let line = match dropped {
            Some(path) => {
                println!("\n  Dropped: {path}");
                path
            }
            None => {
                println!("\n  Drag a .origin file into this window and press Enter.");
                print!("  > ");
                let _ = stdout().flush();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                line.trim().to_string()
            }
        };
        if line.is_empty() {
            return Ok("cancelled".into());
        }
        let path = registry::normalize_dropped_path(&line);
        println!("  Reading: {}", display_path(&path));

        // Report the failure here, on the ordinary terminal, rather than
        // handing it to the status bar - that is one truncated line, and the
        // useful part of a parse error (which file, which line, what is wrong
        // with it) is exactly what gets cut off.
        let origin = match registry::read_origin_file(&path) {
            Ok(origin) => origin,
            Err(e) => {
                println!("\n  Could not add it.\n");
                println!("  {e:#}");
                return Ok("could not read that file - see above".into());
            }
        };
        let existed = registry::add_origin(&origin, false)?;
        println!(
            "\n  {} {} ({})",
            if existed { "Updated" } else { "Added" },
            origin.name,
            origin.id
        );
        Ok(format!("added {}", origin.name))
    })?;

    app.status = match outcome {
        Ok(message) => message,
        Err(e) => format!("{e:#}"),
    };
    app.reload()?;
    Ok(())
}

fn act_login(app: &mut App, screen: &mut Screen) -> Result<()> {
    let Some(row) = app.current() else {
        return Ok(());
    };
    let origin = row.origin.clone();
    let outcome = screen.suspend(|| auth::login(&origin))?;
    app.status = match outcome {
        Ok(_) => format!("signed in to {}", origin.name),
        Err(e) => format!("{e:#}"),
    };
    Ok(())
}

fn act_logout(app: &mut App) -> Result<()> {
    let Some(row) = app.current() else {
        return Ok(());
    };
    let name = row.origin.name.clone();
    app.status = if auth::logout(&row.origin.id)? {
        format!("signed out of {name}")
    } else {
        format!("not signed in to {name}")
    };
    Ok(())
}

fn act_remove(app: &mut App, screen: &mut Screen) -> Result<()> {
    let Some(row) = app.current() else {
        return Ok(());
    };
    let origin = row.origin.clone();
    let outcome = screen.suspend(|| -> Result<bool> {
        println!("\n  Stop tracking {} ({})?", origin.name, origin.id);
        println!("  Files already installed are left alone.");
        if !crate::security::consent::confirm("  Remove?", false) {
            return Ok(false);
        }
        registry::remove_origin(&origin.id)?;
        let _ = auth::logout(&origin.id);
        Ok(true)
    })?;

    app.status = match outcome {
        Ok(true) => format!("removed {}", origin.name),
        Ok(false) => "cancelled".into(),
        Err(e) => format!("{e:#}"),
    };
    app.reload()?;
    if self_index_out_of_range(app) {
        app.selected = app.rows.len().saturating_sub(1);
    }
    Ok(())
}

fn self_index_out_of_range(app: &App) -> bool {
    !app.rows.is_empty() && app.selected >= app.rows.len()
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

fn truncate(text: &str, width: usize) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() <= width {
        return clean;
    }
    let keep = width.saturating_sub(1);
    format!("{}\u{2026}", clean.chars().take(keep).collect::<String>())
}

impl App {
    fn draw(&self, screen: &mut Screen) -> Result<()> {
        let (width, height) = crossterm::terminal::size().unwrap_or((80, 24));
        let out = &mut screen.out;
        Self::render(self, out, width as usize, height as usize)
    }

    /// Rendering, separated from the terminal so tests can draw into a buffer
    /// at awkward sizes and prove none of the arithmetic panics.
    fn render<W: Write>(&self, out: &mut W, width: usize, height: usize) -> Result<()> {
        let width = width.max(40);
        let height = height.max(10);

        queue!(out, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
        self.draw_header(out, width)?;

        match self.view {
            View::List => self.draw_list(out, width, height)?,
            View::Detail => self.draw_detail(out, width, height)?,
            View::Help => self.draw_help(out, width)?,
            View::Versions => self.draw_versions(out, width, height)?,
        }

        self.draw_footer(out, width, height)?;
        out.flush()?;
        Ok(())
    }

    fn draw_header<W: Write>(&self, out: &mut W, width: usize) -> Result<()> {
        queue!(
            out,
            cursor::MoveTo(0, 0),
            SetForegroundColor(ACCENT),
            SetAttribute(Attribute::Bold),
            Print("  HERMES"),
            SetAttribute(Attribute::Reset),
            SetForegroundColor(MUTED),
            Print(format!(
                "  {}  -  decentralized updater",
                env!("CARGO_PKG_VERSION")
            )),
            ResetColor,
            cursor::MoveTo(0, 1),
            SetForegroundColor(MUTED),
            Print(format!("  {}", "-".repeat(width.saturating_sub(4)))),
            ResetColor
        )?;
        Ok(())
    }

    fn draw_list<W: Write>(&self, out: &mut W, width: usize, height: usize) -> Result<()> {
        if self.rows.is_empty() {
            queue!(
                out,
                cursor::MoveTo(0, 3),
                Print("  Nothing registered yet."),
                cursor::MoveTo(0, 5),
                SetForegroundColor(MUTED),
                Print("  Drag a .origin file onto this window, or press  a  to type"),
                cursor::MoveTo(0, 6),
                Print("  its path. A studio gives you that file; it is the trust root"),
                cursor::MoveTo(0, 7),
                Print("  for everything HERMES will install for them."),
                ResetColor
            )?;
            return Ok(());
        }

        let name_width = width.saturating_sub(40).clamp(12, 40);
        let visible = height.saturating_sub(6);
        let first = self.selected.saturating_sub(visible.saturating_sub(1));

        for (offset, row) in self.rows.iter().skip(first).take(visible).enumerate() {
            let index = first + offset;
            let y = (3 + offset) as u16;
            let selected = index == self.selected;
            let (status, colour) = row.status();

            queue!(out, cursor::MoveTo(0, y))?;
            if selected {
                queue!(out, SetAttribute(Attribute::Reverse))?;
            }
            queue!(
                out,
                Print(format!(
                    "  {} {:<name_width$}  ",
                    if selected { ">" } else { " " },
                    truncate(&row.origin.name, name_width),
                    name_width = name_width
                ))
            )?;
            queue!(
                out,
                SetForegroundColor(colour),
                Print(format!("{:<28}", truncate(&status, 28))),
                ResetColor
            )?;
            if selected {
                queue!(out, SetAttribute(Attribute::Reverse))?;
            }
            if row.origin.requires_auth {
                let signed_in = auth::load_token(&row.origin.id)
                    .ok()
                    .flatten()
                    .map(|t| !t.is_expired(paths::now_unix()))
                    .unwrap_or(false);
                queue!(
                    out,
                    SetForegroundColor(if signed_in { GOOD } else { MUTED }),
                    Print(if signed_in { "account" } else { "sign in" })
                )?;
            }
            queue!(out, SetAttribute(Attribute::Reset), ResetColor)?;
        }
        Ok(())
    }

    fn draw_detail<W: Write>(&self, out: &mut W, width: usize, height: usize) -> Result<()> {
        let Some(row) = self.current() else {
            return Ok(());
        };
        let mut y = 3u16;
        let line = |out: &mut W, y: &mut u16, text: String| -> Result<()> {
            queue!(out, cursor::MoveTo(0, *y), Print(truncate(&text, width - 4)))?;
            *y += 1;
            Ok(())
        };

        queue!(
            out,
            cursor::MoveTo(0, y),
            SetAttribute(Attribute::Bold),
            Print(format!("  {}", truncate(&row.origin.name, width - 4))),
            SetAttribute(Attribute::Reset)
        )?;
        y += 2;

        line(out, &mut y, format!("  id         {}", row.origin.id))?;
        if let Some(publisher) = &row.origin.publisher {
            line(out, &mut y, format!("  publisher  {publisher}"))?;
        }
        if let Some(homepage) = &row.origin.homepage {
            line(out, &mut y, format!("  home       {homepage}"))?;
        }
        line(
            out,
            &mut y,
            format!(
                "  installed  {}",
                row.state
                    .installed_version
                    .clone()
                    .unwrap_or_else(|| "not installed".into())
            ),
        )?;
        if let Some(dir) = &row.state.install_dir {
            line(out, &mut y, format!("  folder     {}", display_path(dir)))?;
        }
        line(
            out,
            &mut y,
            format!("  manifest   {}", row.origin.upstream_manifest_url),
        )?;

        if let Some(available) = &row.available {
            y += 1;
            line(
                out,
                &mut y,
                format!("  latest     {}", available.manifest.latest_version),
            )?;
            line(
                out,
                &mut y,
                format!(
                    "  size       {}",
                    available
                        .manifest
                        .artifact()
                        .map(|a| crate::net::human_bytes(a.size_bytes))
                        .unwrap_or_else(|_| "no build for this platform".into())
                ),
            )?;

            if let Some(notes) = available.manifest.display_notes() {
                y += 1;
                queue!(
                    out,
                    cursor::MoveTo(0, y),
                    SetForegroundColor(ACCENT),
                    Print(format!("  What's new in {}", available.manifest.latest_version)),
                    ResetColor
                )?;
                y += 2;
                for note in notes.iter().take(height.saturating_sub(y as usize + 3)) {
                    line(out, &mut y, format!("    {note}"))?;
                }
            }
        } else {
            y += 1;
            queue!(
                out,
                cursor::MoveTo(0, y),
                SetForegroundColor(MUTED),
                Print("  Press  c  to check for an update and load its release notes."),
                ResetColor
            )?;
        }

        if let Some(error) = &row.error {
            y += 1;
            queue!(
                out,
                cursor::MoveTo(0, y),
                SetForegroundColor(BAD),
                Print(format!("  {}", truncate(error, width - 4))),
                ResetColor
            )?;
        }
        Ok(())
    }

    /// The version picker: what the studio offers, and what is installed.
    fn draw_versions<W: Write>(&self, out: &mut W, width: usize, height: usize) -> Result<()> {
        let Some(row) = self.current() else {
            return Ok(());
        };
        let releases = row.releases();
        let installed = row.state.installed_version();

        queue!(
            out,
            cursor::MoveTo(0, 3),
            SetAttribute(Attribute::Bold),
            Print(format!(
                "  {} - choose a version",
                truncate(&row.origin.name, width.saturating_sub(24))
            )),
            SetAttribute(Attribute::Reset)
        )?;

        // Two lines per entry (version, then its first note), so the visible
        // count has to be halved or the notes scroll off under the footer.
        let visible = height.saturating_sub(8) / 2;
        let first = self.version_index.saturating_sub(visible.saturating_sub(1));
        let mut y = 5u16;

        for (offset, release) in releases.iter().skip(first).take(visible).enumerate() {
            let index = first + offset;
            let selected = index == self.version_index;
            let is_installed = installed.as_ref() == Some(&release.version);

            let mut tags = Vec::new();
            if release.is_latest {
                tags.push("latest");
            }
            if is_installed {
                tags.push("installed");
            }
            let size = release
                .artifact()
                .map(|a| crate::net::human_bytes(a.size_bytes))
                .unwrap_or_else(|_| "no build for this platform".into());

            queue!(out, cursor::MoveTo(0, y))?;
            if selected {
                queue!(out, SetAttribute(Attribute::Reverse))?;
            }
            queue!(
                out,
                Print(format!(
                    "  {} {:<14} {:<26}",
                    if selected { ">" } else { " " },
                    release.version.to_string(),
                    size
                ))
            )?;
            queue!(out, SetAttribute(Attribute::Reset))?;
            if !tags.is_empty() {
                queue!(
                    out,
                    SetForegroundColor(if is_installed { GOOD } else { ACCENT }),
                    Print(format!("[{}]", tags.join(", "))),
                    ResetColor
                )?;
            }
            y += 1;

            if let Some(notes) = release.display_notes() {
                if let Some(line) = notes.iter().find(|l| !l.trim().is_empty()) {
                    queue!(
                        out,
                        cursor::MoveTo(0, y),
                        SetForegroundColor(MUTED),
                        Print(format!("      {}", truncate(line, width.saturating_sub(8)))),
                        ResetColor
                    )?;
                }
            }
            y += 1;
        }

        if releases.len() > visible {
            queue!(
                out,
                cursor::MoveTo(0, y),
                SetForegroundColor(MUTED),
                Print(format!(
                    "  showing {}-{} of {}",
                    first + 1,
                    (first + visible).min(releases.len()),
                    releases.len()
                )),
                ResetColor
            )?;
        }
        Ok(())
    }

    fn draw_help<W: Write>(&self, out: &mut W, width: usize) -> Result<()> {
        let keys = [
            ("up / down, k / j", "move between applications"),
            ("enter", "open details and release notes"),
            ("c / C", "check the selected one / check all"),
            ("u", "update to the newest version"),
            ("v", "list every version and pick one"),
            ("a", "add a .origin file by typing its path"),
            ("drag a file in", "add it - no key needed"),
            ("l / L", "sign in to / out of a studio"),
            ("r", "stop tracking an application"),
            ("? , h", "this help"),
            ("q, esc, ctrl-c", "quit"),
        ];
        let mut y = 3u16;
        queue!(
            out,
            cursor::MoveTo(0, y),
            SetAttribute(Attribute::Bold),
            Print("  Keys"),
            SetAttribute(Attribute::Reset)
        )?;
        y += 2;
        for (key, description) in keys {
            queue!(
                out,
                cursor::MoveTo(0, y),
                SetForegroundColor(ACCENT),
                Print(format!("  {key:<18}")),
                ResetColor,
                Print(truncate(description, width.saturating_sub(24)))
            )?;
            y += 1;
        }
        y += 1;
        queue!(
            out,
            cursor::MoveTo(0, y),
            SetForegroundColor(MUTED),
            Print("  Updates always ask for folder permission on the normal"),
            cursor::MoveTo(0, y + 1),
            Print("  terminal before anything is written. This screen never"),
            cursor::MoveTo(0, y + 2),
            Print("  approves an update on your behalf."),
            ResetColor
        )?;
        Ok(())
    }

    fn draw_footer<W: Write>(&self, out: &mut W, width: usize, height: usize) -> Result<()> {
        let y = height.saturating_sub(2) as u16;
        let hints = match self.view {
            View::List => "up/down move   enter details   c check   u update   v versions   a add   q quit",
            View::Detail => "u update   v versions   c check   l login   esc back",
            View::Help => "esc back",
            View::Versions => "up/down choose   enter install this version   esc back",
        };
        queue!(
            out,
            cursor::MoveTo(0, y.saturating_sub(1)),
            SetForegroundColor(MUTED),
            Print(format!("  {}", "-".repeat(width.saturating_sub(4)))),
            cursor::MoveTo(0, y),
            Print(format!("  {}", truncate(hints, width.saturating_sub(4)))),
            ResetColor,
            cursor::MoveTo(0, y + 1),
            Print(format!("  {}", truncate(&self.status, width.saturating_sub(4))))
        )?;
        Ok(())
    }
}

/// Should `hermes` with no arguments open the interactive list?
///
/// Only when there is a real terminal on both ends. Piped or redirected, the
/// caller wants help text, not an alternate screen full of escape codes.
pub fn is_available() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// One-time hint printed after the interactive session, if the binary is not
/// yet installed where a shell can find it.
pub fn install_hint() -> Option<String> {
    if install::resolvable_on_path().is_some() {
        return None;
    }
    Some(format!(
        "Tip: run `{} install` to put hermes on your PATH so you can start it \
         from any terminal.",
        std::env::current_exe()
            .map(|p| display_path(&p))
            .unwrap_or_else(|_| "hermes".into())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Manifest, ORIGIN_SCHEMA};

    fn origin(id: &str, name: &str) -> OriginFile {
        OriginFile {
            schema: ORIGIN_SCHEMA.into(),
            id: id.into(),
            name: name.into(),
            upstream_manifest_url: "https://cdn.example.com/manifest.json".into(),
            studio_auth_url: None,
            public_key: "UepisXeS+U1Eehy5elRw+1d9QM00EGqg1XKp6kueHF8=".into(),
            publisher: Some("Example Studio".into()),
            homepage: None,
            requires_auth: false,
        }
    }

    fn manifest(version: &str, notes: Option<&str>) -> Manifest {
        Manifest {
            schema: crate::schema::MANIFEST_SCHEMA.into(),
            origin_id: "studio.game".into(),
            latest_version: version.into(),
            download_url: "https://cdn.example.com/game.zip".into(),
            checksum_sha256: "aa".repeat(32),
            size_bytes: 1024,
            issued_at: 1000,
            expires_at: None,
            release_notes: notes.map(str::to_string),
            release_notes_url: None,
            minimum_client_version: None,
            foiled_path: None,
            platforms: None,
            versions: None,
            requires_auth: false,
        }
    }

    fn app(rows: Vec<Row>, view: View) -> App {
        App {
            rows,
            selected: 0,
            view,
            status: "ready".into(),
            client: None,
            version_index: 0,
        }
    }

    fn row(id: &str, name: &str, available: Option<Available>) -> Row {
        Row {
            origin: origin(id, name),
            state: OriginState::default(),
            available,
            error: None,
        }
    }

    fn render(app: &App, width: usize, height: usize) -> String {
        let mut buffer: Vec<u8> = Vec::new();
        app.render(&mut buffer, width, height).expect("render");
        String::from_utf8_lossy(&buffer).into_owned()
    }

    #[test]
    fn truncation_never_exceeds_the_width() {
        assert_eq!(truncate("short", 10), "short");
        let cut = truncate("a very long application name indeed", 10);
        assert_eq!(cut.chars().count(), 10);
        // Control characters never reach the screen.
        assert_eq!(truncate("a\u{1b}[2Jb", 10), "a[2Jb");
    }

    #[test]
    fn status_reflects_what_is_known_about_a_row() {
        let mut plain = row("studio.game", "Game", None);
        assert_eq!(plain.status().0, "not installed");

        plain.state.installed_version = Some("1.0.0".into());
        assert_eq!(plain.status().0, "v1.0.0");

        let newer = row(
            "studio.game",
            "Game",
            Some(Available {
                manifest: manifest("2.0.0", None),
                installed: Some(semver::Version::parse("1.0.0").unwrap()),
                is_newer: true,
            }),
        );
        assert_eq!(newer.status().0, "update -> 2.0.0");

        let current = row(
            "studio.game",
            "Game",
            Some(Available {
                manifest: manifest("2.0.0", None),
                installed: Some(semver::Version::parse("2.0.0").unwrap()),
                is_newer: false,
            }),
        );
        assert_eq!(current.status().0, "up to date (2.0.0)");
    }

    /// The drawing code does a lot of width arithmetic. Render every view at
    /// awkward sizes and prove none of it underflows.
    #[test]
    fn renders_at_any_terminal_size_without_panicking() {
        let rows = || {
            vec![
                row("studio.one", "A Game With Quite A Long Name", None),
                row(
                    "studio.two",
                    "Another",
                    Some(Available {
                        manifest: manifest("3.1.0", Some("- fixed a thing\n- broke another")),
                        installed: Some(semver::Version::parse("3.0.0").unwrap()),
                        is_newer: true,
                    }),
                ),
            ]
        };
        for view in [View::List, View::Detail, View::Help, View::Versions] {
            for (width, height) in [(1, 1), (10, 3), (40, 10), (80, 24), (200, 60)] {
                let app = app(rows(), view_of(&view));
                let _ = render(&app, width, height);
            }
        }
        // And with nothing registered at all.
        for (width, height) in [(1, 1), (40, 10), (200, 60)] {
            let _ = render(&app(Vec::new(), View::List), width, height);
        }
    }

    fn view_of(view: &View) -> View {
        match view {
            View::List => View::List,
            View::Detail => View::Detail,
            View::Help => View::Help,
            View::Versions => View::Versions,
        }
    }

    #[test]
    fn list_shows_names_and_the_empty_state() {
        let output = render(&app(vec![row("studio.one", "Starfall", None)], View::List), 80, 24);
        assert!(output.contains("Starfall"), "{output}");
        assert!(output.contains("HERMES"));

        let empty = render(&app(Vec::new(), View::List), 80, 24);
        assert!(empty.contains("Nothing registered yet"), "{empty}");
    }

    #[test]
    fn detail_view_shows_signed_release_notes() {
        let app = app(
            vec![row(
                "studio.two",
                "Another",
                Some(Available {
                    manifest: manifest("3.1.0", Some("- adds the Deep Field expansion")),
                    installed: None,
                    is_newer: true,
                }),
            )],
            View::Detail,
        );
        let output = render(&app, 100, 30);
        assert!(output.contains("What's new in 3.1.0"), "{output}");
        assert!(output.contains("Deep Field expansion"), "{output}");
    }

    #[test]
    fn selection_stays_in_range() {
        let mut app = app(
            vec![row("a", "A", None), row("b", "B", None)],
            View::List,
        );
        app.move_selection(-5);
        assert_eq!(app.selected, 0);
        app.move_selection(50);
        assert_eq!(app.selected, 1);

        let mut empty = app_empty();
        empty.move_selection(1);
        assert_eq!(empty.selected, 0);
    }

    fn app_empty() -> App {
        app(Vec::new(), View::List)
    }

    // -- drag and drop -------------------------------------------------------

    fn typed(text: &str) -> Vec<KeyEvent> {
        text.chars()
            .map(|c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
            .collect()
    }

    /// The bug this exists to prevent: every character of a dropped path used
    /// to be handled as a hotkey, and the `a` in `...\Ca` opened the add
    /// prompt part way through, so only the tail was ever read.
    #[test]
    fn a_dropped_windows_path_is_recognised_whole() {
        let path = r"D:\Developing\CascadeProjects\Scripts\thething\test.origin";
        assert_eq!(dropped_path(&typed(path)).as_deref(), Some(path));

        // The tail that used to arrive at the prompt on its own is exactly
        // what must never be produced again.
        assert!(!dropped_path(&typed(path))
            .expect("recognised")
            .starts_with("scade"));
    }

    #[test]
    fn quoted_and_uri_drops_are_recognised() {
        for raw in [
            "\"C:\\Program Files\\Starfall\\starfall.origin\"",
            "'/home/u/My Game/game.origin'",
            "file:///home/u/My%20Game/game.origin",
            "/opt/games/starfall.origin",
            "./starfall.origin",
        ] {
            assert!(dropped_path(&typed(raw)).is_some(), "{raw}");
        }
        // A terminal that appends a newline to the drop.
        let mut with_enter = typed("/opt/games/starfall.origin");
        with_enter.push(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(dropped_path(&with_enter).is_some());
    }

    /// Key repeat produces a burst too. It must still reach the key map, or
    /// holding `j` would stop scrolling the list.
    #[test]
    fn a_run_of_repeated_keys_is_not_a_path() {
        assert!(dropped_path(&typed("jjjjjjjj")).is_none());
        assert!(dropped_path(&typed("kkkk")).is_none());
        // Short bursts are never paths.
        assert!(dropped_path(&typed("cu")).is_none());
        // Nor is anything with a chord or a navigation key in it.
        let mut mixed = typed("/opt/games/x");
        mixed.push(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert!(dropped_path(&mixed).is_none());
        let ctrl = vec![KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)]
            .into_iter()
            .chain(typed("/opt/x"))
            .collect::<Vec<_>>();
        assert!(dropped_path(&ctrl).is_none());
    }

    /// Waiting for the rest of a burst is only worth it for something that
    /// might be a path; holding `j` must never stall the redraw.
    #[test]
    fn only_a_path_shaped_burst_is_worth_waiting_for() {
        assert!(could_be_path(&typed(r"D:\Dev")));
        assert!(could_be_path(&typed("/opt")));
        assert!(could_be_path(&typed("~/g")));
        assert!(!could_be_path(&typed("jjjjjjjj")));
        assert!(!could_be_path(&typed("CCCC")));
    }

    /// A quoted path reaches no separator until its third character, so the
    /// decision has to wait a few characters rather than judging on the first.
    #[test]
    fn a_quoted_path_survives_its_opening_characters() {
        assert!(could_be_path(&typed("\"")));
        assert!(could_be_path(&typed("\"C")));
        assert!(could_be_path(&typed("\"C:")));
        assert!(could_be_path(&typed("\"C:\\Program Files\\x")));
    }

    /// Key repeat is the one burst that must be given up on immediately.
    #[test]
    fn a_held_key_is_abandoned_before_it_stalls_anything() {
        assert!(!could_be_path(&typed("jj")));
        assert!(!could_be_path(&typed("CC")));
        // ...but two *different* characters are still undecided.
        assert!(could_be_path(&typed("ab")));
    }

    /// Only a printable character can begin a path; navigation keys must act
    /// at once rather than paying the wait.
    #[test]
    fn only_printable_keys_begin_a_possible_drop() {
        assert!(starts_text(&KeyEvent::new(
            KeyCode::Char('D'),
            KeyModifiers::NONE
        )));
        assert!(!starts_text(&KeyEvent::new(
            KeyCode::Down,
            KeyModifiers::NONE
        )));
        assert!(!starts_text(&KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        )));
    }

    #[test]
    fn a_recognised_drop_is_a_path_the_registry_can_parse() {
        let raw = "\"D:\\Games\\My Game\\game.origin\"";
        let dropped = dropped_path(&typed(raw)).expect("recognised");
        assert_eq!(
            registry::normalize_dropped_path(&dropped),
            std::path::PathBuf::from("D:\\Games\\My Game\\game.origin")
        );
    }
}
