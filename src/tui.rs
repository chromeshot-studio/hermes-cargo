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
use crate::schema::OriginFile;
use crate::security::safepath::display_path;
use crate::update::{self, Available, UpdateOptions};
use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{cursor, execute, queue};
use std::io::{stdout, IsTerminal, Stdout, Write};

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
        Ok(Self { out })
    }

    /// Drop back to the normal screen, run `body`, then come back.
    fn suspend<T>(&mut self, body: impl FnOnce() -> T) -> Result<T> {
        execute!(self.out, LeaveAlternateScreen, cursor::Show)?;
        disable_raw_mode()?;
        let outcome = body();
        press_any_key();
        enable_raw_mode()?;
        execute!(self.out, EnterAlternateScreen, cursor::Hide)?;
        Ok(outcome)
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
}

struct App {
    rows: Vec<Row>,
    selected: usize,
    view: View,
    status: String,
    client: Option<HttpClient>,
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

    loop {
        app.draw(&mut screen)?;
        let Some(key) = next_key()? else { continue };

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
                KeyCode::Char('u') => act_update(&mut app, &mut screen)?,
                KeyCode::Char('c') => app.check_selected(&mut screen)?,
                KeyCode::Char('l') => act_login(&mut app, &mut screen)?,
                KeyCode::Char('?') => app.view = View::Help,
                _ => {}
            },
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
                KeyCode::Char('u') => act_update(&mut app, &mut screen)?,
                KeyCode::Char('a') => act_add(&mut app, &mut screen)?,
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
    }
    Ok(())
}

/// Read one key press. Windows reports both press and release; acting on both
/// would make every keystroke fire twice.
fn next_key() -> Result<Option<KeyEvent>> {
    match event::read().context("reading a key")? {
        Event::Key(key) if key.kind == KeyEventKind::Press => Ok(Some(key)),
        _ => Ok(None),
    }
}

impl App {
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

fn act_update(app: &mut App, screen: &mut Screen) -> Result<()> {
    let Some(row) = app.current() else {
        app.status = "nothing selected".into();
        return Ok(());
    };
    let origin = row.origin.clone();
    let known = row.available.is_some();

    let outcome = screen.suspend(|| -> Result<()> {
        let client = HttpClient::new()?;
        if !known {
            println!("\n  Checking {}...", origin.name);
        }
        let available = update::check(&client, &origin)?;
        if !available.is_newer {
            println!(
                "\n  {} is already up to date ({}).",
                origin.name, available.manifest.latest_version
            );
            return Ok(());
        }
        // The consent prompt inside `apply` is the real one, on the real
        // terminal: the interactive mode never approves anything on its own.
        update::apply(&client, &origin, &available, &UpdateOptions::default())
    })?;

    match outcome {
        Ok(()) => app.status = format!("{} finished", origin.name),
        Err(e) => app.status = format!("{}: {e:#}", origin.name),
    }
    app.reload()?;
    Ok(())
}

fn act_add(app: &mut App, screen: &mut Screen) -> Result<()> {
    let outcome = screen.suspend(|| -> Result<String> {
        println!("\n  Drag a .origin file into this window and press Enter.");
        print!("  > ");
        let _ = stdout().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let line = line.trim().to_string();
        if line.is_empty() {
            return Ok("cancelled".into());
        }
        let path = registry::normalize_dropped_path(&line);
        let origin = registry::read_origin_file(&path)?;
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
                Print("  Press  a  to add a .origin file (drag and drop works)."),
                cursor::MoveTo(0, 6),
                Print("  A studio gives you that file; it is the trust root for"),
                cursor::MoveTo(0, 7),
                Print("  everything HERMES will install for them."),
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
                    crate::net::human_bytes(available.manifest.size_bytes)
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

    fn draw_help<W: Write>(&self, out: &mut W, width: usize) -> Result<()> {
        let keys = [
            ("up / down, k / j", "move between applications"),
            ("enter", "open details and release notes"),
            ("c / C", "check the selected one / check all"),
            ("u", "update the selected application"),
            ("a", "add a .origin file (drag and drop it in)"),
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
            View::List => "up/down move   enter details   c check   u update   a add   ? help   q quit",
            View::Detail => "u update   c check   l login   esc back   q back",
            View::Help => "esc back",
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
            install_dir: None,
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
        for view in [View::List, View::Detail, View::Help] {
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
}
