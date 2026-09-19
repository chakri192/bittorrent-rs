//! The `download` binary's live terminal dashboard, built on `ratatui`.
//!
//! Architecture: the download orchestration runs on a background thread
//! and only ever touches shared state through a [`Ui`] handle -- it never
//! writes to stdout directly (that would corrupt the alternate screen).
//! The main thread owns the terminal and runs [`run`] (interactive TUI)
//! or [`run_plain`] (non-TTY fallback: periodic status lines), reading
//! the same shared [`AppState`].
//!
//! All the high-volume detail (every peer connect/disconnect, each PEX/DHT
//! discovery, per-piece verification) flows to the file `Logger` and a
//! bounded in-memory ring the dashboard tails; the summary numbers live in
//! a `Snapshot`.

use crate::sync::lock;
use crate::ui::{format_bytes, format_duration, format_rate, Logger, Snapshot};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Gauge, List, ListItem, Paragraph};
use ratatui::Frame;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LOG_RING_CAP: usize = 500;
const RATE_HISTORY_CAP: usize = 240;

/// Everything the dashboard reads, mutated only through a [`Ui`] handle.
pub struct AppState {
    pub title: String,
    pub out_path: String,
    pub log_path: Option<String>,
    pub snap: Snapshot,
    pub down_hist: VecDeque<u64>,
    pub up_hist: VecDeque<u64>,
    pub logs: VecDeque<String>,
    /// Per-piece completion, for the piece-map heatmap.
    pub pieces: Vec<bool>,
    /// `Some` once the run has ended: `Ok(summary)` or `Err(reason)`.
    pub finished: Option<Result<String, String>>,
}

impl AppState {
    fn new(title: String, out_path: String, log_path: Option<String>) -> Self {
        AppState { title, out_path, log_path, snap: Snapshot::default(), down_hist: VecDeque::new(), up_hist: VecDeque::new(), logs: VecDeque::new(), pieces: Vec::new(), finished: None }
    }
}

/// Cloneable handle the orchestration thread uses to publish state. Every
/// method takes `&self` and locks internally, so it can be shared freely.
#[derive(Clone)]
pub struct Ui {
    state: Arc<Mutex<AppState>>,
    log: Logger,
}

impl Ui {
    pub fn new(title: impl Into<String>, out_path: impl Into<String>, log: Logger) -> Self {
        // The log-path label shown in the footer is filled in later via
        // `set_log_path` (it isn't known until the output dir exists).
        Ui { state: Arc::new(Mutex::new(AppState::new(title.into(), out_path.into(), None))), log }
    }

    pub fn shared(&self) -> Arc<Mutex<AppState>> {
        Arc::clone(&self.state)
    }

    pub fn set_title(&self, title: impl Into<String>) {
        let mut s = lock(&self.state);
        s.title = title.into();
    }

    pub fn set_log_path(&self, path: Option<String>) {
        let mut s = lock(&self.state);
        s.log_path = path;
    }

    /// Appends one activity line: to the on-screen ring (bounded) and, if
    /// enabled, to the persistent log file.
    pub fn log(&self, msg: impl AsRef<str>) {
        let msg = msg.as_ref();
        self.log.line(msg);
        let mut s = lock(&self.state);
        s.logs.push_back(msg.to_string());
        while s.logs.len() > LOG_RING_CAP {
            s.logs.pop_front();
        }
    }

    /// Replaces the summary numbers shown in the stat panes.
    pub fn set_snapshot(&self, snap: Snapshot) {
        let mut s = lock(&self.state);
        s.snap = snap;
    }

    /// Updates the per-piece completion map (cheap `Vec<bool>` snapshot).
    pub fn set_pieces(&self, pieces: Vec<bool>) {
        let mut s = lock(&self.state);
        s.pieces = pieces;
    }

    /// Records one throughput sample for the sparklines.
    pub fn push_rates(&self, down: u64, up: u64) {
        let mut s = lock(&self.state);
        s.down_hist.push_back(down);
        s.up_hist.push_back(up);
        while s.down_hist.len() > RATE_HISTORY_CAP {
            s.down_hist.pop_front();
        }
        while s.up_hist.len() > RATE_HISTORY_CAP {
            s.up_hist.pop_front();
        }
    }

    pub fn finish(&self, result: Result<String, String>) {
        let mut s = lock(&self.state);
        s.finished = Some(result);
    }
}

/// Renders one Unicode block-element sparkline of `width` chars from the
/// most recent `width` samples (left-padded with spaces when short).
fn sparkline(data: &VecDeque<u64>, width: usize) -> String {
    const TICKS: [char; 8] = ['\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];
    if width == 0 {
        return String::new();
    }
    let start = data.len().saturating_sub(width);
    let slice: Vec<u64> = data.iter().skip(start).copied().collect();
    let max = slice.iter().copied().max().unwrap_or(0).max(1);
    let mut s = String::with_capacity(width);
    for _ in 0..width.saturating_sub(slice.len()) {
        s.push(' ');
    }
    for v in slice {
        let idx = ((v as f64 / max as f64) * (TICKS.len() - 1) as f64).round() as usize;
        s.push(TICKS[idx.min(TICKS.len() - 1)]);
    }
    s
}

/// Interactive dashboard. Returns `true` if the user asked to quit early
/// (q / Esc / Ctrl-C), `false` if the run finished on its own. The caller
/// restores the terminal and prints the final summary.
pub fn run(state: &Arc<Mutex<AppState>>, stop: &AtomicBool) -> bool {
    let mut terminal = ratatui::init();
    let mut user_quit = false;
    let mut frame: usize = 0;

    loop {
        frame = frame.wrapping_add(1);
        // Clone a lightweight view under the lock, then render lock-free.
        let view = {
            let s = lock(state);
            View {
                title: s.title.clone(),
                out_path: s.out_path.clone(),
                log_path: s.log_path.clone(),
                snap: s.snap.clone(),
                down_hist: s.down_hist.clone(),
                up_hist: s.up_hist.clone(),
                logs: s.logs.iter().cloned().collect(),
                pieces: s.pieces.clone(),
                finished: s.finished.clone(),
                frame,
            }
        };

        let _ = terminal.draw(|f| render(f, &view));

        // Finished on its own: leave the loop so the caller can print a
        // clean summary on the normal screen.
        if view.finished.is_some() {
            break;
        }

        if event::poll(Duration::from_millis(150)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if key.kind == KeyEventKind::Press {
                    let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
                    if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c {
                        user_quit = true;
                        stop.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        }
    }

    ratatui::restore();
    user_quit
}

/// Snapshot of `AppState` cloned once per frame so rendering never holds
/// the lock (the orchestration thread keeps updating meanwhile).
struct View {
    title: String,
    out_path: String,
    log_path: Option<String>,
    snap: Snapshot,
    down_hist: VecDeque<u64>,
    up_hist: VecDeque<u64>,
    logs: Vec<String>,
    pieces: Vec<bool>,
    finished: Option<Result<String, String>>,
    frame: usize,
}

/// Muted slate for panel borders/titles, so the colored content pops.
const BORDER: Color = Color::Rgb(70, 80, 95);
const TITLE: Color = Color::Rgb(130, 150, 180);

/// A rounded, subtly-bordered panel with a dim title -- the shared frame
/// for every section, for a consistent modern look.
fn panel(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .title(Span::styled(format!(" {} ", title), Style::default().fg(TITLE).add_modifier(Modifier::BOLD)))
}

fn render(f: &mut Frame, view: &View) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // header: name + progress gauge
            Constraint::Min(7),    // transfer stats | piece map
            Constraint::Length(6), // throughput | swarm
            Constraint::Min(4),    // activity log
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    render_header(f, rows[0], view);

    let mid = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Length(30), Constraint::Min(20)]).split(rows[1]);
    render_transfer(f, mid[0], view);
    render_piecemap(f, mid[1], view);

    let lower = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[2]);
    render_throughput(f, lower[0], view);
    render_swarm(f, lower[1], view);

    render_log(f, rows[3], view);
    render_footer(f, rows[4], view);
}

/// Braille spinner frames for the "live" indicator in the header.
const SPINNER: [char; 10] = ['\u{280b}', '\u{2819}', '\u{2839}', '\u{2838}', '\u{283c}', '\u{2834}', '\u{2826}', '\u{2827}', '\u{2807}', '\u{280f}'];

fn render_header(f: &mut Frame, area: Rect, view: &View) {
    let (glyph, glyph_style) = match &view.finished {
        Some(Ok(_)) => ('\u{2713}', Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Some(Err(_)) => ('\u{2717}', Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        None => (SPINNER[view.frame % SPINNER.len()], Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(format!(" {} ", glyph), glyph_style),
            Span::styled("bittorrent-rs ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]))
        .title(Line::from(Span::styled(format!(" {} ", format_duration(view.snap.elapsed_secs)), Style::default().fg(TITLE))).right_aligned());
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(1), Constraint::Length(1)]).split(inner);
    f.render_widget(Paragraph::new(Line::from(Span::styled(view.title.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)))), rows[0]);

    let snap = &view.snap;
    let frac = snap.fraction();
    let gauge_label = format!("{:.1}%   {} / {}", frac * 100.0, format_bytes(snap.done_bytes), format_bytes(snap.total_length));
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Rgb(120, 220, 130)).bg(Color::Rgb(35, 40, 48)))
        .use_unicode(true)
        .ratio(frac)
        .label(Span::styled(gauge_label, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));
    f.render_widget(gauge, rows[1]);
}

fn label(text: &str) -> Span<'static> {
    Span::styled(format!("{:<8}", text), Style::default().fg(Color::DarkGray))
}

fn render_transfer(f: &mut Frame, area: Rect, view: &View) {
    let block = panel("transfer");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let snap = &view.snap;
    let eta = snap.eta_secs.map(format_duration).unwrap_or_else(|| "--".to_string());
    let lines = vec![
        Line::from(vec![Span::styled("\u{25bc} ", Style::default().fg(Color::Green)), Span::styled(format_rate(snap.down_rate), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("\u{25b2} ", Style::default().fg(Color::Cyan)), Span::styled(format_rate(snap.up_rate), Style::default().fg(Color::Cyan))]),
        Line::from(vec![label("uploaded"), Span::raw(format_bytes(snap.up_bytes))]),
        Line::from(vec![label("eta"), Span::styled(eta, Style::default().add_modifier(Modifier::BOLD))]),
        Line::from(vec![label("pieces"), Span::raw(format!("{} / {}", snap.verified, snap.total_pieces))]),
        Line::from(vec![label("status"), Span::styled(format!("[{}]", snap.status), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

/// Gradient shade + glyph for a piece-map cell by its completion fraction.
fn shade(frac: f64) -> (char, Color) {
    if frac <= 0.0 {
        ('\u{b7}', Color::Rgb(55, 60, 72))
    } else if frac < 0.34 {
        ('\u{2591}', Color::Rgb(60, 110, 70))
    } else if frac < 0.67 {
        ('\u{2592}', Color::Rgb(90, 165, 95))
    } else if frac < 1.0 {
        ('\u{2593}', Color::Rgb(120, 205, 120))
    } else {
        ('\u{2588}', Color::Rgb(150, 240, 150))
    }
}

/// Renders the piece bitfield as a `w`x`h` heatmap: each cell aggregates a
/// contiguous block of pieces and is shaded by how many are complete. For
/// a 5,000-piece torrent on an 80-col terminal one cell covers ~10 pieces,
/// so the whole download's shape is visible at a glance.
fn piece_map_lines(pieces: &[bool], w: usize, h: usize) -> Vec<Line<'static>> {
    if w == 0 || h == 0 {
        return Vec::new();
    }
    if pieces.is_empty() {
        return vec![Line::from(Span::styled("(waiting for pieces\u{2026})", Style::default().fg(Color::DarkGray)))];
    }
    let cells = w * h;
    let n = pieces.len();
    let per_cell = n.div_ceil(cells).max(1);
    let mut lines = Vec::with_capacity(h);
    let mut idx = 0usize;
    for _ in 0..h {
        let mut spans = Vec::with_capacity(w);
        for _ in 0..w {
            if idx >= n {
                spans.push(Span::raw(" "));
                continue;
            }
            let end = (idx + per_cell).min(n);
            let done = pieces[idx..end].iter().filter(|&&b| b).count();
            let frac = done as f64 / (end - idx) as f64;
            let (ch, color) = shade(frac);
            spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            idx = end;
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn render_piecemap(f: &mut Frame, area: Rect, view: &View) {
    let block = panel("pieces");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let lines = piece_map_lines(&view.pieces, inner.width as usize, inner.height as usize);
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_throughput(f: &mut Frame, area: Rect, view: &View) {
    let block = panel("throughput");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let w = inner.width as usize;
    let lines = vec![
        Line::from(vec![Span::styled("\u{25bc} down  ", Style::default().fg(Color::DarkGray)), Span::styled(format_rate(view.snap.down_rate), Style::default().fg(Color::Green))]),
        Line::from(Span::styled(sparkline(&view.down_hist, w), Style::default().fg(Color::Green))),
        Line::from(vec![Span::styled("\u{25b2} up    ", Style::default().fg(Color::DarkGray)), Span::styled(format_rate(view.snap.up_rate), Style::default().fg(Color::Cyan))]),
        Line::from(Span::styled(sparkline(&view.up_hist, w), Style::default().fg(Color::Cyan))),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_swarm(f: &mut Frame, area: Rect, view: &View) {
    let block = panel("swarm");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let snap = &view.snap;
    let dot = Span::styled(" \u{b7} ", Style::default().fg(Color::DarkGray));
    let web = if snap.web_seeds > 0 {
        Span::styled(format!("web \u{d7}{}", snap.web_seeds), Style::default().fg(Color::Green))
    } else {
        Span::styled("web \u{d7}0", Style::default().fg(Color::DarkGray))
    };
    let endgame = if snap.endgame { Span::styled("endgame", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)) } else { Span::styled("", Style::default()) };
    let lines = vec![
        Line::from(vec![
            label("peers"),
            Span::styled(format!("{}", snap.active_peers), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(" active", Style::default().fg(Color::Gray)),
            dot.clone(),
            Span::styled(format!("{} dialed", snap.dialed_peers), Style::default().fg(Color::Gray)),
            dot.clone(),
            Span::styled(format!("{} known", snap.known_peers), Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            label("sources"),
            Span::styled(format!("trk {}/{}", snap.trackers_ok, snap.trackers_total), Style::default().fg(Color::Gray)),
            dot.clone(),
            Span::styled(format!("DHT {}", snap.dht_nodes), Style::default().fg(Color::Gray)),
            dot.clone(),
            Span::styled(format!("PEX +{}", snap.pex_total), Style::default().fg(Color::Gray)),
            dot,
            web,
        ]),
        Line::from(endgame),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

/// Classifies a log line by content into (glyph, color): successes green,
/// failures red, discovery/network events cyan, everything else dim.
fn log_symbol(msg: &str) -> (&'static str, Color) {
    let m = msg.to_ascii_lowercase();
    if m.contains("complete") || m.contains("verified") || m.contains("mapping via") {
        ("\u{2713}", Color::Green)
    } else if m.contains("fail") || m.contains("error") || m.contains("disconnect") || m.contains("mismatch") || m.contains("disabled") || m.contains("unreachable") || m.contains("refused") || m.contains("timed out") || m.starts_with("no ") {
        ("\u{2717}", Color::Red)
    } else if m.contains("dht") || m.contains("pex") || m.contains("web seed") || m.contains("announc") || m.contains("resolving") || m.contains("tracker") || m.contains("peer(s)") || m.contains("listening") || m.contains("ipv6") {
        ("\u{2022}", Color::Cyan)
    } else {
        ("\u{b7}", Color::DarkGray)
    }
}

fn render_log(f: &mut Frame, area: Rect, view: &View) {
    let block = panel("activity");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let capacity = inner.height as usize;
    let start = view.logs.len().saturating_sub(capacity);
    let items: Vec<ListItem> = view
        .logs
        .iter()
        .skip(start)
        .map(|l| {
            let (sym, color) = log_symbol(l);
            ListItem::new(Line::from(vec![Span::styled(format!("{} ", sym), Style::default().fg(color)), Span::styled(l.clone(), Style::default().fg(Color::Gray))]))
        })
        .collect();
    f.render_widget(List::new(items), inner);
}

fn render_footer(f: &mut Frame, area: Rect, view: &View) {
    let hint = match &view.finished {
        Some(Ok(_)) => Span::styled(" done \u{b7} q to exit ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        Some(Err(_)) => Span::styled(" failed \u{b7} q to exit ", Style::default().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD)),
        None => Span::styled(" q quit ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
    };
    let log = view.log_path.clone().unwrap_or_else(|| "(logging disabled)".to_string());
    let line = Line::from(vec![hint, Span::raw("  "), Span::styled(format!("log \u{2192} {}   out \u{2192} {}", log, view.out_path), Style::default().fg(Color::DarkGray))]);
    f.render_widget(Paragraph::new(line).alignment(Alignment::Left), area);
}

/// Non-TTY fallback: no ANSI, no alternate screen -- just a periodic
/// single status line (every ~3s) plus the final summary, so piped output
/// and CI logs stay clean. Returns `false` (never a user-initiated quit).
pub fn run_plain(state: &Arc<Mutex<AppState>>, stop: &AtomicBool) -> bool {
    let mut last = Instant::now() - Duration::from_secs(10);
    loop {
        let (snap, finished, title) = {
            let s = lock(state);
            (s.snap.clone(), s.finished.clone(), s.title.clone())
        };
        // The caller prints the final summary once, on the normal screen,
        // for both UI modes -- so just stop looping here.
        if finished.is_some() {
            return false;
        }
        if last.elapsed() >= Duration::from_secs(3) {
            let eta = snap.eta_secs.map(format_duration).unwrap_or_else(|| "--".to_string());
            println!(
                "[{:5.1}%] {} / {}  down {}  up {}  peers {}/{}  pieces {}/{}  DHT {}  ETA {}  [{}]  {}",
                snap.fraction() * 100.0,
                format_bytes(snap.done_bytes),
                format_bytes(snap.total_length),
                format_rate(snap.down_rate),
                format_rate(snap.up_rate),
                snap.active_peers,
                snap.dialed_peers,
                snap.verified,
                snap.total_pieces,
                snap.dht_nodes,
                eta,
                snap.status,
                title,
            );
            last = Instant::now();
        }
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `--quiet` mode: no output at all. Waits for the run to finish (or the
/// process to be killed) without touching stdout. Returns `false` (no
/// interactive quit path here).
pub fn run_silent(state: &Arc<Mutex<AppState>>, stop: &AtomicBool) -> bool {
    loop {
        if lock(state).finished.is_some() || stop.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_pads_left_and_scales_to_max() {
        let mut d = VecDeque::new();
        d.extend([0u64, 5, 10]);
        let line = sparkline(&d, 5);
        assert_eq!(line.chars().count(), 5);
        assert!(line.starts_with("  "), "short history is left-padded with spaces: {:?}", line);
        assert_eq!(line.chars().last(), Some('\u{2588}'), "the max sample is a full block");
        assert!(line.starts_with("  \u{2581}"), "the zero sample is the lowest tick: {:?}", line);
    }

    #[test]
    fn sparkline_zero_width_is_empty() {
        let mut d = VecDeque::new();
        d.push_back(1);
        assert_eq!(sparkline(&d, 0), "");
    }

    #[test]
    fn ui_handle_updates_shared_state_and_bounds_the_ring() {
        let ui = Ui::new("t", "/out", Logger::disabled());
        for i in 0..(LOG_RING_CAP + 50) {
            ui.log(format!("line {}", i));
        }
        ui.set_snapshot(Snapshot { verified: 7, ..Default::default() });
        ui.push_rates(100, 20);
        let s = ui.shared();
        let s = s.lock().unwrap();
        assert_eq!(s.logs.len(), LOG_RING_CAP, "ring is bounded");
        assert_eq!(s.logs.back().unwrap(), &format!("line {}", LOG_RING_CAP + 49));
        assert_eq!(s.snap.verified, 7);
        assert_eq!(s.down_hist.back().copied(), Some(100));
    }

    #[test]
    fn finish_records_result() {
        let ui = Ui::new("t", "/out", Logger::disabled());
        ui.finish(Ok("all done".to_string()));
        let s = ui.shared();
        assert!(matches!(s.lock().unwrap().finished, Some(Ok(ref m)) if m == "all done"));
    }

    #[test]
    fn a_poisoned_display_still_learns_that_the_download_finished() {
        // If finish() were skipped, plain mode would wait for a `finished`
        // that never arrives.
        let ui = Ui::new("t", "out", Logger::disabled());
        let shared = ui.shared();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = shared.lock().unwrap();
            panic!("a thread died holding the dashboard's lock");
        }));
        assert!(shared.is_poisoned(), "the setup must really poison it");

        ui.log("still logging");
        ui.finish(Ok("done".to_string()));

        let state = lock(&shared);
        assert!(matches!(state.finished, Some(Ok(ref m)) if m == "done"));
        assert_eq!(state.logs.back().map(String::as_str), Some("still logging"));
    }
}
