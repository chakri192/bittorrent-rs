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

use crate::ui::{format_bytes, format_duration, format_rate, Logger, Snapshot};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph};
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
    /// `Some` once the run has ended: `Ok(summary)` or `Err(reason)`.
    pub finished: Option<Result<String, String>>,
}

impl AppState {
    fn new(title: String, out_path: String, log_path: Option<String>) -> Self {
        AppState { title, out_path, log_path, snap: Snapshot::default(), down_hist: VecDeque::new(), up_hist: VecDeque::new(), logs: VecDeque::new(), finished: None }
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
        if let Ok(mut s) = self.state.lock() {
            s.title = title.into();
        }
    }

    pub fn set_log_path(&self, path: Option<String>) {
        if let Ok(mut s) = self.state.lock() {
            s.log_path = path;
        }
    }

    /// Appends one activity line: to the on-screen ring (bounded) and, if
    /// enabled, to the persistent log file.
    pub fn log(&self, msg: impl AsRef<str>) {
        let msg = msg.as_ref();
        self.log.line(msg);
        if let Ok(mut s) = self.state.lock() {
            s.logs.push_back(msg.to_string());
            while s.logs.len() > LOG_RING_CAP {
                s.logs.pop_front();
            }
        }
    }

    /// Replaces the summary numbers shown in the stat panes.
    pub fn set_snapshot(&self, snap: Snapshot) {
        if let Ok(mut s) = self.state.lock() {
            s.snap = snap;
        }
    }

    /// Records one throughput sample for the sparklines.
    pub fn push_rates(&self, down: u64, up: u64) {
        if let Ok(mut s) = self.state.lock() {
            s.down_hist.push_back(down);
            s.up_hist.push_back(up);
            while s.down_hist.len() > RATE_HISTORY_CAP {
                s.down_hist.pop_front();
            }
            while s.up_hist.len() > RATE_HISTORY_CAP {
                s.up_hist.pop_front();
            }
        }
    }

    pub fn finish(&self, result: Result<String, String>) {
        if let Ok(mut s) = self.state.lock() {
            s.finished = Some(result);
        }
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

    loop {
        // Clone a lightweight view under the lock, then render lock-free.
        let view = {
            let s = state.lock().unwrap();
            View {
                title: s.title.clone(),
                out_path: s.out_path.clone(),
                log_path: s.log_path.clone(),
                snap: s.snap.clone(),
                down_hist: s.down_hist.clone(),
                up_hist: s.up_hist.clone(),
                logs: s.logs.iter().cloned().collect(),
                finished: s.finished.clone(),
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
    finished: Option<Result<String, String>>,
}

fn render(f: &mut Frame, view: &View) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // header: name + progress gauge
            Constraint::Length(8), // transfer + throughput
            Constraint::Length(4), // swarm
            Constraint::Min(3),    // activity log
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    render_header(f, rows[0], view);

    let mid = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(42), Constraint::Percentage(58)]).split(rows[1]);
    render_transfer(f, mid[0], view);
    render_throughput(f, mid[1], view);

    render_swarm(f, rows[2], view);
    render_log(f, rows[3], view);
    render_footer(f, rows[4], view);
}

fn render_header(f: &mut Frame, area: Rect, view: &View) {
    let block = Block::default().borders(Borders::ALL).title(Span::styled(" bittorrent-rs ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(1), Constraint::Length(1)]).split(inner);
    f.render_widget(Paragraph::new(Line::from(Span::styled(view.title.clone(), Style::default().add_modifier(Modifier::BOLD)))), rows[0]);

    let snap = &view.snap;
    let frac = snap.fraction();
    let label = format!("{:.1}%   {} / {}", frac * 100.0, format_bytes(snap.done_bytes), format_bytes(snap.total_length));
    let gauge = Gauge::default().gauge_style(Style::default().fg(Color::Green).bg(Color::Rgb(30, 30, 30))).ratio(frac).label(Span::styled(label, Style::default().add_modifier(Modifier::BOLD)));
    f.render_widget(gauge, rows[1]);
}

fn label(text: &str) -> Span<'static> {
    Span::styled(format!("{:<8}", text), Style::default().fg(Color::DarkGray))
}

fn render_transfer(f: &mut Frame, area: Rect, view: &View) {
    let block = Block::default().borders(Borders::ALL).title(" transfer ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let snap = &view.snap;
    let eta = snap.eta_secs.map(format_duration).unwrap_or_else(|| "--".to_string());
    let lines = vec![
        Line::from(vec![label("down"), Span::styled(format_rate(snap.down_rate), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))]),
        Line::from(vec![label("up"), Span::styled(format_rate(snap.up_rate), Style::default().fg(Color::Cyan))]),
        Line::from(vec![label("uploaded"), Span::raw(format_bytes(snap.up_bytes))]),
        Line::from(vec![label("eta"), Span::styled(eta, Style::default().add_modifier(Modifier::BOLD))]),
        Line::from(vec![label("pieces"), Span::raw(format!("{} / {}", snap.verified, snap.total_pieces))]),
        Line::from(vec![label("status"), Span::styled(format!("[{}]", snap.status), Style::default().fg(Color::Magenta))]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_throughput(f: &mut Frame, area: Rect, view: &View) {
    let block = Block::default().borders(Borders::ALL).title(" throughput ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let w = inner.width as usize;
    let lines = vec![
        Line::from(Span::styled("download", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(sparkline(&view.down_hist, w), Style::default().fg(Color::Green))),
        Line::from(Span::styled("upload", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(sparkline(&view.up_hist, w), Style::default().fg(Color::Cyan))),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_swarm(f: &mut Frame, area: Rect, view: &View) {
    let block = Block::default().borders(Borders::ALL).title(" swarm ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let snap = &view.snap;
    let dot = Span::styled(" \u{b7} ", Style::default().fg(Color::DarkGray));
    let endgame = if snap.endgame { Span::styled("endgame on", Style::default().fg(Color::Yellow)) } else { Span::styled("endgame off", Style::default().fg(Color::DarkGray)) };
    let lines = vec![
        Line::from(vec![
            label("peers"),
            Span::styled(format!("{} active", snap.active_peers), Style::default().add_modifier(Modifier::BOLD)),
            dot.clone(),
            Span::raw(format!("{} dialed", snap.dialed_peers)),
            dot.clone(),
            Span::raw(format!("{} known", snap.known_peers)),
        ]),
        Line::from(vec![
            label("sources"),
            Span::raw(format!("trackers {}/{}", snap.trackers_ok, snap.trackers_total)),
            dot.clone(),
            Span::raw(format!("DHT {} nodes", snap.dht_nodes)),
            dot.clone(),
            Span::raw(format!("PEX +{}", snap.pex_total)),
            dot.clone(),
            if snap.web_seeds > 0 { Span::styled(format!("web \u{d7}{}", snap.web_seeds), Style::default().fg(Color::Green)) } else { Span::styled("web \u{d7}0", Style::default().fg(Color::DarkGray)) },
            dot,
            endgame,
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_log(f: &mut Frame, area: Rect, view: &View) {
    let block = Block::default().borders(Borders::ALL).title(" activity ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let capacity = inner.height as usize;
    let start = view.logs.len().saturating_sub(capacity);
    let items: Vec<ListItem> = view.logs.iter().skip(start).map(|l| ListItem::new(Line::from(Span::styled(l.clone(), Style::default().fg(Color::Gray))))).collect();
    f.render_widget(List::new(items), inner);
}

fn render_footer(f: &mut Frame, area: Rect, view: &View) {
    let hint = match &view.finished {
        Some(Ok(_)) => Span::styled(" done \u{b7} q to exit ", Style::default().fg(Color::Black).bg(Color::Green)),
        Some(Err(_)) => Span::styled(" failed \u{b7} q to exit ", Style::default().fg(Color::White).bg(Color::Red)),
        None => Span::styled(" q quit ", Style::default().fg(Color::Black).bg(Color::Cyan)),
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
            let s = state.lock().unwrap();
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
        if state.lock().unwrap().finished.is_some() || stop.load(Ordering::SeqCst) {
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
}
