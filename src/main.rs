use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use color_eyre::Result;
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event, EventStream, KeyEventKind,
};
use crossterm::execute;
use futures::StreamExt;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::interval;

use fido2_tui::app::App;
use fido2_tui::app::jobs::WorkerMsg;
use fido2_tui::fido::FidoBackend;
use fido2_tui::fido::native::Libfido2;
use fido2_tui::sys::{self, ExternalCommand};
use fido2_tui::ui::{self, theme::Theme};

#[derive(Parser, Debug)]
#[command(
    name = "fido2-tui",
    version,
    about = "Manage FIDO2 security keys: passkeys, PIN, fingerprints, SSH and LUKS unlock"
)]
struct Args {
    /// Color theme: nord, mocha, gruvbox, terminal
    #[arg(long, default_value = "nord")]
    theme: String,
    /// Print detected security keys and exit (no TUI)
    #[arg(long)]
    list: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    let backend: Arc<dyn FidoBackend> = Arc::new(Libfido2::new());

    if args.list {
        return list_devices(backend.as_ref());
    }

    let (mut app, mut rx) = App::new(backend);
    if let Some(t) = Theme::by_name(&args.theme) {
        app.theme = t;
    }
    app.start();

    let mut terminal = ratatui::init();
    execute!(std::io::stdout(), EnableBracketedPaste)?;
    let res = run(&mut terminal, &mut app, &mut rx).await;
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    res
}

async fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    rx: &mut UnboundedReceiver<WorkerMsg>,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut frame_tick = interval(Duration::from_millis(50));
    let mut slow_tick = interval(Duration::from_millis(250));

    while !app.should_quit {
        tokio::select! {
            _ = frame_tick.tick() => {
                terminal.draw(|f| ui::render(app, f))?;
            }
            _ = slow_tick.tick() => app.on_tick(),
            Some(msg) = rx.recv() => app.handle_worker(msg),
            ev = events.next() => match ev {
                Some(Ok(Event::Key(k))) if k.kind == KeyEventKind::Press => app.handle_key(k),
                Some(Ok(Event::Paste(s))) => app.handle_paste(&s),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => break,
            },
        }

        if let Some((cmd, reload)) = app.take_external() {
            // Stop reading the terminal while the child process owns it.
            drop(events);
            let ok = run_external(terminal, &cmd)?;
            events = EventStream::new();
            app.after_external(reload, ok);
        }
    }
    Ok(())
}

/// Suspend the TUI, run an interactive command on the real terminal, resume.
fn run_external(terminal: &mut ratatui::DefaultTerminal, cmd: &ExternalCommand) -> Result<bool> {
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    let mut out = std::io::stdout();
    write!(out, "\x1b[2J\x1b[H")?;
    writeln!(out, "\x1b[1;36m==> {}\x1b[0m", cmd.title)?;
    writeln!(out, "\x1b[2m$ {}\x1b[0m\n", cmd.display())?;
    out.flush()?;

    let mut c = std::process::Command::new(&cmd.program);
    c.args(&cmd.args);
    if let Some(dir) = &cmd.cwd {
        c.current_dir(dir);
    }
    // Ctrl-C / Ctrl-\ should stop the child, not fido2-tui: ignore them here and
    // restore default handling in the child before exec.
    use std::os::unix::process::CommandExt;
    unsafe {
        c.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }
    let prev_int = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
    let prev_quit = unsafe { libc::signal(libc::SIGQUIT, libc::SIG_IGN) };
    let status = c.status();
    unsafe {
        libc::signal(libc::SIGINT, prev_int);
        libc::signal(libc::SIGQUIT, prev_quit);
    }
    let ok = match status {
        Ok(s) if s.success() => {
            println!("\n\x1b[32m✓ Done.\x1b[0m");
            true
        }
        Ok(s) => {
            println!("\n\x1b[31m✗ Command exited with {s}.\x1b[0m");
            false
        }
        Err(e) => {
            println!("\n\x1b[31m✗ Could not run {}: {e}\x1b[0m", cmd.program);
            false
        }
    };
    print!("Press Enter to return to fido2-tui... ");
    let _ = out.flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);

    // A fresh Terminal has empty buffers, so the next draw repaints everything.
    // (Terminal::clear() would query the cursor position, which can time out here.)
    *terminal = ratatui::init();
    execute!(std::io::stdout(), EnableBracketedPaste)?;
    Ok(ok)
}

fn list_devices(backend: &dyn FidoBackend) -> Result<()> {
    let list = backend
        .enumerate()
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    if list.is_empty() {
        println!("No FIDO security keys found.");
    }
    for s in &list {
        match backend.device_info(s) {
            Ok(d) => {
                println!(
                    "{}  {}  ({:04x}:{:04x})",
                    d.path,
                    d.display_name(),
                    d.vendor_id,
                    d.product_id
                );
                println!(
                    "    firmware {}  ·  {}",
                    d.fw_version_string().unwrap_or_else(|| "?".into()),
                    d.versions.join(" ")
                );
                println!(
                    "    PIN {}{}",
                    if d.has_pin_set() {
                        "set"
                    } else if d.supports_pin() {
                        "not set"
                    } else {
                        "unsupported"
                    },
                    d.pin_retries
                        .map(|r| format!(" ({r} retries left)"))
                        .unwrap_or_default()
                );
            }
            Err(e) => println!("{}  {}  - error: {e}", s.path, s.product),
        }
    }
    for k in sys::inaccessible_fido_nodes() {
        println!(
            "{}  {}  - NOT ACCESSIBLE (permission denied; run ./install.sh to add a udev rule)",
            k.node, k.name
        );
    }
    Ok(())
}
