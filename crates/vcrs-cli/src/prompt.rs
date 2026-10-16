//! Asking for a password at the terminal, without echoing it.
//!
//! The flags (`--password`, `$VCRS_PASSWORD`, `--password-stdin`) are for scripts
//! and for a GUI. A person who types `vcrs info secret.vc` at a prompt expects to
//! be asked, the way VeraCrypt asks — and a password given on the command line
//! ends up in the process list, so nobody should be nudged into that. When stdin
//! is not a terminal the old refusal is kept instead, so a script that forgot a
//! password fails rather than waiting forever.

use anyhow::{Context, Result};

/// Ask for a password, or fail with `missing` when there is nobody to ask.
pub fn password(missing: &str) -> Result<Vec<u8>> {
    if !at_a_terminal() {
        anyhow::bail!("{missing}");
    }
    ask("Password (not shown): ")
}

/// Ask for a password twice, for a password that is being *set* rather than
/// checked: one typo would otherwise make the volume unopenable for good.
pub fn new_password(missing: &str) -> Result<Vec<u8>> {
    if !at_a_terminal() {
        anyhow::bail!("{missing}");
    }
    let first = ask("New password (not shown): ")?;
    if first.is_empty() {
        anyhow::bail!(
            "the new password would be empty — type one, or pass the empty password with \
             --password \"\" if that is really what you want"
        );
    }
    let again = ask("Repeat the new password: ")?;
    if first != again {
        anyhow::bail!("the two passwords differ");
    }
    Ok(first)
}

/// Read a secret that is not a password — a master key, in hex — from a pipe or
/// from the terminal with the echo off. Unlike a password this has to be
/// readable from a pipe, because keeping it out of the process list is the whole
/// point of the flag.
pub fn secret_line(label: &str, missing: &str) -> Result<String> {
    let text = if at_a_terminal() {
        use std::io::Write as _;
        eprint!("{label}");
        std::io::stderr().flush().ok();
        let text = read_hidden()?;
        eprintln!();
        text
    } else {
        use std::io::BufRead as _;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("reading the value from standard input")?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    if text.is_empty() {
        anyhow::bail!("{missing}");
    }
    Ok(text)
}

fn ask(label: &str) -> Result<Vec<u8>> {
    use std::io::Write as _;
    eprint!("{label}");
    std::io::stderr().flush().ok();
    let text = read_hidden()?;
    eprintln!();
    Ok(text.into_bytes())
}

/// True when there is a console on stdin, i.e. somebody is there to answer.
fn at_a_terminal() -> bool {
    platform::at_a_terminal()
}

/// Read one line with the echo off, and put the terminal back afterwards.
fn read_hidden() -> Result<String> {
    platform::read_hidden()
}

#[cfg(windows)]
mod platform {
    use anyhow::{bail, Context, Result};
    use std::io::BufRead as _;
    use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_INPUT_HANDLE;

    /// `ENABLE_ECHO_INPUT`, which winapi keeps in the `wincon` feature we do not
    /// otherwise need. Declared here for the same reason as the other constants
    /// this crate spells out.
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    pub(super) fn at_a_terminal() -> bool {
        let mut mode = 0;
        unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut mode) != 0 }
    }

    pub(super) fn read_hidden() -> Result<String> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut mode = 0;
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            bail!("there is no console to read the password from");
        }
        if unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0 {
            bail!("Windows would not switch the echo off for the password");
        }
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line);
        // Whatever happened, the console goes back the way it was.
        unsafe { SetConsoleMode(handle, mode) };
        read.context("reading the password")?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

#[cfg(unix)]
mod platform {
    use anyhow::{bail, Result};
    use std::io::BufRead as _;
    use std::os::fd::AsRawFd as _;

    pub(super) fn at_a_terminal() -> bool {
        unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
    }

    pub(super) fn read_hidden() -> Result<String> {
        let fd = std::io::stdin().as_raw_fd();
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
            bail!("there is no terminal to read the password from");
        }
        let original = term;
        term.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
            bail!("the terminal would not switch the echo off for the password");
        }
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line);
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
        read?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    use anyhow::{bail, Result};

    pub(super) fn at_a_terminal() -> bool {
        false
    }

    pub(super) fn read_hidden() -> Result<String> {
        bail!("this system has no terminal password prompt")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn without_a_terminal_the_old_refusal_is_kept() {
        // Under `cargo test` stdin is usually a pipe; when it is a terminal the
        // prompt would block, so the test steps aside.
        if super::at_a_terminal() {
            return;
        }
        let error = super::password("no password given")
            .unwrap_err()
            .to_string();
        assert_eq!(error, "no password given");
    }
}
