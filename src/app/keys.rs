//! Keyboard handling.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use super::modal::*;
use super::{App, Page, ResetStage};
use crate::ui::theme::Theme;

impl App {
    pub fn handle_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q')) {
            self.should_quit = true;
            return;
        }
        if self.busy.is_some() {
            return;
        }
        if self.modal.is_some() {
            self.handle_modal_key(key);
            return;
        }
        if let Some(w) = &self.reset {
            match key.code {
                KeyCode::Esc => self.cancel_reset(),
                KeyCode::Enter if w.stage == ResetStage::Unplug => self.reset_now(),
                _ => {}
            }
            return;
        }
        if self.searching {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Down | KeyCode::Up => {
                    self.searching = false
                }
                KeyCode::Backspace => {
                    self.search.pop();
                }
                KeyCode::Char('u') if ctrl => self.search.clear(),
                KeyCode::Char(c) => self.search.push(c),
                _ => {}
            }
            self.passkeys.selected = 0;
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                return;
            }
            KeyCode::Char('?') => {
                self.modal = Some(Modal::Help { scroll: 0 });
                return;
            }
            KeyCode::Tab => {
                let i = (self.page.index() + 1) % Page::ALL.len();
                self.goto(Page::ALL[i]);
                return;
            }
            KeyCode::BackTab => {
                let i = (self.page.index() + Page::ALL.len() - 1) % Page::ALL.len();
                self.goto(Page::ALL[i]);
                return;
            }
            KeyCode::Char(c @ '1'..='9') => {
                let i = c as usize - '1' as usize;
                if let Some(p) = Page::ALL.get(i) {
                    self.goto(*p);
                }
                return;
            }
            KeyCode::Char(']') => {
                if !self.devices.is_empty() {
                    self.select_device((self.selected_device + 1) % self.devices.len());
                    self.on_page_enter();
                }
                return;
            }
            KeyCode::Char('[') => {
                if !self.devices.is_empty() {
                    let n = self.devices.len();
                    self.select_device((self.selected_device + n - 1) % n);
                    self.on_page_enter();
                }
                return;
            }
            KeyCode::Char('r') => {
                self.refresh_page();
                return;
            }
            KeyCode::Char('L') => {
                self.lock();
                return;
            }
            KeyCode::Char('T') => {
                self.theme = Theme::next(&self.theme);
                self.notify(Level::Info, format!("Theme: {}", self.theme.name));
                return;
            }
            KeyCode::Char('i') if self.page != Page::Passkeys => {
                self.identify();
                return;
            }
            _ => {}
        }

        match self.page {
            Page::Overview => self.overview_key(key),
            Page::Passkeys => self.passkeys_key(key),
            Page::Security => self.security_key(key),
            Page::Fingerprints => self.bio_key(key),
            Page::LargeBlobs => self.blobs_key(key),
            Page::Ssh => self.ssh_key(key),
            Page::Disk => self.disk_key(key),
            Page::Audit => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    self.audit_scroll = self.audit_scroll.saturating_add(1)
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.audit_scroll = self.audit_scroll.saturating_sub(1)
                }
                KeyCode::Char('x') => self.export_audit(true),
                KeyCode::Char('c') => self.export_audit(false),
                KeyCode::Char('u') => self.unlock(),
                _ => {}
            },
            Page::Info => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    self.info_scroll = self.info_scroll.saturating_add(1)
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.info_scroll = self.info_scroll.saturating_sub(1)
                }
                KeyCode::PageDown => self.info_scroll = self.info_scroll.saturating_add(10),
                KeyCode::PageUp => self.info_scroll = self.info_scroll.saturating_sub(10),
                KeyCode::Char('g') | KeyCode::Home => self.info_scroll = 0,
                _ => {}
            },
        }
    }

    pub fn handle_paste(&mut self, text: &str) {
        let text = text.trim_end_matches(['\n', '\r']);
        match &mut self.modal {
            Some(Modal::Pin(p)) => p.input.push_str(text),
            Some(Modal::Form(f)) => {
                if let Some(field) = f.fields.get_mut(f.focus).filter(|f| f.is_text_like()) {
                    for c in text.chars() {
                        field.input_char(c);
                    }
                }
            }
            Some(Modal::Confirm(c)) if c.type_to_confirm.is_some() => c.typed.push_str(text),
            None if self.searching => self.search.push_str(text),
            _ => {}
        }
    }

    fn refresh_page(&mut self) {
        self.scan_devices();
        match self.page {
            Page::Passkeys | Page::Ssh => self.load_credentials(false),
            Page::Fingerprints => self.load_fingerprints(false),
            Page::LargeBlobs => self.load_blobs(),
            Page::Disk | Page::Audit => self.load_luks(),
            _ => {}
        }
        if self.page == Page::Ssh {
            self.ssh_keys = crate::sys::ssh_sk_keys();
        }
        self.notify(Level::Info, "Refreshed");
    }

    fn overview_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.overview_list.down(self.devices.len());
                self.select_device(self.overview_list.selected);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.overview_list.up();
                self.select_device(self.overview_list.selected);
            }
            KeyCode::Char('t') => self.self_test(),
            KeyCode::Char('p') => {
                if self.device().is_some_and(|d| d.has_pin_set()) {
                    self.open_change_pin_form()
                } else {
                    self.open_set_pin_form()
                }
            }
            KeyCode::Char('u') => self.unlock(),
            _ => {}
        }
    }

    fn passkeys_key(&mut self, key: KeyEvent) {
        let n = self.filtered_credentials().len();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.passkeys.down(n),
            KeyCode::Char('k') | KeyCode::Up => self.passkeys.up(),
            KeyCode::Char('g') | KeyCode::Home => self.passkeys.selected = 0,
            KeyCode::Char('G') | KeyCode::End => self.passkeys.selected = n.saturating_sub(1),
            KeyCode::PageDown => (0..10).for_each(|_| self.passkeys.down(n)),
            KeyCode::PageUp => (0..10).for_each(|_| self.passkeys.up()),
            KeyCode::Char('/') => {
                if self.credentials().is_some() {
                    self.searching = true;
                }
            }
            KeyCode::Esc => {
                self.search.clear();
                self.passkeys.selected = 0;
            }
            KeyCode::Enter | KeyCode::Char('i') => self.show_credential_details(),
            KeyCode::Char('e') => self.edit_credential(),
            KeyCode::Char('d') | KeyCode::Delete => self.delete_credential(),
            KeyCode::Char('x') => self.export_credentials(),
            KeyCode::Char('u') => self.unlock(),
            _ => {}
        }
    }

    fn security_key(&mut self, key: KeyEvent) {
        let items = self.security_items();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.security.down(items.len()),
            KeyCode::Char('k') | KeyCode::Up => self.security.up(),
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(item) = items.get(self.security.selected) {
                    match &item.available {
                        Ok(()) => self.run_security_action(item.action),
                        Err(why) => self.notify(Level::Warn, why.clone()),
                    }
                }
            }
            KeyCode::Char('p') => {
                if self.device().is_some_and(|d| d.has_pin_set()) {
                    self.open_change_pin_form()
                } else {
                    self.open_set_pin_form()
                }
            }
            KeyCode::Char('v') => self.verify_pin(),
            KeyCode::Char('m') => self.open_min_pin_form(),
            KeyCode::Char('a') => self.toggle_always_uv(),
            KeyCode::Char('R') => self.start_factory_reset(),
            _ => {}
        }
    }

    fn bio_key(&mut self, key: KeyEvent) {
        let n = self
            .session()
            .and_then(|s| s.bio.as_ref())
            .map_or(0, |b| b.len());
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.bio_list.down(n),
            KeyCode::Char('k') | KeyCode::Up => self.bio_list.up(),
            KeyCode::Char('n') | KeyCode::Char('a') => self.enroll_fingerprint(),
            KeyCode::Char('e') => self.rename_fingerprint(),
            KeyCode::Char('d') | KeyCode::Delete => self.delete_fingerprint(),
            KeyCode::Char('u') => self.load_fingerprints(true),
            _ => {}
        }
    }

    fn blobs_key(&mut self, key: KeyEvent) {
        let n = self.blob_capable().len();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.blob_list.down(n),
            KeyCode::Char('k') | KeyCode::Up => self.blob_list.up(),
            KeyCode::Enter | KeyCode::Char('v') => self.view_blob(),
            KeyCode::Char('e') | KeyCode::Char('w') => self.edit_blob(),
            KeyCode::Char('s') => self.export_blob(),
            KeyCode::Char('d') | KeyCode::Delete => self.delete_blob(),
            KeyCode::Char('u') => {
                if self.credentials().is_some() {
                    self.load_blobs()
                } else {
                    self.unlock()
                }
            }
            _ => {}
        }
    }

    fn ssh_key(&mut self, key: KeyEvent) {
        let n = self.ssh_keys.len();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.ssh_list.down(n),
            KeyCode::Char('k') | KeyCode::Up => self.ssh_list.up(),
            KeyCode::Char('n') | KeyCode::Char('g') => self.ssh_generate(),
            KeyCode::Char('l') => self.ssh_download(),
            KeyCode::Enter => self.ssh_show_pubkey(),
            KeyCode::Char('u') => self.unlock(),
            _ => {}
        }
    }

    fn disk_key(&mut self, key: KeyEvent) {
        let n = self.luks.as_ref().map_or(0, |l| l.devices.len());
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.disk_list.down(n),
            KeyCode::Char('k') | KeyCode::Up => self.disk_list.up(),
            KeyCode::Char('a') => self.sudo_auth(),
            KeyCode::Char('e') => self.luks_enroll(),
            KeyCode::Char('x') => self.luks_wipe_fido2(),
            KeyCode::Char('b') => self.luks_backup_header(),
            KeyCode::Char('t') => self.luks_test_unlock(true),
            KeyCode::Char('w') => self.luks_test_unlock(false),
            KeyCode::Char('c') | KeyCode::Enter => self.luks_crypttab_help(),
            KeyCode::Char('n') => self.practice_create(),
            KeyCode::Char('D') => self.practice_delete(),
            _ => {}
        }
    }

    // Modals

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let Some(modal) = self.modal.as_mut() else {
            return;
        };
        match modal {
            Modal::Help { scroll } | Modal::Text { scroll, .. } => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?') => {
                    self.modal = None
                }
                KeyCode::Char('j') | KeyCode::Down => *scroll = scroll.saturating_add(1),
                KeyCode::Char('k') | KeyCode::Up => *scroll = scroll.saturating_sub(1),
                KeyCode::PageDown => *scroll = scroll.saturating_add(10),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                _ => {}
            },
            Modal::Message { .. } => {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char(' ')
                ) {
                    self.modal = None;
                }
            }
            Modal::Confirm(c) => {
                if c.type_to_confirm.is_some() {
                    match key.code {
                        KeyCode::Esc => self.modal = None,
                        KeyCode::Backspace => {
                            c.typed.pop();
                        }
                        KeyCode::Char(ch) if !ctrl => c.typed.push(ch),
                        KeyCode::Enter if c.can_confirm() => self.confirm_yes(),
                        _ => {}
                    }
                    return;
                }
                match key.code {
                    KeyCode::Esc | KeyCode::Char('n') => self.modal = None,
                    KeyCode::Left
                    | KeyCode::Right
                    | KeyCode::Tab
                    | KeyCode::Char('h')
                    | KeyCode::Char('l') => c.yes_selected = !c.yes_selected,
                    KeyCode::Char('y') => self.confirm_yes(),
                    KeyCode::Enter => {
                        if c.yes_selected {
                            self.confirm_yes()
                        } else {
                            self.modal = None
                        }
                    }
                    _ => {}
                }
            }
            Modal::Pin(p) => match key.code {
                KeyCode::Esc => self.modal = None,
                KeyCode::Backspace => {
                    p.input.pop();
                }
                KeyCode::Char('u') if ctrl => p.input.clear(),
                KeyCode::Char('r') if ctrl => p.reveal = !p.reveal,
                KeyCode::F(2) => p.reveal = !p.reveal,
                KeyCode::Char(ch) if !ctrl => p.input.push(ch),
                KeyCode::Enter => {
                    if p.input.chars().count() < p.min_len.min(4) {
                        p.error =
                            Some(format!("PINs are at least {} characters", p.min_len.min(4)));
                        return;
                    }
                    let pin = Zeroizing::new(p.input.as_str().to_string());
                    let cb = p.on_submit.take();
                    self.modal = None;
                    if let Some(cb) = cb {
                        cb(self, pin);
                    }
                }
                _ => {}
            },
            Modal::Form(f) => {
                let n = f.fields.len();
                match key.code {
                    KeyCode::Esc => self.modal = None,
                    KeyCode::Tab | KeyCode::Down => f.focus = (f.focus + 1) % n,
                    KeyCode::BackTab | KeyCode::Up => f.focus = (f.focus + n - 1) % n,
                    KeyCode::Left => f.fields[f.focus].cycle(false),
                    KeyCode::Right => f.fields[f.focus].cycle(true),
                    KeyCode::Backspace => {
                        f.fields[f.focus].value.pop();
                    }
                    KeyCode::Char('u') if ctrl => f.fields[f.focus].value.clear(),
                    KeyCode::Char(' ') if !f.fields[f.focus].is_text_like() => {
                        f.fields[f.focus].cycle(true)
                    }
                    KeyCode::Char(ch) if !ctrl => f.fields[f.focus].input_char(ch),
                    KeyCode::Enter => self.submit_form(),
                    _ => {}
                }
            }
        }
    }

    fn confirm_yes(&mut self) {
        if let Some(Modal::Confirm(mut c)) = self.modal.take()
            && let Some(cb) = c.on_yes.take()
        {
            cb(self);
        }
    }

    fn submit_form(&mut self) {
        let Some(Modal::Form(form)) = self.modal.take() else {
            return;
        };
        // The callback may open a follow-up modal (e.g. PIN prompt); keep the form
        // only if validation failed.
        match (form.on_submit)(self, &form.fields) {
            Ok(()) => {}
            Err(e) => {
                let mut form = form;
                form.error = Some(e);
                if self.modal.is_none() {
                    self.modal = Some(Modal::Form(form));
                }
            }
        }
    }
}
