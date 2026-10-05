use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub name: &'static str,
    pub bg: Color,
    pub surface: Color,
    pub overlay: Color,
    pub fg: Color,
    pub muted: Color,
    pub accent: Color,
    pub accent2: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
    pub info: Color,
    pub border: Color,
    pub selection: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self::nord()
    }
}

impl Theme {
    pub fn nord() -> Self {
        Self {
            name: "Nord",
            bg: Color::Rgb(46, 52, 64),
            surface: Color::Rgb(59, 66, 82),
            overlay: Color::Rgb(67, 76, 94),
            fg: Color::Rgb(236, 239, 244),
            muted: Color::Rgb(146, 154, 170),
            accent: Color::Rgb(136, 192, 208),
            accent2: Color::Rgb(180, 142, 173),
            success: Color::Rgb(163, 190, 140),
            warning: Color::Rgb(235, 203, 139),
            danger: Color::Rgb(191, 97, 106),
            info: Color::Rgb(129, 161, 193),
            border: Color::Rgb(76, 86, 106),
            selection: Color::Rgb(67, 76, 94),
        }
    }

    pub fn mocha() -> Self {
        Self {
            name: "Catppuccin Mocha",
            bg: Color::Rgb(30, 30, 46),
            surface: Color::Rgb(49, 50, 68),
            overlay: Color::Rgb(69, 71, 90),
            fg: Color::Rgb(205, 214, 244),
            muted: Color::Rgb(147, 153, 178),
            accent: Color::Rgb(137, 180, 250),
            accent2: Color::Rgb(203, 166, 247),
            success: Color::Rgb(166, 227, 161),
            warning: Color::Rgb(249, 226, 175),
            danger: Color::Rgb(243, 139, 168),
            info: Color::Rgb(116, 199, 236),
            border: Color::Rgb(88, 91, 112),
            selection: Color::Rgb(69, 71, 90),
        }
    }

    pub fn gruvbox() -> Self {
        Self {
            name: "Gruvbox",
            bg: Color::Rgb(40, 40, 40),
            surface: Color::Rgb(60, 56, 54),
            overlay: Color::Rgb(80, 73, 69),
            fg: Color::Rgb(235, 219, 178),
            muted: Color::Rgb(168, 153, 132),
            accent: Color::Rgb(131, 165, 152),
            accent2: Color::Rgb(211, 134, 155),
            success: Color::Rgb(184, 187, 38),
            warning: Color::Rgb(250, 189, 47),
            danger: Color::Rgb(251, 73, 52),
            info: Color::Rgb(142, 192, 124),
            border: Color::Rgb(102, 92, 84),
            selection: Color::Rgb(80, 73, 69),
        }
    }

    /// Uses the terminal's own palette - works on light and dark terminals.
    pub fn terminal() -> Self {
        Self {
            name: "Terminal",
            bg: Color::Reset,
            surface: Color::Reset,
            overlay: Color::Reset,
            fg: Color::Reset,
            muted: Color::DarkGray,
            accent: Color::Cyan,
            accent2: Color::Magenta,
            success: Color::Green,
            warning: Color::Yellow,
            danger: Color::Red,
            info: Color::Blue,
            border: Color::DarkGray,
            selection: Color::DarkGray,
        }
    }

    pub const ALL: [fn() -> Theme; 4] =
        [Theme::nord, Theme::mocha, Theme::gruvbox, Theme::terminal];

    pub fn by_name(name: &str) -> Option<Theme> {
        let n = name.to_lowercase();
        Self::ALL
            .iter()
            .map(|f| f())
            .find(|t| t.name.to_lowercase().contains(&n))
    }

    pub fn next(&self) -> Theme {
        let all: Vec<Theme> = Self::ALL.iter().map(|f| f()).collect();
        let i = all.iter().position(|t| t.name == self.name).unwrap_or(0);
        all[(i + 1) % all.len()]
    }

    pub fn base(&self) -> Style {
        Style::default().fg(self.fg).bg(self.bg)
    }

    pub fn text(&self) -> Style {
        Style::default().fg(self.fg)
    }

    pub fn dim(&self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn title(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn bold(&self) -> Style {
        Style::default().fg(self.fg).add_modifier(Modifier::BOLD)
    }

    pub fn key(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn border(&self, focused: bool) -> Style {
        Style::default().fg(if focused { self.accent } else { self.border })
    }

    pub fn selected(&self) -> Style {
        Style::default()
            .bg(self.selection)
            .fg(self.fg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn fg(&self, c: Color) -> Style {
        Style::default().fg(c)
    }

    pub fn badge(&self, c: Color) -> Style {
        let fg = if self.bg == Color::Reset {
            Color::Black
        } else {
            self.bg
        };
        Style::default().fg(fg).bg(c).add_modifier(Modifier::BOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycles_through_all_themes() {
        let mut t = Theme::default();
        let mut seen = vec![t.name];
        for _ in 0..Theme::ALL.len() - 1 {
            t = t.next();
            seen.push(t.name);
        }
        assert_eq!(t.next().name, "Nord");
        seen.dedup();
        assert_eq!(seen.len(), Theme::ALL.len());
        assert_eq!(Theme::by_name("mocha").unwrap().name, "Catppuccin Mocha");
    }
}
