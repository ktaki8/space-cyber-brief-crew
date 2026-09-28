"""Keep terminal output and saved briefs free of emojis.

CrewAI's progress display decorates its panels with emojis. install() wraps
stdout and stderr so every emoji is blanked out before it reaches the
terminal, keeping the panel borders aligned. Saved briefs have emojis removed
outright.
"""
import re
import sys

EMOJI = re.compile(
    "["
    "\U0001F000-\U0001FAFF"   # pictographs, emoticons, transport, flags, symbols
    "\u2600-\u27BF"           # miscellaneous symbols and dingbats
    "\u2B00-\u2BFF"           # arrows and stars used as emoji
    "\u23E9-\u23FA"           # media and clock symbols
    "\uFE0F\u200D"            # emoji presentation selector and joiner
    "]"
)
# An emoji followed by a space should not leave a double space behind.
EMOJI_WITH_SPACE = re.compile(EMOJI.pattern + r"+ ?")


def strip_emoji(text: str) -> str:
    """Remove emojis (for saved briefs)."""
    return EMOJI_WITH_SPACE.sub("", text)


def blank_emoji(text: str) -> str:
    """Replace emojis with spaces of the same on-screen width (for the
    terminal), so the panels CrewAI draws around them stay aligned."""
    from rich.cells import cell_len
    return EMOJI.sub(lambda m: " " * cell_len(m.group(0)), text)


class _EmojiFilter:
    """File-like wrapper that removes emojis from everything written to it."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        return self._stream.write(blank_emoji(text))

    def __getattr__(self, name):
        return getattr(self._stream, name)


def install():
    """Filter stdout and stderr for the rest of the program. Safe to call twice."""
    if not isinstance(sys.stdout, _EmojiFilter):
        sys.stdout = _EmojiFilter(sys.stdout)
    if not isinstance(sys.stderr, _EmojiFilter):
        sys.stderr = _EmojiFilter(sys.stderr)
