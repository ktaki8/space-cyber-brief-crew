import io

from plain_output import _EmojiFilter, strip_emoji


def test_emojis_removed_and_spacing_kept():
    assert strip_emoji("\U0001F4CB Task Started") == "Task Started"
    assert strip_emoji("\u2705 Agent Final Answer") == "Agent Final Answer"
    assert strip_emoji("Agent: \U0001F916 Writer") == "Agent: Writer"
    assert strip_emoji("Severity: High \u26a0\ufe0f") == "Severity: High "


def test_box_drawing_and_ordinary_text_kept():
    text = "\u256d\u2500 Task Completion \u2500\u256e\n\u2502 Collector \u2192 Analyst \u2502 caf\u00e9"
    assert strip_emoji(text) == text


def test_stream_filter():
    buffer = io.StringIO()
    stream = _EmojiFilter(buffer)
    stream.write("\U0001F50D Detailed execution traces")
    assert buffer.getvalue().strip() == "Detailed execution traces"
    assert stream.getvalue() == buffer.getvalue()  # other attributes pass through


def test_rich_console_output_is_filtered():
    from rich.console import Console
    from rich.panel import Panel
    buffer = io.StringIO()
    Console(file=_EmojiFilter(buffer), width=60).print(Panel("\u2705 Agent Final Answer", title="\U0001F916 Agent Started"))
    out = buffer.getvalue()
    assert "Agent Final Answer" in out and "Agent Started" in out
    assert not any(ch in out for ch in "\u2705\U0001F916")
    from rich.cells import cell_len
    widths = {cell_len(line) for line in out.splitlines() if line}
    assert len(widths) == 1  # panel borders stay aligned
