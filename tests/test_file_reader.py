import os

from tools.file_reader import FileReaderTool, list_source_files


def test_reads_only_supported_files(tmp_path):
    (tmp_path / "a.md").write_text("alpha", encoding="utf-8")
    (tmp_path / "b.txt").write_text("bravo", encoding="utf-8")
    (tmp_path / "c.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".hidden.md").write_text("hidden", encoding="utf-8")
    assert list_source_files(str(tmp_path)) == ["a.md", "b.txt"]


def test_skips_symlinks_that_leave_the_folder(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("do not read", encoding="utf-8")
    os.symlink(secret, corpus / "link.txt")
    (corpus / "ok.md").write_text("fine", encoding="utf-8")
    out = FileReaderTool(sources_dir=str(corpus))._run()
    assert "fine" in out and "do not read" not in out


def test_ignores_arguments_from_the_model(tmp_path):
    (tmp_path / "a.md").write_text("alpha", encoding="utf-8")
    tool = FileReaderTool(sources_dir=str(tmp_path))
    out = tool._run(directory="/etc", path="/etc/passwd")
    assert "alpha" in out and "root:" not in out


def test_default_folder_is_sources():
    assert FileReaderTool().sources_dir.endswith("sources")
