"""Which files count as the source corpus. Shared by the pipeline and the auditor."""
import os

SUPPORTED_EXTENSIONS = (".txt", ".md")


def list_source_files(sources_dir):
    """Readable source files directly inside sources_dir, sorted.

    Hidden files, unsupported extensions, subfolders, and symlinks that
    resolve outside the folder are skipped, so the pipeline and the auditor
    agree on what the corpus is.
    """
    root = os.path.realpath(sources_dir)
    if not os.path.isdir(root):
        return []
    names = []
    for filename in sorted(os.listdir(root)):
        if filename.startswith(".") or not filename.endswith(SUPPORTED_EXTENSIONS):
            continue
        filepath = os.path.realpath(os.path.join(root, filename))
        if os.path.dirname(filepath) != root or not os.path.isfile(filepath):
            continue
        names.append(filename)
    return names


def load_corpus(sources_dir):
    texts = {}
    for name in list_source_files(sources_dir):
        with open(os.path.join(sources_dir, name), "r", encoding="utf-8") as f:
            texts[name] = f.read()
    return texts
