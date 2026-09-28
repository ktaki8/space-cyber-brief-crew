"""Read-only source reader for the Collector agent.

The source folder is chosen by the operator when the crew is built (default
sources/, or --sources / BRIEF_SOURCES_DIR). The agent cannot choose or change
it: the tool takes no arguments, so an instruction injected into a source
document cannot redirect this tool to other folders on the machine.
"""
import os
from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel

from sanitize import sanitize_text

# Absolute path to the default sources/ folder, resolved once at import.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_DIR = os.path.realpath(os.path.join(REPO_ROOT, "sources"))
SUPPORTED_EXTENSIONS = (".txt", ".md")


def list_source_files(sources_dir: str) -> list[str]:
    """Readable source files directly inside sources_dir, sorted.

    Hidden files, unsupported extensions, subfolders, and symlinks that
    resolve outside the folder are skipped. main.py and check_brief.py use
    the same rule, so all three agree on what the corpus is.
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


class FileReaderInput(BaseModel):
    """No arguments: the tool always reads the folder fixed at construction."""


class FileReaderTool(BaseTool):
    name: str = "Source Document Reader"
    description: str = (
        "Reads all approved .txt and .md source documents. "
        "Takes no arguments; the source folder is fixed."
    )
    args_schema: Type[BaseModel] = FileReaderInput
    sources_dir: str = SOURCES_DIR
    # Quarantine known injection patterns before the model sees the text.
    # Set by the operator (main.py --no-sanitize), never by the model.
    sanitize: bool = True

    def _run(self, **kwargs) -> str:
        # Any arguments the model tries to pass (such as a directory) are ignored.
        root = os.path.realpath(self.sources_dir)
        if not os.path.isdir(root):
            return "Error: approved sources directory not found."

        results = []
        for filename in list_source_files(root):
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                if self.sanitize:
                    content = sanitize_text(content).text
                content = content.strip()
                results.append(f"=== SOURCE: {filename} ===\n{content}\n=== END: {filename} ===\n")
            except Exception as e:
                results.append(f"=== SOURCE: {filename} ===\nError: {e}\n=== END: {filename} ===\n")

        if not results:
            return "No source documents found in the approved sources directory."
        return f"Found {len(results)} source document(s):\n\n" + "\n".join(results)
