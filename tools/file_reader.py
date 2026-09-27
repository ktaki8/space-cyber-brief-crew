"""Read-only source reader for the Collector agent.

The approved directory is fixed in code. The agent cannot choose a
different path, so an instruction injected into a source document
cannot redirect this tool to other folders on the machine.
"""
import os
from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel

# Absolute path to the approved sources/ folder, resolved once at import.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_DIR = os.path.realpath(os.path.join(REPO_ROOT, "sources"))
SUPPORTED_EXTENSIONS = (".txt", ".md")


class FileReaderInput(BaseModel):
    """No arguments: the tool always reads the fixed sources/ folder."""


class FileReaderTool(BaseTool):
    name: str = "Source Document Reader"
    description: str = (
        "Reads all approved .txt and .md source documents. "
        "Takes no arguments; the source folder is fixed."
    )
    args_schema: Type[BaseModel] = FileReaderInput

    def _run(self, **kwargs) -> str:
        # Any arguments the model tries to pass (such as a directory) are ignored.
        if not os.path.isdir(SOURCES_DIR):
            return "Error: approved sources directory not found."

        results = []
        for filename in sorted(os.listdir(SOURCES_DIR)):
            if filename.startswith(".") or not filename.endswith(SUPPORTED_EXTENSIONS):
                continue
            filepath = os.path.realpath(os.path.join(SOURCES_DIR, filename))
            # Refuse symlinks or anything that resolves outside sources/.
            if os.path.dirname(filepath) != SOURCES_DIR or not os.path.isfile(filepath):
                continue
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                results.append(f"=== SOURCE: {filename} ===\n{content}\n=== END: {filename} ===\n")
            except Exception as e:
                results.append(f"=== SOURCE: {filename} ===\nError: {e}\n=== END: {filename} ===\n")

        if not results:
            return "No source documents found in the approved sources directory."
        return f"Found {len(results)} source document(s):\n\n" + "\n".join(results)
