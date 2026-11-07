import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))


def offline_llm():
    from mock_llm import MockLLM
    return MockLLM()
