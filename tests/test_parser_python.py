from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.python.parser import PythonParser
import os
from pathlib import Path
import pytest

# positional checks over a live semgrep run; the full output is pinned by tests/test_golden.py
pytestmark = pytest.mark.semgrep

def test_parser_python_get_parser():

    pf = ParserFactory()

    parser = pf.get_parser('python')
    assert parser.__qualname__ == "PythonParser"


def test_parser_python_parse_folder():

    pf = ParserFactory()

    parserCls = pf.get_parser('python')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "python_samples")

    pr: PythonParser = parserCls(parser='python', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) == 15 

    assert results[0].parser == 'python'
    assert results[0].object_name == 'User'

    assert results[-1].parser == 'python'
    assert results[-1].object_name == '/ (hello)'
