from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.java.parser import JavaParser
import os
from pathlib import Path
import pytest

# positional checks over a live semgrep run; the full output is pinned by tests/test_golden.py
pytestmark = pytest.mark.semgrep

def test_parser_java_get_parser():

    pf = ParserFactory()

    parser = pf.get_parser('java')
    assert parser.__qualname__ == "JavaParser"


def test_parser_java_parse_folder():

    pf = ParserFactory()

    parserCls = pf.get_parser('java')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "java_samples")

    pr: JavaParser = parserCls(parser='java', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) == 1 

    assert results[0].parser == 'java'
    assert results[0].object_name == 'AudioEntity'
    assert 'counter' in results[0].fields
    assert results[0].fields['acState'].file == '/javax.java'
