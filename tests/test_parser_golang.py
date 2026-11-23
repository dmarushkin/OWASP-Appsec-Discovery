from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.golang.parser import GolangParser
import os
from pathlib import Path
import pytest

# positional checks over a live semgrep run; the full output is pinned by tests/test_golden.py
pytestmark = pytest.mark.semgrep

def test_parser_golang_get_parser():

    pf = ParserFactory()

    parser = pf.get_parser('golang')
    assert parser.__qualname__ == "GolangParser"


def test_parser_golang_parse_folder():

    pf = ParserFactory()

    parserCls = pf.get_parser('golang')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "golang_samples")

    pr: GolangParser = parserCls(parser='golang', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) == 6 

    assert results[0].parser == 'golang'
    assert results[0].object_name == 'UserDTO'

    assert results[-1].parser == 'golang'
    assert results[-1].object_name == 'FullAccessRecoveryComment'
    assert results[-1].fields['ID'].field_name == 'ID'
