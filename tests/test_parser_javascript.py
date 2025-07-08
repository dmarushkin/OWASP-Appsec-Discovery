from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.javascript.parser import JsGqlParser
import os
from pathlib import Path
import pytest

def test_parser_javascript_get_parser():

    pf = ParserFactory()

    parser = pf.get_parser('javascript')
    assert parser.__qualname__ == "JsGqlParser"


def test_parser_javascript_parse_folder():

    pf = ParserFactory()

    parserCls = pf.get_parser('javascript')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "javascript_samples")

    pr: JsGqlParser = parserCls(parser='javascript', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) > 0

    assert results[0].parser == 'javascript'
    assert "JS GQL Resolver" in results[0].object_name


def test_parser_javascript_local_debug():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    pf = ParserFactory()

    parserCls = pf.get_parser('javascript')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "local_samples")

    pr: JsGqlParser = parserCls(parser='javascript', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) > 0