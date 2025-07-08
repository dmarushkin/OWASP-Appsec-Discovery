from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.graphql.parser import GraphqlParser
import os
from pathlib import Path
import pytest

def test_parser_graphql_get_parser():

    pf = ParserFactory()

    parser = pf.get_parser('graphql')
    assert parser.__qualname__ == "GraphqlParser"


def test_parser_graphql_parse_folder():

    pf = ParserFactory()

    parserCls = pf.get_parser('graphql')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "graphql_samples")

    pr: GraphqlParser = parserCls(parser='graphql', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) == 4

    assert results[0].object_name ==  'Mutation BusinessLoungesMutations.createOrder'

    assert 'input.idempotencyKey' in results[1].fields.keys()


def test_parser_graphql_local_debug():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    pf = ParserFactory()

    parserCls = pf.get_parser('graphql')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "local_samples")

    pr: GraphqlParser = parserCls(parser='graphql', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) > 0
