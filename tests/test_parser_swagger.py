from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.swagger.parser import SwaggerParser
import os
from pathlib import Path

def test_parser_swagger_get_parser():

    pf = ParserFactory()

    parser = pf.get_parser('swagger')
    assert parser.__qualname__ == "SwaggerParser"


def test_parser_swagger_parse_folder():

    pf = ParserFactory()

    parserCls = pf.get_parser('swagger')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "swagger_samples")

    pr: SwaggerParser = parserCls(parser='swagger', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) == 17 

    assert results[0].parser == 'swagger'
    assert results[0].object_name == 'Swagger route /pet (POST)'

    assert results[-1].parser == 'swagger'
    assert results[-1].object_name == 'Swagger route /user/{username} (PUT)'
    assert results[-1].fields['Input.username'].field_name == 'Input.username'