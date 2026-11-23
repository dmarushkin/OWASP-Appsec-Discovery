from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.protobuf.parser import ProtobufParser
import os
from pathlib import Path

def test_parser_protobuf_get_parser():

    pf = ParserFactory()

    parser = pf.get_parser('protobuf')
    assert parser.__qualname__ == "ProtobufParser"


def test_parser_protobuf_parse_folder():

    pf = ParserFactory()

    parserCls = pf.get_parser('protobuf')

    test_folder = str(Path(__file__).resolve().parent)
    samples_folder = os.path.join(test_folder, "protobuf_samples")

    pr: ProtobufParser = parserCls(parser='protobuf', source_folder=samples_folder)

    results = pr.run_scan()

    assert len(results) == 7

    assert results[5].object_type == 'rpc'
    assert results[5].object_name == '/search.SearchService/search'   # no type word in the name

    assert len(results[6].fields) > 0 


def test_protobuf_nested_fan_out_is_capped(tmp_path, caplog):
    # 8 fields of the next message on 6 levels: 8^6 leaves without a budget
    lines = ['syntax = "proto3";', 'package demo;', 'service S { rpc Get(M0) returns (M0); }']
    for level in range(6):
        body = ' '.join(f'M{level + 1} f{i} = {i + 1};' for i in range(8))
        lines.append(f'message M{level} {{ {body} }}')
    lines.append('message M6 { string leaf = 1; }')
    (tmp_path / 'api.proto').write_text('\n'.join(lines) + '\n')

    import logging
    with caplog.at_level(logging.INFO):
        [rpc] = ProtobufParser(parser='protobuf', source_folder=str(tmp_path)).run_scan()
    inputs = [k for k in rpc.fields if k.startswith('input.')]
    outputs = [k for k in rpc.fields if k.startswith('output.')]
    assert 0 < len(inputs) <= ProtobufParser.max_resolved_fields
    assert 0 < len(outputs) <= ProtobufParser.max_resolved_fields
    assert 'input.M0.f0.M1.f0.M2.f0.M3.f0.M4.f0.M5.f0' in rpc.fields     # the first branch is kept
    assert not any(f.field_type == 'Empty' for f in rpc.fields.values())  # no marker for truncated messages
    assert 'output truncated' in caplog.text


def test_protobuf_small_messages_are_not_truncated(tmp_path):
    (tmp_path / 'api.proto').write_text(
        'syntax = "proto3";\npackage demo;\nservice S { rpc Get(Req) returns (Empty); }\n'
        'message Money { int64 units = 1; string currency = 2; }\n'
        'message Req { Money a = 1; Money b = 2; }\nmessage Empty {}\n')
    [rpc] = ProtobufParser(parser='protobuf', source_folder=str(tmp_path)).run_scan()
    assert set(rpc.fields) == {'input.Req.a.Money.units', 'input.Req.a.Money.currency',
                               'input.Req.b.Money.units', 'input.Req.b.Money.currency', 'output.Empty'}
