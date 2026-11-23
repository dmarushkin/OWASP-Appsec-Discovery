from appsec_discovery.services import ScanService


def find(objects, file, object_name):
    [obj] = [o for o in objects if o.file == file and o.object_name == object_name]
    return obj


def test_scan_service_default_config_load():

    scan_service = ScanService(source_folder="some")

    score_config = scan_service.config

    assert score_config.object_types[0] == 'all'

    assert score_config.score_tags['pii']['high'][0] == 'full_name'


def test_scan_service_custom_config_load(tests_dir):

    with open(tests_dir / "config_samples" / "conf.yaml") as conf_file:
        scan_service = ScanService(source_folder="some", conf_file=conf_file)

    score_config = scan_service.config

    assert score_config.object_types[0] == 'all'

    assert score_config.score_tags['pii']['high'][0] == 'firstname'


def test_scan_service_run_scanners(samples_dir):

    scan_service = ScanService(source_folder=str(samples_dir('swagger')), only_scored_objects=False)

    scanned_objects = scan_service.scan_folder()

    unscored = find(scanned_objects, '/swagger.yaml', 'GET /pet/findByStatus')
    assert unscored.severity is None

    scored = find(scanned_objects, '/swagger.yaml', 'POST /user')

    assert scored.severity == 'high'

    assert scored.properties['path'].prop_value == '/user'

    assert 'auth' in scored.tags

    assert not scored.fields['output.id'].severity

    assert scored.fields['input.firstName'].severity == 'high'
