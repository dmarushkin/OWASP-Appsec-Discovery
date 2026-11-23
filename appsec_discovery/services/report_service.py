"""Deprecated: use ``appsec_discovery.render_report`` and write the string yourself."""
import logging
from typing import List

from appsec_discovery.models import CodeObject
from appsec_discovery.reports import render_json, render_report, render_sarif, render_yaml

logger = logging.getLogger(__name__)


class ReportService:
    """Backward-compatible wrapper over the pure renderers in ``appsec_discovery.reports``."""

    def __init__(self, code_objects: List[CodeObject], report_type, report_file):

        self.report_type = report_type
        self.report_file = report_file

        self.code_objects = code_objects

    def render(self) -> str:
        """The report text; ``ValueError`` for an unknown ``report_type``."""
        return render_report(self.code_objects, self.report_type)

    def save_report_to_disk(self):
        """Write the report to ``report_file`` (left open: the caller owns it) or print it to stdout."""
        report_str = self.render()

        if self.report_file:
            self.report_file.write(report_str)
            self.report_file.flush()
        else:
            print(report_str)

    def get_json_report(self) -> str:
        return render_json(self.code_objects)

    def get_yaml_report(self) -> str:
        return render_yaml(self.code_objects)

    def get_sarif_report(self) -> str:
        return render_sarif(self.code_objects)
