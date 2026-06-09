"""
Report generation job helpers.
"""
import logging
import threading

from flask import current_app

from app.extensions import db
from app.models.monitoring import Report
from app.models.system import ReportStatus


logger = logging.getLogger(__name__)


def _run_report_generation(report_id, flask_app):
    """Executa a geração dentro de um contexto Flask proprio."""
    with flask_app.app_context():
        from app.controllers.reports.reports_controller import _generate_report_data

        report = db.session.get(Report, report_id)
        if not report:
            logger.warning("Report generation skipped: report %s not found", report_id)
            return

        if report.status != ReportStatus.GENERATING.value:
            report.start_generation()

        _generate_report_data(report)


def trigger_report_generation(report_id, async_mode=None):
    """
    Dispara geração de relatório.

    Usa thread local quando Celery não está disponível. Em TESTING roda
    sincronamente para manter os testes determinísticos.
    """
    flask_app = current_app._get_current_object()
    if async_mode is None:
        async_mode = not flask_app.config.get('TESTING', False)

    if async_mode:
        thread = threading.Thread(
            target=_run_report_generation,
            args=(report_id, flask_app),
            name=f'report-generation-{report_id}',
            daemon=True,
        )
        thread.start()
        return True

    _run_report_generation(report_id, flask_app)
    return True
