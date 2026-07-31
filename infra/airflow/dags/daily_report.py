"""
DAG para Geração de Relatórios Diários.
Gera um relatório executivo automático.
"""
from datetime import datetime, timedelta
import json
from airflow import DAG
from airflow.models import Variable
from airflow.providers.http.operators.http import SimpleHttpOperator
from airflow.utils.dates import days_ago

# Configurações via Variáveis do Airflow (com defaults)
API_CONN_ID = Variable.get("open_monitor_api_conn_id", default_var="open_monitor_api")
ADMIN_EMAIL = Variable.get("admin_email", default_var="admin@openmonitor.local")

default_args = {
    'owner': 'open-monitor',
    'depends_on_past': False,
    'email': [ADMIN_EMAIL],
    'retries': 1,
}

with DAG(
    'generate_daily_report',
    default_args=default_args,
    description='Gera relatório executivo diário',
    schedule_interval='0 6 * * *',  # Todo dia às 06:00 AM
    start_date=days_ago(1),
    tags=['report', 'daily'],
) as dag:

    trigger_report = SimpleHttpOperator(
        task_id='trigger_executive_report',
        http_conn_id=API_CONN_ID,
        endpoint='api/reports',
        method='POST',
        headers={"Content-Type": "application/json"},
        data='{"title": "Daily Executive Report - {{ ds }}", "type": "EXECUTIVE", "filters": {"time_range_days": 1}}',
        response_check=lambda response: response.status_code in [200, 201, 202],
        log_response=True,
    )
