"""
DAG para Importação em Massa de CVEs.
Pode ser acionada manualmente com parâmetros de configuração.
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
    'nvd_bulk_import',
    default_args=default_args,
    description='Importação em massa de CVEs via arquivo JSON',
    schedule_interval=None,  # Apenas manual
    start_date=days_ago(1),
    tags=['nvd', 'maintenance', 'manual'],
) as dag:

    # Exemplo de conf: {"file_path": "/app/uploads/nvd_dump.json"}
    trigger_import = SimpleHttpOperator(
        task_id='trigger_bulk_import',
        http_conn_id=API_CONN_ID,
        endpoint='nvd/api/import/bulk',
        method='POST',
        headers={"Content-Type": "application/json"},
        # Pega o caminho do arquivo da configuração da run
        data='{"file_path": "{{ dag_run.conf.get("file_path", "/app/uploads/nvd_dump.json") }}"}',
        response_check=lambda response: response.status_code in [200, 202],
        log_response=True,
    )
