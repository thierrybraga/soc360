
from airflow import DAG
from airflow.models import Variable
from airflow.providers.http.operators.http import SimpleHttpOperator
from airflow.utils.dates import days_ago
from datetime import timedelta

# Configurações via Variáveis do Airflow (com defaults)
API_CONN_ID = Variable.get("open_monitor_api_conn_id", default_var="open_monitor_api")
ADMIN_EMAIL = Variable.get("admin_email", default_var="admin@openmonitor.local")

default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email': [ADMIN_EMAIL],
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 3,
    'retry_delay': timedelta(minutes=5),
}

# DAG para enriquecimento diário com dados da MITRE
with DAG(
    'mitre_enrichment_daily',
    default_args=default_args,
    description='Enriquecimento de vulnerabilidades com dados da MITRE',
    schedule_interval=None,  # Disparado pela DAG da EUVD
    start_date=days_ago(1),
    catchup=False,
    tags=['mitre', 'security', 'enrichment'],
) as dag:

    trigger_enrichment = SimpleHttpOperator(
        task_id='trigger_mitre_enrichment',
        http_conn_id=API_CONN_ID,
        endpoint='api/mitre/enrich?limit=500',
        method='POST',
        headers={"Content-Type": "application/json"},
        response_check=lambda response: response.status_code in [200, 202],
        log_response=True,
    )

    trigger_enrichment
