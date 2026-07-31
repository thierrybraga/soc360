
from airflow import DAG
from airflow.models import Variable
from airflow.providers.http.operators.http import SimpleHttpOperator
from airflow.providers.http.sensors.http import HttpSensor
from airflow.operators.trigger_dagrun import TriggerDagRunOperator
from airflow.utils.dates import days_ago
from datetime import timedelta
import json

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

# DAG para sincronização diária da EUVD
with DAG(
    'euvd_sync_daily',
    default_args=default_args,
    description='Sincronização diária da European Vulnerability Database',
    schedule_interval=None,  # Disparado pela DAG do NVD
    start_date=days_ago(1),
    catchup=False,
    tags=['euvd', 'security', 'daily'],
) as dag_daily:

    check_api = HttpSensor(
        task_id='check_api_health',
        http_conn_id=API_CONN_ID,
        endpoint='health',
        method='GET',
        response_check=lambda response: response.status_code == 200,
        poke_interval=30,
        timeout=120,
    )

    trigger_sync = SimpleHttpOperator(
        task_id='trigger_euvd_sync',
        http_conn_id=API_CONN_ID,
        endpoint='api/euvd/sync/latest',
        method='POST',
        headers={"Content-Type": "application/json"},
        response_check=lambda response: response.status_code in [200, 202],
        log_response=True,
    )

    trigger_mitre = TriggerDagRunOperator(
        task_id='trigger_mitre_enrichment',
        trigger_dag_id='mitre_enrichment_daily',
        wait_for_completion=False,
    )

    check_api >> trigger_sync >> trigger_mitre

# DAG para sincronização manual por range
with DAG(
    'euvd_sync_range',
    default_args=default_args,
    description='Sincronização manual da EUVD por data',
    schedule_interval=None,
    start_date=days_ago(1),
    tags=['euvd', 'security', 'manual'],
) as dag_range:

    trigger_range_sync = SimpleHttpOperator(
        task_id='trigger_range_sync',
        http_conn_id=API_CONN_ID,
        endpoint='api/euvd/sync/range',
        method='POST',
        headers={"Content-Type": "application/json"},
        data='{"from_date": "{{ dag_run.conf.get("from_date", (execution_date - macros.timedelta(days=7)).strftime("%Y-%m-%d")) }}", "to_date": "{{ dag_run.conf.get("to_date", execution_date.strftime("%Y-%m-%d")) }}"}',
        response_check=lambda response: response.status_code in [200, 202],
        log_response=True,
    )
