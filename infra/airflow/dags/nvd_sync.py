"""
DAG de Sincronização NVD do Open-Monitor.
Suporta sincronização incremental (diária) e full (semanal).
"""
from datetime import datetime, timedelta
import json
from airflow import DAG
from airflow.models import Variable
from airflow.providers.http.operators.http import SimpleHttpOperator
from airflow.providers.http.sensors.http import HttpSensor
from airflow.operators.trigger_dagrun import TriggerDagRunOperator
from airflow.utils.dates import days_ago

# Configurações via Variáveis do Airflow (com defaults)
API_CONN_ID = Variable.get("open_monitor_api_conn_id", default_var="open_monitor_api")
ADMIN_EMAIL = Variable.get("admin_email", default_var="admin@openmonitor.local")

default_args = {
    'owner': 'open-monitor',
    'depends_on_past': False,
    'email': [ADMIN_EMAIL],
    'email_on_failure': True,
    'email_on_retry': False,
    'retries': 3,
    'retry_delay': timedelta(minutes=5),
}

# DAG para sincronização incremental (Diária)
with DAG(
    'nvd_sync_incremental',
    default_args=default_args,
    description='Sincronização incremental diária do NVD',
    schedule_interval='0 4 * * *',  # Todo dia às 04:00 AM
    start_date=days_ago(1),
    catchup=False,
    tags=['nvd', 'security', 'daily'],
) as dag_incremental:

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
        task_id='trigger_incremental_sync',
        http_conn_id=API_CONN_ID,
        endpoint='nvd/api/sync/start',
        method='POST',
        headers={"Content-Type": "application/json"},
        data=json.dumps({"mode": "incremental"}),
        response_check=lambda response: response.status_code in [200, 202, 409],
        log_response=True,
    )

    trigger_euvd = TriggerDagRunOperator(
        task_id='trigger_euvd_sync',
        trigger_dag_id='euvd_sync_daily',
        wait_for_completion=False,  # Não trava a DAG do NVD
    )

    check_api >> trigger_sync >> trigger_euvd

# DAG para sincronização completa (Semanal)
with DAG(
    'nvd_sync_full',
    default_args=default_args,
    description='Sincronização completa semanal do NVD',
    schedule_interval='0 2 * * 0',  # Todo domingo às 02:00 AM
    start_date=days_ago(7),
    catchup=False,
    tags=['nvd', 'security', 'weekly'],
) as dag_full:

    check_api_full = HttpSensor(
        task_id='check_api_health',
        http_conn_id=API_CONN_ID,
        endpoint='health',
        method='GET',
        response_check=lambda response: response.status_code == 200,
        poke_interval=30,
        timeout=120,
    )

    trigger_sync_full = SimpleHttpOperator(
        task_id='trigger_full_sync',
        http_conn_id=API_CONN_ID,
        endpoint='nvd/api/sync/start',
        method='POST',
        headers={"Content-Type": "application/json"},
        data=json.dumps({"mode": "full"}),
        response_check=lambda response: response.status_code in [200, 202, 409],
        log_response=True,
    )

    trigger_euvd_full = TriggerDagRunOperator(
        task_id='trigger_euvd_sync_after_full',
        trigger_dag_id='euvd_sync_daily', # Pode usar a mesma DAG de EUVD ou uma específica full
        wait_for_completion=False,
    )

    check_api_full >> trigger_sync_full >> trigger_euvd_full
