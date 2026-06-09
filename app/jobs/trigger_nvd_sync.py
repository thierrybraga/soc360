import sys
if '/app' not in sys.path:
    sys.path.append('/app')

from app import create_app
from app.jobs import trigger_nvd_sync

app = create_app()

with app.app_context():
    print("Triggering NVD sync (incremental)...")
    started = trigger_nvd_sync(mode='incremental')
    if started:
        print("NVD sync triggered.")
    else:
        print("NVD sync was not triggered because another sync is running or dispatch failed.")
