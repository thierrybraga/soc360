#!/usr/bin/env python3
"""
Executa sincronizacao incremental da NVD usando o orquestrador da aplicacao.
"""
import logging
import os
import sys

from dotenv import load_dotenv


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

os.chdir(BASE_DIR)
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("nvd_sync")


def main():
    from app import create_app
    from app.services.nvd.nvd_sync_service import NVDSyncService, SyncMode

    app = create_app()

    with app.app_context():
        logger.info("Starting incremental NVD sync")
        service = NVDSyncService()
        started = service.start_sync(mode=SyncMode.INCREMENTAL, async_mode=False)
        if not started:
            logger.error("NVD sync is already running")
            return 1
        logger.info("Incremental NVD sync finished with status: %s", service.get_progress().get('status'))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
