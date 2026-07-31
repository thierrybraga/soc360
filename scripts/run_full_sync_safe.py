#!/usr/bin/env python3
"""
Script seguro para executar sincronização full da NVD.
Importa todos os modelos necessários antes de criar as tabelas.
"""
import os
import sys
import logging

from dotenv import load_dotenv
from sqlalchemy import text

# =========================
# FIX PATH
# =========================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# =========================
# LOAD ENV
# =========================
load_dotenv()

# =========================
# LOGGING
# =========================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("nvd_sync")

# =========================
# MAIN
# =========================

def main():
    # Importar a aplicação primeiro
    from app import create_app
    from app.extensions import db
    
    app = create_app()
    
    with app.app_context():
        logger.info("=== STARTING FULL NVD SYNC ===")
        
        # 1. Importar TODOS os modelos antes de criar tabelas
        # Isso garante que todas as tabelas sejam registradas no metadata
        logger.info("Importing all models...")
        
        # System models
        from app.models.system import (
            SyncMetadata, ChatSession, ChatMessage,
        )
        
        # Auth models
        from app.models.auth import User, Role, UserRole
        
        # MITRE models
        from app.models.mitre import Tactic, Technique, AttackMitigation
        
        # NVD models - VULNERABILITY PRIMEIRO
        from app.models.nvd.vulnerability import Vulnerability
        from app.models.nvd import (
            CvssMetric, Weakness, Reference, Mitigation,
            CVEProduct, CVEVendor, ReferenceTypeModel, VersionReference
        )
        
        # Inventory models
        from app.models.inventory import Asset, AssetVulnerability, Vendor, Product, AssetCategory
        
        # Monitoring models
        from app.models.monitoring import MonitoringRule, Alert, Report, RiskAssessment, ApiCallLog
        
        # Wazuh models
        from app.models.wazuh import WazuhAlert, WazuhTreatmentNote
        
        # Umbrella models
        from app.models.umbrella import (
            UmbrellaOrganization, UmbrellaNetwork, UmbrellaRoamingComputer,
            UmbrellaVirtualAppliance, UmbrellaReportData, UmbrellaGeneratedReport
        )
        
        # D3FEND models - DEPOIS de Vulnerability
        from app.models.d3fend import (
            D3fendTechnique, D3fendArtifact, D3fendTactic,
            D3fendOffensiveMapping, CveD3fendCorrelation
        )
        
        logger.info("All models imported successfully.")
        
        # 2. Verificar conexão com banco
        try:
            engine = db.engine
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Database connection OK")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return 1
        
        # 3. Criar todas as tabelas
        logger.info("Creating database tables...")
        try:
            db.create_all()
            logger.info("Tables created successfully.")
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
            import traceback
            traceback.print_exc()
            return 1
        
        # 4. Executar o sync full pelo orquestrador central.
        # Isso reutiliza lock persistente, cancelamento, watermark correto,
        # deduplicacao e o mesmo fluxo usado pela UI/Celery.
        from app.services.nvd.nvd_sync_service import NVDSyncService, SyncMode

        service = NVDSyncService()
        started = service.start_sync(mode=SyncMode.FULL, async_mode=False)
        if not started:
            logger.error("NVD sync is already running")
            return 1

        logger.info("Full NVD sync finished with status: %s", service.get_progress().get('status'))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
