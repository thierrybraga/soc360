#!/usr/bin/env python3
"""
Script para resetar status de sincronização que ficaram travados.
"""
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

os.chdir(BASE_DIR)

from app import create_app
from app.models.system import SyncMetadata

def reset_sync_status():
    app = create_app()
    
    with app.app_context():
        print("Resetando status de sincronização...")
        
        # Verificar EUVD (está como running mas provavelmente não está rodando)
        euvd_status = SyncMetadata.get('euvd_sync_progress_status')
        print(f"EUVD status atual: {euvd_status}")
        
        if euvd_status == 'running':
            SyncMetadata.set('euvd_sync_progress_status', 'idle')
            SyncMetadata.set('euvd_sync_progress_message', 'Resetado manualmente')
            print("✅ EUVD status resetado para 'idle'")
        
        # Verificar outros serviços
        services = ['nvd', 'mitre', 'mitre-attack', 'd3fend']
        for service in services:
            status_key = f'{service}_sync_progress_status'
            status = SyncMetadata.get(status_key)
            print(f"{service.upper()} status atual: {status}")
            
            if status == 'running':
                SyncMetadata.set(status_key, 'idle')
                SyncMetadata.set(f'{service}_sync_progress_message', 'Resetado manualmente')
                print(f"✅ {service.upper()} status resetado para 'idle'")

        SyncMetadata.delete('nvd_sync_lock')
        SyncMetadata.set('nvd_sync_cancel_requested', 'false')
        print("✅ Lock persistente da NVD limpo")
        
        print("\n✅ Todos os status verificados!")

if __name__ == "__main__":
    reset_sync_status()
