"""
Cisco Umbrella Report Models
SQLAlchemy ORM models for Umbrella integration.
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, ForeignKey, DateTime, Boolean, Index
from sqlalchemy.orm import relationship

from app.models.system.base_model import CoreModel
from app.extensions.db_types import JSONB


class UmbrellaOrganization(CoreModel):
    """Umbrella organization (tenant)."""
    __tablename__ = 'umbrella_organizations'

    organization_id = Column(Integer, unique=True, nullable=False, index=True)
    organization_name = Column(String(255), nullable=False)
    status = Column(String(50), default='active')

    networks = relationship('UmbrellaNetwork', backref='organization', lazy='dynamic',
                            cascade='all, delete-orphan')
    roaming_computers = relationship('UmbrellaRoamingComputer', backref='organization', lazy='dynamic',
                                     cascade='all, delete-orphan')
    virtual_appliances = relationship('UmbrellaVirtualAppliance', backref='organization', lazy='dynamic',
                                      cascade='all, delete-orphan')
    reports = relationship('UmbrellaGeneratedReport', backref='organization', lazy='dynamic',
                           cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'organization_name': self.organization_name,
            'status': self.status,
            'network_count': self.networks.count(),
            'active_networks': self.networks.filter_by(status='active').count(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class UmbrellaNetwork(CoreModel):
    """Network deployment in Umbrella."""
    __tablename__ = 'umbrella_networks'

    organization_id = Column(Integer, ForeignKey('umbrella_organizations.organization_id'), nullable=False, index=True)
    network_id = Column(Integer, nullable=True)
    name = Column(String(255))
    ip_address = Column(String(64))
    status = Column(String(50))
    is_dynamic = Column(Boolean, default=False)
    primary_policy = Column(String(255))

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'network_id': self.network_id,
            'name': self.name,
            'ip_address': self.ip_address,
            'status': self.status,
            'is_dynamic': self.is_dynamic,
            'primary_policy': self.primary_policy,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class UmbrellaRoamingComputer(CoreModel):
    """Roaming computer (agent) in Umbrella."""
    __tablename__ = 'umbrella_roaming_computers'

    organization_id = Column(Integer, ForeignKey('umbrella_organizations.organization_id'), nullable=False, index=True)
    device_id = Column(String(128))
    name = Column(String(255))
    status = Column(String(50))
    last_sync = Column(DateTime, nullable=True)
    os_version = Column(String(128))

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'device_id': self.device_id,
            'name': self.name,
            'status': self.status,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'os_version': self.os_version,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class UmbrellaVirtualAppliance(CoreModel):
    """Virtual Appliance in Umbrella."""
    __tablename__ = 'umbrella_virtual_appliances'

    organization_id = Column(Integer, ForeignKey('umbrella_organizations.organization_id'), nullable=False, index=True)
    va_id = Column(String(128))
    name = Column(String(255))
    status = Column(String(50))
    ip_address = Column(String(64))

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'va_id': self.va_id,
            'name': self.name,
            'status': self.status,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class UmbrellaReportData(CoreModel):
    """Cached report data per organization and period."""
    __tablename__ = 'umbrella_report_data'

    organization_id = Column(Integer, ForeignKey('umbrella_organizations.organization_id'), nullable=False, index=True)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    data_type = Column(String(50), nullable=False)  # deployment, activity, security_categories, app_discovery, security_requests
    data_json = Column(JSONB, nullable=False)

    __table_args__ = (
        Index('ix_umbrella_report_data_org_period_type',
              'organization_id', 'period_start', 'period_end', 'data_type'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'period_start': self.period_start.isoformat() if self.period_start else None,
            'period_end': self.period_end.isoformat() if self.period_end else None,
            'data_type': self.data_type,
            'data_json': self.data_json,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class UmbrellaGeneratedReport(CoreModel):
    """Generated report file (DOCX/PDF)."""
    __tablename__ = 'umbrella_generated_reports'

    organization_id = Column(Integer, ForeignKey('umbrella_organizations.organization_id'), nullable=False, index=True)
    organization_name = Column(String(255), nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    file_path = Column(Text)
    docx_filename = Column(String(255))
    pdf_filename = Column(String(255))
    status = Column(String(50), default='pending')  # pending, completed, docx_only, failed

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'organization_name': self.organization_name,
            'period_start': self.period_start.strftime('%Y-%m-%d') if self.period_start else None,
            'period_end': self.period_end.strftime('%Y-%m-%d') if self.period_end else None,
            'file_path': self.file_path,
            'docx_filename': self.docx_filename,
            'pdf_filename': self.pdf_filename,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
