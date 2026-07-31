# tests/integration/test_api_integration.py
"""
Integration tests for API endpoints.
Tests full request/response cycles with database interactions.
"""

import pytest
import json
from app import create_app
from app.extensions import db
from app.models.nvd import Vulnerability
from app.models.inventory import Asset
from app.models.auth import User
from app.models.monitoring import MonitoringRule
from datetime import datetime


@pytest.fixture
def client():
    """Create test client with test database."""
    app = create_app('testing')

    with app.app_context():
        db.create_all()

        # Create test data
        test_user = User(
            username='testuser',
            email='test@example.com',
            password='hashed_password'
        )
        db.session.add(test_user)

        # Create test vulnerability
        test_vuln = Vulnerability(
            cve_id='CVE-2023-TEST01',
            description='Test vulnerability for integration tests',
            base_severity='HIGH',
            published_date=datetime.utcnow()
        )
        db.session.add(test_vuln)

        # Create test asset
        test_asset = Asset(
            name='Test Server',
            ip_address='192.168.1.100',
            owner_id=1
        )
        db.session.add(test_asset)

        db.session.commit()

    with app.test_client() as client:
        yield client


class TestAPIIntegration:
    """Integration tests for API functionality."""

    def test_full_cve_workflow(self, client):
        """Test complete CVE retrieval workflow."""
        # Get CVEs list
        response = client.get('/api/v1/cves')
        assert response.status_code == 200
        cves_data = json.loads(response.data)
        assert 'data' in cves_data
        assert 'meta' in cves_data

        # Get specific CVE
        response = client.get('/api/v1/cves/CVE-2023-TEST01')
        assert response.status_code == 200
        cve_data = json.loads(response.data)
        assert cve_data['cve_id'] == 'CVE-2023-TEST01'

        # Test vulnerabilities alias
        response = client.get('/api/v1/vulnerabilities')
        assert response.status_code == 200

    def test_asset_crud_operations(self, client):
        """Test complete asset CRUD operations."""
        # Create asset
        asset_data = {
            'name': 'Integration Test Server',
            'ip_address': '10.0.0.50'
        }
        response = client.post(
            '/api/v1/assets',
            data=json.dumps(asset_data),
            content_type='application/json'
        )
        assert response.status_code == 201
        created_asset = json.loads(response.data)
        assert created_asset['name'] == 'Integration Test Server'

        # List assets
        response = client.get('/api/v1/assets')
        assert response.status_code == 200
        assets_data = json.loads(response.data)
        assert len(assets_data['data']) >= 1

    def test_risk_assessment_workflow(self, client):
        """Test risk assessment creation and retrieval."""
        # Create risk assessment
        risk_data = {
            'cve_id': 'CVE-2023-TEST01',
            'score': 8.5,
            'details': 'High risk due to exposure'
        }
        response = client.post(
            '/api/v1/risk',
            data=json.dumps(risk_data),
            content_type='application/json'
        )
        assert response.status_code == 201

        # Retrieve risk assessment
        response = client.get('/api/v1/risk/CVE-2023-TEST01')
        assert response.status_code == 200
        risk_data = json.loads(response.data)
        assert risk_data['score'] == 8.5

    def test_ticket_creation_workflow(self, client):
        """Test support ticket creation."""
        ticket_data = {
            'title': 'Integration Test Ticket',
            'description': 'Testing ticket creation workflow',
            'priority': 'medium',
            'cve_id': 'CVE-2023-TEST01'
        }
        response = client.post(
            '/api/v1/tickets',
            data=json.dumps(ticket_data),
            content_type='application/json'
        )
        assert response.status_code == 201
        ticket_response = json.loads(response.data)
        assert ticket_response['success'] is True
        assert 'ticket' in ticket_response

    def test_mitigation_workflow(self, client):
        """Test mitigation initiation workflow."""
        mitigation_data = {
            'action': 'start_mitigation',
            'user_id': 1
        }
        response = client.post(
            '/api/v1/vulnerabilities/CVE-2023-TEST01/mitigate',
            data=json.dumps(mitigation_data),
            content_type='application/json'
        )
        assert response.status_code == 200
        mitigation_response = json.loads(response.data)
        assert mitigation_response['success'] is True

    def test_error_handling(self, client):
        """Test error handling for invalid requests."""
        # Test invalid JSON
        response = client.post(
            '/api/v1/assets',
            data='invalid json',
            content_type='application/json'
        )
        assert response.status_code == 400

        # Test non-existent CVE
        response = client.get('/api/v1/cves/CVE-9999-99999')
        assert response.status_code == 404

        # Test invalid asset creation
        asset_data = {'name': '', 'ip_address': 'invalid'}
        response = client.post(
            '/api/v1/assets',
            data=json.dumps(asset_data),
            content_type='application/json'
        )
        assert response.status_code == 400


class TestAnalyticsIntegration:
    """Integration tests for analytics endpoints."""

    def test_analytics_endpoints_accessible(self, client):
        """Test that analytics endpoints are accessible."""
        endpoints = [
            '/api/v1/analytics/overview',
            '/api/v1/analytics/severity-distribution',
            '/api/v1/analytics/patch-status'
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == 200

    def test_analytics_query_execution(self, client):
        """Test analytics query execution."""
        query_data = {
            'query': 'SELECT COUNT(*) as count FROM vulnerabilities',
            'format': 'json'
        }
        response = client.post(
            '/api/v1/analytics/query',
            data=json.dumps(query_data),
            content_type='application/json'
        )
        assert response.status_code == 200


class TestChatbotIntegration:
    """Integration tests for chatbot endpoints."""

    def test_chatbot_endpoints_accessible(self, client):
        """Test that chatbot endpoints are accessible."""
        # Health check
        response = client.get('/chatbot/health')
        assert response.status_code == 200

        # Trending CVEs
        response = client.get('/chatbot/trending')
        assert response.status_code == 200

    def test_chat_interaction(self, client):
        """Test basic chat interaction."""
        chat_data = {
            'message': 'Hello, what can you tell me about vulnerabilities?',
            'session_id': 'integration-test-session'
        }
        response = client.post(
            '/chatbot/chat',
            data=json.dumps(chat_data),
            content_type='application/json'
        )
        assert response.status_code == 200

    def test_session_management(self, client):
        """Test chat session management."""
        # Get session
        response = client.get('/chatbot/session/integration-test-session')
        assert response.status_code == 200

        # Clear session
        response = client.post('/chatbot/session/integration-test-session/clear')
        assert response.status_code == 200


class TestPaginationAndFiltering:
    """Test pagination and filtering functionality."""

    def test_pagination_parameters(self, client):
        """Test pagination parameter handling."""
        response = client.get('/api/v1/cves?page=2&per_page=5')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['meta']['page'] == 2
        assert data['meta']['per_page'] == 5

    def test_filtering_by_severity(self, client):
        """Test filtering by severity."""
        response = client.get('/api/v1/cves?severity=HIGH')
        assert response.status_code == 200
        # Note: Actual filtering depends on data, but endpoint should work

    def test_invalid_pagination(self, client):
        """Test invalid pagination parameters."""
        response = client.get('/api/v1/cves?page=-1&per_page=0')
        # Should handle gracefully, possibly with defaults
        assert response.status_code == 200
