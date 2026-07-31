# tests/unit/test_api_endpoints.py
"""
Unit tests for API endpoints.
Tests authentication, validation, and basic functionality.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from app import create_app
from app.extensions import db
from app.models.nvd import Vulnerability
from app.models.inventory import Asset
from app.models.auth import User


@pytest.fixture
def client():
    """Create test client with test database."""
    app = create_app('testing')

    with app.app_context():
        db.create_all()
        # Create test user with API key
        test_user = User(
            username='testuser',
            email='test@example.com',
            password='hashed_password',
            api_key='test-api-key-12345',
            is_active=True
        )
        db.session.add(test_user)
        db.session.commit()

    with app.test_client() as client:
        yield client


def _get_auth_headers():
    """Get headers with API key for authenticated requests."""
    return {'X-API-Key': 'test-api-key-12345'}


class TestAPIV1Endpoints:
    """Test API v1 endpoints."""

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get('/api/v1/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['service'] == 'api_v1'

    def test_get_cves_unauthenticated(self, client):
        """Test CVE listing without authentication."""
        response = client.get('/api/v1/cves')
        # Should work without auth for now
        assert response.status_code == 200

    def test_get_cves_with_pagination(self, client):
        """Test CVE listing with pagination parameters."""
        response = client.get('/api/v1/cves?page=1&per_page=10')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'data' in data
        assert 'meta' in data
        assert data['meta']['page'] == 1
        assert data['meta']['per_page'] == 10

    def test_get_cves_with_filters(self, client):
        """Test CVE listing with severity filter."""
        response = client.get('/api/v1/cves?severity=HIGH')
        assert response.status_code == 200

    @patch('app.controllers.api.api_controller.Vulnerability.query')
    def test_get_cve_detail(self, mock_query, client):
        """Test getting specific CVE details."""
        # Mock CVE object
        mock_cve = MagicMock()
        mock_cve.to_dict.return_value = {
            'cve_id': 'CVE-2023-12345',
            'description': 'Test vulnerability'
        }
        mock_query.filter_by.return_value.first.return_value = mock_cve

        response = client.get('/api/v1/cves/CVE-2023-12345')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['cve_id'] == 'CVE-2023-12345'

    def test_get_cve_not_found(self, client):
        """Test getting non-existent CVE."""
        response = client.get('/api/v1/cves/CVE-9999-99999')
        assert response.status_code == 404

    def test_create_asset_unauthenticated(self, client):
        """Test asset creation requires authentication."""
        asset_data = {
            'name': 'Test Server',
            'ip_address': '192.168.1.100'
        }
        response = client.post(
            '/api/v1/assets',
            data=json.dumps(asset_data),
            content_type='application/json'
        )
        assert response.status_code == 401

    def test_create_asset_authenticated(self, client):
        """Test creating asset with authentication."""
        asset_data = {
            'name': 'Test Server',
            'ip_address': '192.168.1.100'
        }
        response = client.post(
            '/api/v1/assets',
            data=json.dumps(asset_data),
            content_type='application/json',
            headers=_get_auth_headers()
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['name'] == 'Test Server'
        assert data['ip_address'] == '192.168.1.100'

    def test_create_asset_invalid_data(self, client):
        """Test creating asset with invalid data."""
        asset_data = {
            'name': '',  # Invalid: empty name
            'ip_address': 'invalid-ip'
        }
        response = client.post(
            '/api/v1/assets',
            data=json.dumps(asset_data),
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_create_asset_missing_fields(self, client):
        """Test creating asset with missing required fields."""
        asset_data = {'name': 'Test Server'}  # Missing ip_address
        response = client.post(
            '/api/v1/assets',
            data=json.dumps(asset_data),
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_create_ticket_valid(self, client):
        """Test creating support ticket."""
        ticket_data = {
            'title': 'Test Issue',
            'description': 'Test description',
            'priority': 'high'
        }
        response = client.post(
            '/api/v1/tickets',
            data=json.dumps(ticket_data),
            content_type='application/json'
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'ticket' in data

    def test_create_ticket_invalid(self, client):
        """Test creating ticket with invalid data."""
        ticket_data = {
            'title': '',  # Invalid: empty title
            'description': 'Test',
            'priority': 'high'
        }
        response = client.post(
            '/api/v1/tickets',
            data=json.dumps(ticket_data),
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_start_mitigation_valid(self, client):
        """Test starting mitigation for valid CVE."""
        mitigation_data = {
            'action': 'start_mitigation',
            'user_id': 1
        }

        # Mock vulnerability exists
        with patch('controllers.api_controller.Vulnerability.query') as mock_query:
            mock_vuln = MagicMock()
            mock_query.filter_by.return_value.first.return_value = mock_vuln

            response = client.post(
                '/api/v1/vulnerabilities/CVE-2023-12345/mitigate',
                data=json.dumps(mitigation_data),
                content_type='application/json'
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True

    def test_start_mitigation_invalid_cve(self, client):
        """Test starting mitigation for non-existent CVE."""
        mitigation_data = {
            'action': 'start_mitigation',
            'user_id': 1
        }
        response = client.post(
            '/api/v1/vulnerabilities/CVE-9999-99999/mitigate',
            data=json.dumps(mitigation_data),
            content_type='application/json'
        )
        assert response.status_code == 404


class TestVulnerabilityAPIEndpoints:
    """Test vulnerability-specific API endpoints."""

    @patch('controllers.vulnerability_controller.Vulnerability.query')
    def test_get_vulnerabilities_api(self, mock_query, client):
        """Test getting vulnerabilities via API."""
        mock_vulns = [MagicMock(), MagicMock()]
        mock_vulns[0].to_dict.return_value = {'cve_id': 'CVE-2023-0001'}
        mock_vulns[1].to_dict.return_value = {'cve_id': 'CVE-2023-0002'}

        mock_query.all.return_value = mock_vulns

        response = client.get('/api/v1/vulnerabilities')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) == 2

    @patch('controllers.vulnerability_controller.Vulnerability.query')
    def test_get_vulnerability_detail_api(self, mock_query, client):
        """Test getting specific vulnerability details via API."""
        mock_vuln = MagicMock()
        mock_vuln.to_dict.return_value = {
            'cve_id': 'CVE-2023-12345',
            'description': 'Test vulnerability'
        }
        mock_query.filter_by.return_value.first.return_value = mock_vuln

        response = client.get('/api/v1/vulnerabilities/CVE-2023-12345')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['cve_id'] == 'CVE-2023-12345'

    @patch('controllers.vulnerability_controller.Vulnerability.query')
    def test_update_vulnerability_api(self, mock_query, client):
        """Test updating vulnerability via API."""
        mock_vuln = MagicMock()
        mock_query.filter_by.return_value.first.return_value = mock_vuln

        update_data = {'status': 'mitigated'}
        response = client.patch(
            '/api/v1/vulnerabilities/CVE-2023-12345',
            data=json.dumps(update_data),
            content_type='application/json'
        )
        assert response.status_code == 200

    @patch('controllers.vulnerability_controller.Vulnerability.query')
    def test_delete_vulnerability_api(self, mock_query, client):
        """Test deleting vulnerability via API."""
        mock_vuln = MagicMock()
        mock_query.filter_by.return_value.first.return_value = mock_vuln

        response = client.delete('/api/v1/vulnerabilities/CVE-2023-12345')
        assert response.status_code == 200


class TestAnalyticsAPIEndpoints:
    """Test analytics API endpoints."""

    def test_analytics_overview(self, client):
        """Test analytics overview endpoint."""
        response = client.get('/api/v1/analytics/overview')
        assert response.status_code == 200

    def test_analytics_details(self, client):
        """Test analytics details endpoint."""
        response = client.get('/api/v1/analytics/details/vulnerabilities')
        assert response.status_code == 200

    def test_analytics_timeseries(self, client):
        """Test analytics timeseries endpoint."""
        response = client.get('/api/v1/analytics/timeseries/cve_count')
        assert response.status_code == 200

    def test_analytics_severity_distribution(self, client):
        """Test severity distribution endpoint."""
        response = client.get('/api/v1/analytics/severity-distribution')
        assert response.status_code == 200

    def test_analytics_patch_status(self, client):
        """Test patch status endpoint."""
        response = client.get('/api/v1/analytics/patch-status')
        assert response.status_code == 200

    def test_analytics_query(self, client):
        """Test analytics query endpoint."""
        query_data = {
            'query': 'SELECT COUNT(*) FROM vulnerabilities',
            'format': 'json'
        }
        response = client.post(
            '/api/v1/analytics/query',
            data=json.dumps(query_data),
            content_type='application/json',
            headers=_get_auth_headers()
        )
        assert response.status_code == 200


class TestSecurityAndRateLimiting:
    """Test security features and rate limiting."""

    def test_unauthenticated_api_access(self, client):
        """Test that protected endpoints require authentication."""
        protected_endpoints = [
            ('/api/v1/risk/CVE-2023-TEST01', 'GET'),
            ('/api/v1/assets', 'GET'),
            ('/api/v1/tickets', 'POST'),
            ('/api/v1/vulnerabilities/CVE-2023-TEST01/mitigate', 'POST'),
            ('/api/v1/analytics/overview', 'GET')
        ]

        for endpoint, method in protected_endpoints:
            if method == 'GET':
                response = client.get(endpoint)
            else:
                response = client.post(endpoint)
            assert response.status_code == 401, f"Endpoint {endpoint} should require authentication"

    def test_authenticated_api_access(self, client):
        """Test that authenticated requests work."""
        response = client.get('/api/v1/assets', headers=_get_auth_headers())
        assert response.status_code == 200

    def test_invalid_api_key(self, client):
        """Test invalid API key is rejected."""
        headers = {'X-API-Key': 'invalid-key'}
        response = client.get('/api/v1/assets', headers=headers)
        assert response.status_code == 401

    def test_health_check_public(self, client):
        """Test health check is publicly accessible."""
        response = client.get('/api/v1/health')
        assert response.status_code == 200

    def test_cve_data_public(self, client):
        """Test CVE data is publicly accessible with rate limiting."""
        response = client.get('/api/v1/cves')
        assert response.status_code == 200


class TestChatbotAPIEndpoints:
    """Test chatbot API endpoints."""

    def test_chat_endpoint(self, client):
        """Test chatbot chat endpoint."""
        chat_data = {
            'message': 'What is CVE-2023-12345?',
            'session_id': 'test-session'
        }
        response = client.post(
            '/chatbot/chat',
            data=json.dumps(chat_data),
            content_type='application/json'
        )
        assert response.status_code == 200

    def test_get_session(self, client):
        """Test getting chat session."""
        response = client.get('/chatbot/session/test-session')
        assert response.status_code == 200

    def test_clear_session(self, client):
        """Test clearing chat session."""
        response = client.post('/chatbot/session/test-session/clear')
        assert response.status_code == 200

    def test_cve_info(self, client):
        """Test getting CVE info via chatbot."""
        response = client.get('/chatbot/cve/CVE-2023-12345')
        assert response.status_code == 200

    def test_trending_cves(self, client):
        """Test getting trending CVEs."""
        response = client.get('/chatbot/trending')
        assert response.status_code == 200

    def test_chatbot_health(self, client):
        """Test chatbot health check."""
        response = client.get('/chatbot/health')
        assert response.status_code == 200
