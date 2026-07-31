# test_app.py: Unit tests for the Flask application
# This file contains tests to verify application functionality,
# including route responses and configuration.

import pytest
from app import create_app

@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app = create_app('testing')
    with app.test_client() as client:
        yield client

def test_root_redirects_to_login(client):
    """The application root redirects anonymous users to authentication."""
    response = client.get('/')
    assert response.status_code == 302
    assert '/auth/login' in response.headers['Location']

def test_config():
    """Test that the app loads the correct configuration."""
    app = create_app('testing')
    assert app.config['DEBUG']
    assert app.config['SECRET_KEY'] is not None
