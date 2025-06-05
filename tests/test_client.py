"""Basic tests for KPNBoxAPI client."""
import pytest
from unittest.mock import patch, MagicMock
from kpnboxapi import KPNBoxAPI
from kpnboxapi.exceptions import AuthenticationError, ConnectionError


def test_client_initialization():
    """Test that the client can be initialized with basic parameters."""
    # Test without actually connecting
    with patch('requests.Session'):
        client = KPNBoxAPI()
        assert client is not None


def test_client_initialization_with_host():
    """Test client initialization with custom host."""
    with patch('requests.Session'):
        client = KPNBoxAPI(host="192.168.1.1")
        assert client is not None


def test_exceptions_import():
    """Test that custom exceptions can be imported."""
    # This just ensures our exceptions module is importable
    assert AuthenticationError is not None
    assert ConnectionError is not None


@patch('requests.Session')
def test_client_methods_exist(mock_session):
    """Test that key client methods exist."""
    client = KPNBoxAPI()
    
    # Check that key methods exist (without calling them)
    assert hasattr(client, 'login') or hasattr(client, 'authenticate')
    assert hasattr(client, 'get_device_info') or hasattr(client, 'get_router_info')


# Todo: Add more comprehensive tests with proper mocking