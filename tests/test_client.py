"""Basic tests for KPNBoxAPI client."""
import pytest
from kpnboxapi import KPNBoxClient
from kpnboxapi.exceptions import AuthenticationError, ConnectionError


def test_client_initialization():
    """Test that the client can be initialized with basic parameters."""
    client = KPNBoxClient()

def test_exceptions_import():
    """Test that custom exceptions can be imported."""
    # This just ensures our exceptions module is importable
    assert AuthenticationError is not None
    assert ConnectionError is not None


# Todo: Add more tests