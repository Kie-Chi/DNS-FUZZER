"""Interface for analyze module integration."""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AnalyzeInterface(ABC):
    """Abstract interface for analyze module integration."""
    
    @abstractmethod
    async def wait_for_signal(self, timeout: float = 1.0) -> bool:
        """
        Wait for analyze signal.
        
        Args:
            timeout: Maximum time to wait for signal in seconds
            
        Returns:
            True if signal received, False if timeout
        """
        pass
    
    @abstractmethod
    async def send_iteration_data(self, iteration_data: Dict[str, Any]) -> None:
        """
        Send iteration data to analyze module.
        
        Args:
            iteration_data: Data from completed iteration
        """
        pass
    
    @abstractmethod
    async def connect(self) -> bool:
        """
        Connect to analyze module.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from analyze module."""
        pass


class MockAnalyzeInterface(AnalyzeInterface):
    """Mock implementation for development and testing."""
    
    def __init__(self, simulate_delay: float = 1.0):
        """
        Initialize mock analyze interface.
        
        Args:
            simulate_delay: Delay to simulate analyze processing time
        """
        self.simulate_delay = simulate_delay
        self.connected = False
    
    async def wait_for_signal(self, timeout: float = 1.0) -> bool:
        """Simulate waiting for analyze signal with a delay."""
        try:
            await asyncio.sleep(min(self.simulate_delay, timeout))
            logger.debug(f"Mock analyze signal received after {self.simulate_delay}s")
            return True
        except asyncio.TimeoutError:
            logger.warning(f"Mock analyze signal timeout after {timeout}s")
            return False
    
    async def send_iteration_data(self, iteration_data: Dict[str, Any]) -> None:
        """Mock sending iteration data."""
        logger.debug(f"Mock sending iteration data: iteration={iteration_data.get('iteration', 'unknown')}")
        # Simulate some processing time
        await asyncio.sleep(0.1)
    
    async def connect(self) -> bool:
        """Mock connection to analyze module."""
        logger.info("Mock connecting to analyze module")
        await asyncio.sleep(0.1)  # Simulate connection time
        self.connected = True
        return True
    
    async def disconnect(self) -> None:
        """Mock disconnection from analyze module."""
        logger.info("Mock disconnecting from analyze module")
        self.connected = False


class HTTPAnalyzeInterface(AnalyzeInterface):
    """HTTP-based analyze interface for future API integration."""
    
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        """
        Initialize HTTP analyze interface.
        
        Args:
            base_url: Base URL of analyze API
            api_key: Optional API key for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = None
        self.connected = False
    
    async def wait_for_signal(self, timeout: float = 1.0) -> bool:
        """
        Wait for analyze signal via HTTP polling or WebSocket.
        
        TODO: Implement actual HTTP/WebSocket communication
        """
        # Placeholder implementation
        logger.warning("HTTPAnalyzeInterface.wait_for_signal not yet implemented")
        await asyncio.sleep(timeout)
        return True
    
    async def send_iteration_data(self, iteration_data: Dict[str, Any]) -> None:
        """
        Send iteration data via HTTP POST.
        
        TODO: Implement actual HTTP request
        """
        # Placeholder implementation
        logger.warning("HTTPAnalyzeInterface.send_iteration_data not yet implemented")
        logger.debug(f"Would send iteration data to {self.base_url}/iteration")
    
    async def connect(self) -> bool:
        """
        Connect to analyze API.
        
        TODO: Implement actual HTTP session setup
        """
        # Placeholder implementation
        logger.warning("HTTPAnalyzeInterface.connect not yet implemented")
        logger.info(f"Would connect to analyze API at {self.base_url}")
        self.connected = True
        return True
    
    async def disconnect(self) -> None:
        """
        Disconnect from analyze API.
        
        TODO: Implement actual session cleanup
        """
        # Placeholder implementation
        logger.info("Would disconnect from analyze API")
        self.connected = False


def create_analyze_interface(interface_type: str = "mock", **kwargs) -> AnalyzeInterface:
    """
    Factory function to create analyze interface instances.
    
    Args:
        interface_type: Type of interface ("mock" or "http")
        **kwargs: Additional arguments for interface initialization
        
    Returns:
        AnalyzeInterface instance
    """
    if interface_type == "mock":
        return MockAnalyzeInterface(**kwargs)
    elif interface_type == "http":
        return HTTPAnalyzeInterface(**kwargs)
    else:
        raise ValueError(f"Unknown interface type: {interface_type}")