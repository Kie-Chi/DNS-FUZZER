"""DNS Fuzzer Client implementation."""

import asyncio
import socket
import time
import random
from typing import List, Dict, Any, Optional, AsyncGenerator
from pathlib import Path
import json
from dataclasses import asdict

from .config import ClientConfig
from ..core.query import DNSQuery, create_basic_query
from ..core.mutator import create_default_mutator
from ..utils.logger import get_logger

logger = get_logger(__name__)


class DNSFuzzerClient:
    """DNS fuzzer client for sending mutated queries to target servers."""
    
    def __init__(self, config: ClientConfig):
        """Initialize the DNS fuzzer client.
        
        Args:
            config: Client configuration
        """
        self.config = config
        self.mutator = create_default_mutator(config.random_seed)        
        self.results: List[Dict[str, Any]] = []
        self.stats = {
            'queries_sent': 0,
            'responses_received': 0,
            'timeouts': 0,
            'errors_encountered': 0,
            'mutations_applied': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Set random seed if provided
        if config.random_seed is not None:
            # Ensure the seed is a valid type for random.seed()
            if isinstance(config.random_seed, (int, float, str, bytes, bytearray)):
                random.seed(config.random_seed)
                logger.info(f"Set random seed to {config.random_seed}")
            else:
                logger.warning(f"Invalid random seed type: {type(config.random_seed)}, using default")
    
    def run_fuzzing(self) -> None:
        """Run the fuzzing process synchronously."""
        asyncio.run(self.start_fuzzing())
    
    async def start_fuzzing(self) -> None:
        logger.info("Starting DNS fuzzing client")
        logger.info(f"Target servers: {self.config.target_servers}")
        logger.info(f"Max iterations: {self.config.max_iterations}")
        logger.info(f"Concurrent requests: {self.config.concurrent_requests}")
        
        self.stats['start_time'] = time.time()
        
        # Create output directory
        output_path = Path(self.config.output_directory)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)
        
        # Generate and send queries
        tasks = []
        async for query_data in self._generate_queries():
            if len(tasks) >= self.config.max_iterations:
                break
                
            task = asyncio.create_task(
                self._send(semaphore, query_data)
            )
            tasks.append(task)
            
            # Add delay between request creation
            if self.config.delay_between_requests > 0:
                await asyncio.sleep(self.config.delay_between_requests)
        
        # Wait for all tasks to complete
        logger.info(f"Waiting for {len(tasks)} queries to complete")
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.stats['end_time'] = time.time()
        
        # Save results
        await self._save_results()
        
        # Print summary
        self._print_summary()
    
    async def _generate_queries(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Generate DNS queries for fuzzing."""
        iteration = 0
        
        while iteration < self.config.max_iterations:
            # Create base query
            base_query = create_basic_query(
                qname=self.config.default_query_name,
                qtype=self.config.default_query_type
            )
            base_query.qclass = self.config.default_query_class
            
            # Apply mutations
            try:
                mutated_query = self.mutator.mutate(base_query)
                
                # Check if mutation was actually applied
                if mutated_query != base_query:
                    self.stats['mutations_applied'] += 1
                
                # Select target server
                target_server = random.choice(self.config.target_servers)
                
                query_data = {
                    'iteration': iteration,
                    'target_server': target_server,
                    'target_port': self.config.target_port,
                    'original_query': base_query,
                    'mutated_query': mutated_query,
                    'timestamp': time.time()
                }
                
                yield query_data
                iteration += 1
                
            except Exception as e:
                logger.error(f"Error generating query {iteration}: {e}")
                iteration += 1
                continue
    
    async def _send(self, semaphore: asyncio.Semaphore, query_data: Dict[str, Any]) -> None:
        """Send a single query with semaphore control."""
        async with semaphore:
            await self._send_query(query_data)
    
    async def _send_query(self, query_data: Dict[str, Any]) -> None:
        """Send a single DNS query and record the result."""
        iteration = query_data['iteration']
        target_server = query_data['target_server']
        target_port = query_data['target_port']
        mutated_query = query_data['mutated_query']
        
        result = {
            'iteration': iteration,
            'target_server': target_server,
            'target_port': target_port,
            'timestamp': query_data['timestamp'],
            'query_sent': None,
            'response_received': None,
            'response_time': None,
            'error': None,
            'timeout': False
        }
        
        try:
            # Convert query to wire format
            query_bytes = mutated_query.to_wire()
            result['query_sent'] = len(query_bytes)
            
            # Send query and measure response time
            start_time = time.time()
            response_bytes = await self._send_udp_query(
                query_bytes, target_server, target_port
            )
            end_time = time.time()
            
            result['response_time'] = end_time - start_time
            result['response_received'] = len(response_bytes) if response_bytes else 0
            
            # Parse response if received
            if response_bytes:
                try:
                    response_query = DNSQuery.from_wire(response_bytes)
                    if self.config.save_responses:
                        result['response_data'] = self._serialize_query(response_query)
                except Exception as e:
                    logger.debug(f"Failed to parse response for iteration {iteration}: {e}")
                    result['parse_error'] = str(e)
            
            # Save packet data if requested
            if self.config.save_packets:
                result['query_packet'] = query_bytes.hex()
                if response_bytes:
                    result['response_packet'] = response_bytes.hex()
            
            self.stats['queries_sent'] += 1
            if response_bytes:
                self.stats['responses_received'] += 1
                
        except asyncio.TimeoutError:
            result['timeout'] = True
            result['error'] = 'Timeout'
            self.stats['timeouts'] += 1
            logger.debug(f"Timeout for query {iteration} to {target_server}")
            
        except Exception as e:
            result['error'] = str(e)
            self.stats['errors_encountered'] += 1
            logger.debug(f"Error sending query {iteration} to {target_server}: {e}")
        
        # Store result
        self.results.append(result)
        
        # Log progress
        if iteration % 100 == 0:
            logger.info(f"Completed {iteration} queries")
    
    async def _send_udp_query(self, query_bytes: bytes, server: str, port: int) -> Optional[bytes]:
        """Send UDP DNS query and return response using async operations."""
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, query_bytes, (server, port))
                response_data = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096),
                    timeout=self.config.timeout
                )
                return response_data
            finally:
                sock.close()
                
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError()
        except Exception as e:
            raise e
    
    def _serialize_query(self, query: DNSQuery) -> Dict[str, Any]:
        """Serialize DNSQuery to dictionary for JSON storage."""
        try:
            # Convert dataclass to dict, handling special types
            query_dict = asdict(query)
            
            # Convert enum values to strings
            if hasattr(query_dict['opcode'], 'name'):
                query_dict['opcode'] = query_dict['opcode'].name
            if hasattr(query_dict['response_code'], 'name'):
                query_dict['response_code'] = query_dict['response_code'].name
                
            return query_dict
        except Exception as e:
            logger.warning(f"Failed to serialize query: {e}")
            return {'error': f'Serialization failed: {e}'}
    
    async def _save_results(self) -> None:
        """Save fuzzing results to files."""
        output_path = Path(self.config.output_directory)
        
        # Save detailed results
        results_file = output_path / f"fuzzing_results_{int(time.time())}.json"
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'config': self.config.model_dump(),
                    'stats': self.stats,
                    'results': self.results
                }, f, indent=2, default=str)
            logger.info(f"Results saved to {results_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
        
        # Save summary statistics
        stats_file = output_path / f"fuzzing_stats_{int(time.time())}.json"
        try:
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2, default=str)
            logger.info(f"Statistics saved to {stats_file}")
        except Exception as e:
            logger.error(f"Failed to save statistics: {e}")
    
    def _print_summary(self) -> None:
        """Print fuzzing summary."""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        logger.info("=== Fuzzing Summary ===")
        logger.info(f"Duration: {duration:.2f} seconds")
        logger.info(f"Queries sent: {self.stats['queries_sent']}")
        logger.info(f"Responses received: {self.stats['responses_received']}")
        logger.info(f"Timeouts: {self.stats['timeouts']}")
        logger.info(f"Errors: {self.stats['errors_encountered']}")
        
        if self.stats['queries_sent'] > 0:
            response_rate = (self.stats['responses_received'] / self.stats['queries_sent']) * 100
            logger.info(f"Response rate: {response_rate:.1f}%")
            
            queries_per_second = self.stats['queries_sent'] / duration
            logger.info(f"Queries per second: {queries_per_second:.1f}")
        
        logger.info("======================")
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get fuzzing results."""
        return self.results.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fuzzing statistics."""
        return self.stats.copy()

async def run_client(config: ClientConfig, **kwargs) -> DNSFuzzerClient:
    """Run the DNS client fuzzer with the given configuration.
    
    Args:
        config: ClientConfig instance
        
    Returns:
        DNSFuzzerClient instance with results
    """    
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)

    # Create and run client
    client = DNSFuzzerClient(config)
    await client.start_fuzzing()
    
    return client


if __name__ == "__main__":
    import sys
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Run the client fuzzer
    asyncio.run(run_client(config_path))