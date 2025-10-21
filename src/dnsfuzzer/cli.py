"""Command-line interface for DNS Fuzzer."""

import click
import asyncio
import sys
from pathlib import Path
from typing import Optional

from .core.config import load_config, create_default_config
from .core.query import create_basic_query
from .core.mutator import create_default_mutator
from .utils.logger import setup_logger, get_logger

logger = get_logger(__name__)


def setup_logging(level: str, module_levels: dict = None) -> None:
    """Setup logging configuration using our custom logger."""
    debug = level.upper() == 'DEBUG'
    setup_logger(debug=debug, module_levels=module_levels)
    logger.info(f"Logging initialized with level: {level}")


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file path')
@click.option('--log-level', '-l', default='INFO',
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']),
              help='Logging level')
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], log_level: str) -> None:
    """DNS Fuzzer - A tool for fuzzing DNS queries."""
    setup_logging(log_level)
    
    # Store config path and log level in context
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config
    ctx.obj['log_level'] = log_level


@cli.command()
@click.pass_context
def list_strategies(ctx: click.Context) -> None:
    """List all available mutation strategies."""
    # Load configuration
    config_path = ctx.obj.get('config_path')
    if config_path:
        config = load_config(config_path)
    else:
        config = create_default_config()
    
    click.echo("Available mutation strategies:")
    click.echo()
    
    for strategy in config.strategies:
        status = "✓" if strategy.enabled else "✗"
        click.echo(f"  {status} {strategy.name} (weight: {strategy.weight})")
        
        if strategy.parameters:
            for key, value in strategy.parameters.items():
                click.echo(f"      {key}: {value}")
    
    enabled_count = len(config.get_enabled_strategies())
    total_count = len(config.strategies)
    click.echo()
    click.echo(f"Total: {total_count} strategies ({enabled_count} enabled)")


@cli.command()
@click.option('--output', '-o', type=click.Path(), default='fuzzer_config.yaml',
              help='Output configuration file path')
@click.option('--force', is_flag=True, help='Overwrite existing file')
def init_config(output: str, force: bool) -> None:
    """Initialize a default configuration file."""
    output_path = Path(output)
    
    if output_path.exists() and not force:
        click.echo(f"Configuration file '{output}' already exists. Use --force to overwrite.", err=True)
        sys.exit(1)
    
    config = create_default_config()
    config.save_to_file(str(output_path))
    
    click.echo(f"Default configuration saved to '{output}'")
    click.echo("You can now edit this file to customize your fuzzing settings.")


@cli.command()
@click.option('--query-name', '-n', default='example.com', help='Query name')
@click.option('--query-type', default='A', help='Query type')
@click.option('--strategy', '-s', help='Specific strategy to test')
@click.option('--count', '-c', type=int, default=5, help='Number of mutations to generate')
@click.pass_context
def test_strategy(ctx: click.Context, query_name: str, query_type: str,
                  strategy: Optional[str], count: int) -> None:
    """Test mutation strategies with sample queries."""
    # Load configuration
    config_path = ctx.obj.get('config_path')
    if config_path:
        config = load_config(config_path)
    else:
        config = create_default_config()
    
    # Create base query
    base_query = create_basic_query(query_name, query_type)
    click.echo(f"Base query: {query_name} ({query_type})")
    click.echo()
    
    # Create mutator
    mutator = create_default_mutator()
    
    # Load strategies from config
    for strategy_config in config.get_enabled_strategies():
        if strategy and strategy_config.name != strategy:
            continue
        
        click.echo(f"Testing strategy: {strategy_config.name}")
        click.echo("-" * 40)
        
        for i in range(count):
            try:
                mutated = mutator.mutate_query(base_query, strategy_config.name)
                if mutated != base_query:
                    click.echo(f"  {i+1}. {mutated.name} ({mutated.qtype}) - ID: {mutated.id}")
                else:
                    click.echo(f"  {i+1}. No mutation applied")
            except Exception as e:
                click.echo(f"  {i+1}. Error: {e}")
        
        click.echo()
        
        if strategy:
            break


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Client configuration file path')
@click.option('--target', '-t', help='Target DNS server IP address')
@click.option('--port', '-p', type=int, help='Target DNS server port')
@click.option('--iterations', '-i', type=int, help='Number of fuzzing iterations')
@click.option('--concurrent', type=int, help='Number of concurrent requests')
@click.option('--delay', '-d', type=float, help='Delay between requests (seconds)')
@click.option('--output', '-o', type=click.Path(), help='Output directory for results')
@click.option('--query-name', '-n', help='Default query name to fuzz')
@click.option('--query-type', '-q', help='Default query type (A, AAAA, MX, etc.)')
@click.option('--timeout', type=float, help='Request timeout in seconds')
@click.pass_context
def client(ctx: click.Context, config: Optional[str], target: Optional[str], 
           port: Optional[int],
           iterations: Optional[int], concurrent: Optional[int], delay: Optional[float],
           output: Optional[str], query_name: Optional[str], query_type: Optional[str],
           timeout: Optional[float]) -> None:
    """Start the DNS Fuzzer client."""
    from .client.client import run_client
    from .client.config import load_client_config, create_default_client_config
    
    # Use config from command line or context
    config_path = config or ctx.obj.get('config_path')
    
    try:
        if config_path:
            client_config = load_client_config(config_path)
        else:
            # Use default configuration
            client_config = create_default_client_config()
        
        # Override config with command line options
        if target:
            client_config.target_servers = target if isinstance(target, list) else [target]
        if port is not None:
            client_config.target_port = port
        if iterations is not None:
            client_config.max_iterations = iterations
        if concurrent is not None:
            client_config.concurrent_requests = concurrent
        if delay is not None:
            client_config.delay_between_requests = delay
        if output:
            client_config.output_directory = output
        if query_name:
            client_config.default_query_name = query_name
        if query_type:
            client_config.default_query_type = query_type
        if timeout is not None:
            client_config.timeout = timeout
        
        logger.info("Starting DNS Fuzzer Client...")
        logger.info(f"Target: {', '.join(client_config.target_servers)}:{client_config.target_port}")
        logger.info(f"Max Iterations: {client_config.max_iterations}")
        
        # Run the client
        asyncio.run(run_client(client_config))
        
    except Exception as e:
        logger.error(f"Failed to start client: {e}")
        sys.exit(1)


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Authentication server configuration file path')
@click.option('--host', '-h', help='Authentication server bind address')
@click.option('--port', '-p', type=int, help='Authentication server port')
@click.option('--output', '-o', type=click.Path(), help='Output directory for results')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              help='Logging level')
@click.pass_context
def auth(ctx: click.Context, config: Optional[str], host: Optional[str], 
         port: Optional[int], output: Optional[str], log_level: Optional[str],) -> None:
    """Start the DNS Authentication server."""
    from .auth.server import run_auth
    from .auth.config import load_auth_config, create_default_auth_config
    
    # Use config from command line or context
    config_path = config or ctx.obj.get('config_path')
    
    try:
        if config_path:
            auth_config = load_auth_config(config_path)
        else:
            # Use default configuration
            auth_config = create_default_auth_config()
        # Override config with command line options
        if host:
            auth_config.listen_address = host
        if port is not None:
            auth_config.listen_port = port
        if log_level:
            auth_config.log_level = log_level
        if output:
            auth_config.output_directory = output
        
        
        logger.info("Starting DNS Authentication Server...")
        logger.info(f"Listening on: {auth_config.listen_address}:{auth_config.listen_port}")
        logger.info(f"Log Level: {auth_config.log_level}")
        
        # Run the auth server
        run_auth(auth_config)
        
    except Exception as e:
        logger.error(f"Failed to start auth server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    cli()