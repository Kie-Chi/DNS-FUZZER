# logger.py
import logging
import sys
import os

try:
    import colorlog
except ImportError:
    # If colorlog is not installed, we'll use a basic fallback
    colorlog = None
    
from .. import constants


def setup_logger(debug: bool = False, module_levels: dict | None = None):
    """
    Configures the root logger for the DNS Fuzzer application with colored output.
    
    Args:
        debug: If True, sets logging level to DEBUG, otherwise INFO
        module_levels: Dictionary mapping module names to log levels
    """
    logger = logging.getLogger()
    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)

    # Prevent duplicate handlers if this function is called multiple times
    if logger.handlers:
        # Even if handlers exist, still allow adjusting module levels dynamically
        _apply_module_levels(module_levels)
        return

    # Check if we should use colors
    # Respect NO_COLOR env var (https://no-color.org/)
    use_colors = sys.stdout.isatty() and colorlog and not os.environ.get("NO_COLOR")

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.NOTSET)

    if use_colors:
        # Define the format with color codes
        formatter = colorlog.ColoredFormatter(
            '%(log_color)s[%(levelname).4s]%(reset)s %(cyan)s%(name)s%(reset)s: %(message)s',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
            reset=True,
            style='%'
        )
    else:
        # Basic formatter for non-color environments
        formatter = logging.Formatter('[%(levelname).4s] %(name)s: %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Apply per-module levels from env or argument
    _apply_module_levels(module_levels)


def _apply_module_levels(module_levels: dict | None):
    """Apply per-module logger levels from mapping or env var DNSFUZZ_LOG_LEVELS.

    module_levels format: {"dnsfuzzer.core.query": "DEBUG", "dnsfuzzer.strategies.basic": "INFO"}
    Env var example: DNSFUZZ_LOG_LEVELS="query=DEBUG,mutator=INFO"
    """
    # Parse from env if not provided
    if module_levels is None:
        env = os.environ.get("DNSFUZZ_LOG_LEVELS")
        if env:
            module_levels = {}
            for pair in env.split(','):
                pair = pair.strip()
                if not pair:
                    continue
                if '=' not in pair:
                    continue
                name, lvl = pair.split('=', 1)
                module_levels[name.strip()] = lvl.strip().upper()

    if not module_levels:
        return

    for name, lvl_str in module_levels.items():
        try:
            norm_name = _normalize_module_name(name)
            lvl = getattr(logging, lvl_str.upper())
            logging.getLogger(norm_name).setLevel(lvl)
        except Exception:
            # Silently ignore invalid levels to avoid crashing
            continue


def _normalize_module_name(name: str) -> str:
    """Normalize provided module name with alias and auto-prefix.

    - If name is an alias, expand to full module path.
    - If name ends with '.*', treat it as base logger (strip the wildcard).
    - If name does not start with 'dnsfuzzer.' and begins with a known top module, prefix 'dnsfuzzer.'.
    """
    # Alias expansion
    if name in constants.LOG_ALIAS_MAP:
        return constants.LOG_ALIAS_MAP[name]
    # Wildcard base (e.g., 'core.*' => 'dnsfuzzer.core')
    if name.endswith('.*'):
        name = name[:-2]
    # Auto-prefix for our modules
    if not name.startswith('dnsfuzzer.'):
        first = name.split('.', 1)[0]
        if first in constants.KNOWN_TOP_MODULES:
            name = f'dnsfuzzer.{name}'
    return name


def get_logger(name: str = None) -> logging.Logger:
    """Get a logger instance for the given name.
    
    Args:
        name: Logger name, typically __name__ from the calling module
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)