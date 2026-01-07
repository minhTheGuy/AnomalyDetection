"""
utils.py - Shared utility functions
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def validate_ssh_key(key_file: Optional[str]) -> Optional[str]:
    """Validate and expand SSH key file path.
    
    Args:
        key_file: Path to SSH key file (supports ~)
        
    Returns:
        Expanded path if file exists, None otherwise
    """
    if not key_file:
        return None
    
    # Expand ~ to home directory
    expanded = str(Path(key_file).expanduser())
    
    if not Path(expanded).exists():
        logger.warning(f"SSH key not found: {key_file}")
        return None
    
    return expanded
