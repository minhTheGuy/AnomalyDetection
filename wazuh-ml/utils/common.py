"""
Common utility functions để tinh gọn code
"""

import os
import pandas as pd
import joblib
from typing import Optional, Dict, Any
from functools import wraps


# ============================================================================
# Print Utilities
# ============================================================================

def print_header(title: str, width: int = 70, char: str = "="):
    """In header với format chuẩn"""
    print(f"\n{char * width}")
    print(title.upper())
    print(f"{char * width}")


def print_section(title: str, width: int = 70, char: str = "-"):
    """In section header"""
    print(f"\n{char * width}")
    print(title)
    print(f"{char * width}")


# ============================================================================
# File Utilities
# ============================================================================

def safe_load_csv(path: str, default: Optional[pd.DataFrame] = None) -> Optional[pd.DataFrame]:
    """Load CSV file an toàn, trả về None nếu lỗi"""
    if not os.path.exists(path):
        return default
    try:
        return pd.read_csv(path)
    except Exception as e:
        print(f"Warning: Could not load {path}: {e}")
        return default


def safe_save_csv(df: pd.DataFrame, path: str, **kwargs) -> bool:
    """Save CSV file an toàn"""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        df.to_csv(path, index=False, **kwargs)
        return True
    except Exception as e:
        print(f"Error saving {path}: {e}")
        return False


def safe_load_joblib(path: str, default: Any = None) -> Any:
    """Load joblib file an toàn"""
    if not os.path.exists(path):
        return default
    try:
        return joblib.load(path)
    except Exception as e:
        print(f"Warning: Could not load {path}: {e}")
        return default


def safe_save_joblib(obj: Any, path: str) -> bool:
    """Save joblib file an toàn"""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(obj, path)
        return True
    except Exception as e:
        print(f"Error saving {path}: {e}")
        return False


# ============================================================================
# Error Handling Decorator
# ============================================================================

def handle_errors(default_return=None, print_error=True):
    """Decorator để handle errors một cách nhất quán"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if print_error:
                    print(f"Error in {func.__name__}: {e}")
                    import traceback
                    traceback.print_exc()
                return default_return
        return wrapper
    return decorator


# ============================================================================
# DataFrame Utilities
# ============================================================================

def ensure_dataframe(data: Any) -> pd.DataFrame:
    """Convert data thành DataFrame nếu cần"""
    if isinstance(data, pd.DataFrame):
        return data
    elif isinstance(data, list):
        return pd.DataFrame(data) if data else pd.DataFrame()
    else:
        return pd.DataFrame()


# ============================================================================
# Path Utilities
# ============================================================================

def ensure_dir(path: str):
    """Đảm bảo directory tồn tại"""
    dir_path = os.path.dirname(path) if os.path.isfile(path) else path
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

