from .core import generate_password
from .strength import assess_strength, print_password_count
from .utils import interactive_mode
from .constant import initialize_local_storage

__version__     = "2.1"
__author__      = "Bansal"
__description__ = "Advanced Password Generator with Built-in + Local + HIBP breach detection"

__all__ = [
    "generate_password",
    "assess_strength",
    "print_password_count",
    "interactive_mode",
]

# Ensure the local weak-password store exists on first import
initialize_local_storage()

print(f"🔐 Password Generator v{__version__} loaded successfully!")
