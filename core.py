import secrets
from .constant import(
    LOWERCASE,UPPERCASE,DIGITS,SYMBOLS,AMBIGUOUS_CHARS
)

def generaate_password(
        length: int =16,
        uppercase: bool=True,
        lowercase: bool=True,
        digits: bool=True,
        symbols: bool=True,
        exclude_ambiguous: bool=True
        )-> str: