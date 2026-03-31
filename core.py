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
    if length<4:
        raise ValueError("Password length must be at least 4 characters")
    char_sets=[]
    if lowercase:
        char_sets.append(LOWERCASE)
    if uppercase:
        char_sets.append(UPPERCASE)
    if digits:
        char_sets(DIGITS)
    if symbols:
        char_sets.append(SYMBOLS)
    if not char_sets:
        raise ValueError("At least one character type must be selected(uppercase,lowercase,digits or symbols)")
    if exclude_ambiguous:
        char_sets=["".join(c for c in char_set if c not in AMBIGUOUS_CHARS)for char_set in char_sets]
    pool="".join (char_sets)
    password_list=[]
    for char_set in char_sets:
        if char_set:
            password_list.append(secrets.choice(char_set))
    while len(password_list)<length:
        password_list.append(secrets.choice(pool))
    secrets.SystemRandom().shuffle(password_list)
    return "".join(password_list[:length])
    