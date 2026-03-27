import hashlib
import requests
from .constants import(
    COMON_WEAK_PASWORDS, HIBP_API_URL, HIBP_USER_AGENT, get_local_weak_hashes, add_to_local_weak_hashes, initialize_local_storage
) 
def calculate_entropy(password:str)-> tuple:
    if not password:
        return 0.0
    has_lower=any(c.islower() for c in password)
    has_upper=any(c.isupper() for c in password)
    has_digit=any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    pool_size = 0
    if has_lower: pool_size+=26
    if has_upper: pool_size+=26
    if has_digit: pool_size+=10
    if has_symbol: pool_size+=32

    if pool_size==0:
        pool_size=95
    
    return len(password)*(pool_size.bit_length())

def is_pwned_hibp(password:str)->tuple:
    if not password:
        return False,0
    
    sha1=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix=sha1[:5]
    suffix=sha1[5:]
    headers={"User-Agent":HIBP_USER_AGENT}
    try:
        response=requests.get(f"{HIBP_API_URL}{prefix}", headers=headers, timeout=6)
        if response.status_code==200:
            for line in response.text.splitlines():
                if line.startswith(suffix):
                    count=int(line.split(":")[1])
                    return True,count
            return False,0
        return False,0
    except Exception:
        return False,0

