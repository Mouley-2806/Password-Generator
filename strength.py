import hashlib
import requests
from .constant import (
    COMMON_WEAK_PASSWORDS,
    HIBP_API_URL,
    HIBP_USER_AGENT,
    get_local_weak_hashes,
    add_to_local_weak_hashes,
    initialize_local_storage
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

def assess_strength(password:str, enable_learning:bool=True):
    if not password:
        return "Very Weak", "Password is empty", 0.0
    
    entropy=calculate_entropy(password)
    length=len(password)
    score=0
    breach_info=" "

    if password.lower() in COMMON_WEAK_PASSWORDS:
        score=0
        breach_info="This is one of the most commonly used passwords in the world"
    else:
        local_hashes=get_local_weak_hashes()
        password_hash=hashlib.sha256(password.encode('utf-8')).hexdigest()
        if password_hash in local_hashes:
            score=0
            breach_info="This password was previously marked as weak by you"
    if not breach_info:
        is_pwned, count= is_pwned_hibp(password)
        if is_pwned:
            score=0
            breach_info=f"This password has been breached{count:,} times in real data leaks"
    if length>=18:
        score+=5
    elif length>=14:
        score+=4
    elif length>=12:
        score+=3
    elif length>=8:
        score+=2
    if any(c.islower() for c in password): score+=1
    if any(c.isupper()for c in password): score+=1
    if any(c.isdigits() for c in password): score+=1
    if any(not c.isalnum() for c in password): score+=1

    if entropy >=80: score+=3
    elif entropy>=60: score+=3
    elif entropy>=40: score+=2

    if score>=12:
        level="Very Strong"
        feedback="Excellent extremely hard to guess!"
    elif score>=9:
        level="Strong"
        feedback="Great Password. Highly recommended"
    elif score>=6:
        level="Medium"
        feedback="Decent, but can be improved"
    elif score>=3:
        level="Weak"
        feedback="Very Weak Password"
    if breach_info:
        feedback=breach_info+"\n"+feedback
    if enable_learning and level in ["Weak","Very Weak"] and not breach_info:
        try:
            choice=input(f"Save it to Local weak list for future checks?(y/n):").strip().lower()
            if choice=='y':
                pwd_hash=hashlib.sha256(password.encode('utf-8')).hexadigit()
                add_to_local_weak_hashes(pwd_hash)
                print("Saved to Weak Password List")
        except:
            pass
    return level,feedback,entropy

def print_password_count(password:str):
    level, feedback, entropy=assess_strength(password)
    print("\n"+"="*72)
    print(f"Password: {password}")
    print(f"length: {len(password)} characters")
    print(f"entropy: {entropy:.1f} bits")
    print(f"Strength: {level}")
    print(f"Feedback: {feedback}")
    print(f"="*72)
    
    
    






