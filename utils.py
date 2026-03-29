from .core import generate_passowrd
from .strength import print_password_count, assess_strength

def interactive_mode():
    print("\n Advanced Password Generator and Analyzer with Hybride Breach Detection")
    while True:
        print("\n Options:")
        print("1. Generate a Password")
        print("2. Assess Password Strength")
        print("3. Exit")

        choice=input("Enter your choice (1/2/3): ").strip()
        if choice=='1':
            try:
                length = int(input("\nEnter password length [default 16]: ") or "16")
                uppercase = input("Include Uppercase letters? (y/n) [y]: ").lower() != "n"
                lowercase = input("Include Lowercase letters? (y/n) [y]: ").lower() != "n"
                digits = input("Include Digits? (y/n) [y]: ").lower() != "n"
                symbols = input("Include Symbols? (y/n) [y]: ").lower() != "n"
                exclude_amb = input("Exclude ambiguous characters (0O1lI)? (y/n) [y]: ").lower() != "n"
                count = int(input("How many passwords to generate? [1]: ") or "1")
                print(f"\n🔨 Generating {count} secure password(s)...\n")

                for i in range(count):
                    pwd=generate_password(
                        length=length,uppercase=uppercase,lowercase=lowercase,symbols=symbols,exclude_ambiguous=exclude_amb
                    )
                    print(f"Password #{i+1}:")
                    print_password_card(pwd)

            except ValueError as e:
                print("Error"+e)
            except KeyboardInterrupt:
                print("Existing.......")

        elif choice=='2':
            pwd = input("\nEnter the password you want to check: ").strip()
            if pwd:
                print("\nAnalyzing password strength...")
                level, feedback, entropy = assess_strength(pwd)
                print("\n" + "=" * 72)
                print(f"🔑 Password     :  {pwd}")
                print(f"📏 Length       :  {len(pwd)} characters")
                print(f"🔢 Entropy      :  {entropy:.1f} bits")
                print(f"💪 Strength     :  {level}")
                print(f"📝 Feedback     :  {feedback}")
                print("=" * 72)

        elif choice == "3":
            print("\n👋 Thank you for using the Advanced Password Generator!")
            print("   Stay secure! 🔐")
            break

        else:
            print("❌ Invalid choice! Please enter 1, 2, or 3.")

    
                    

