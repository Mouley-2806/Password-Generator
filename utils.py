from .core import generate_password
from .strength import print_password_count, assess_strength


def interactive_mode():
    print("\n🔐 Advanced Password Generator & Analyzer — Hybrid Breach Detection")
    print("=" * 72)

    while True:
        print("\n  Options:")
        print("  1. Generate a Password")
        print("  2. Assess Password Strength")
        print("  3. Exit")

        choice = input("\nEnter your choice (1/2/3): ").strip()

        if choice == "1":
            try:
                length     = int(input("\nPassword length [default 16]: ").strip() or "16")
                uppercase  = input("Include uppercase letters? (y/n) [y]: ").strip().lower() != "n"
                lowercase  = input("Include lowercase letters? (y/n) [y]: ").strip().lower() != "n"
                digits     = input("Include digits?           (y/n) [y]: ").strip().lower() != "n"
                symbols    = input("Include symbols?          (y/n) [y]: ").strip().lower() != "n"
                excl_amb   = input("Exclude ambiguous chars (0O1lI)? (y/n) [y]: ").strip().lower() != "n"
                count      = int(input("How many passwords to generate? [1]: ").strip() or "1")

                print(f"\n🔨 Generating {count} secure password(s)...\n")

                for i in range(count):
                    pwd = generate_password(
                        length=length,
                        uppercase=uppercase,
                        lowercase=lowercase,
                        digits=digits,
                        symbols=symbols,
                        exclude_ambiguous=excl_amb,
                    )
                    print(f"  Password #{i + 1}:")
                    print_password_count(pwd)

            except ValueError as e:
                # FIX: was `print("Error" + e)` — can't concatenate str + Exception
                print(f"  ❌ Error: {e}")
            except KeyboardInterrupt:
                print("\n  Exiting...")

        elif choice == "2":
            pwd = input("\nEnter the password to analyse: ").strip()
            if pwd:
                print("\n  Analysing password strength...")
                level, feedback, entropy = assess_strength(pwd)
                print("\n" + "=" * 72)
                print(f"  Password : {pwd}")
                print(f"  Length   : {len(pwd)} characters")
                print(f"  Entropy  : {entropy:.1f} bits")
                print(f"  Strength : {level}")
                print(f"  Feedback : {feedback}")
                print("=" * 72)
            else:
                print("  ⚠️  No password entered.")

        elif choice == "3":
            print("\n  Thank you for using the Advanced Password Generator!")
            print("  Stay secure! 🔒")
            break

        else:
            print("  ⚠️  Invalid choice — please enter 1, 2, or 3.")
