import argparse
import sys

from password.core import generate_password
from password.strength import print_password_count, assess_strength
from password.utils import interactive_mode
from password.constant import initialize_local_storage

def main():
    initialize_local_storage()
    parser = argparse.ArgumentParser(
        description="Advanced Password Generator with Hybrid Breach Detection",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-g", "--generate", action="store_true",
                        help="Generate one or more passwords")
    parser.add_argument("-c", "--check", type=str, metavar="PASSWORD",
                        help="Check the strength of a password")
    parser.add_argument("-l", "--length", type=int, default=16,
                        help="Password length (default: 16)")
    parser.add_argument("--no-upper",     action="store_true", help="Exclude uppercase")
    parser.add_argument("--no-lower",     action="store_true", help="Exclude lowercase")
    parser.add_argument("--no-digits",    action="store_true", help="Exclude digits")
    parser.add_argument("--no-symbols",   action="store_true", help="Exclude symbols")
    parser.add_argument("--no-ambiguous", action="store_false", default=True,
                        help="Do NOT exclude ambiguous characters (0O1lI)")
    parser.add_argument("-n", "--count",  type=int, default=1,
                        help="Number of passwords to generate")

    args = parser.parse_args()

    # === Generate Mode ===
    if args.generate:
        for i in range(args.count):
            try:
                pwd = generate_password(
                    length=args.length,
                    uppercase=not args.no_upper,
                    lowercase=not args.no_lower,
                    digits=not args.no_digits,
                    symbols=not args.no_symbols,
                    exclude_ambiguous=args.no_ambiguous,
                )
                if args.count > 1:
                    print(f"\n--- Password #{i + 1} ---")
                print_password_count(pwd)
            except Exception as e:
                print(f"❌ Error: {e}")

    # === Check Password Strength Mode ===
    elif args.check is not None:
        print("\n🔍 Analyzing password strength...")
        level, feedback, entropy = assess_strength(args.check)
        print("\n" + "=" * 75)
        print(f"🔑 Password     :  {args.check}")
        print(f"📏 Length       :  {len(args.check)} characters")
        print(f"🔢 Entropy      :  {entropy:.1f} bits")
        print(f"💪 Strength     :  {level}")
        print(f"📝 Feedback     :  {feedback}")
        print("=" * 75)

    # === Default: Interactive Mode ===
    else:
        interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye! Stay secure! 🔐")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
