import re

def check_phishing(url):
    warnings = []

    # Rule 1: IP address in URL
    if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
        warnings.append("Uses IP instead of domain ❌")

    # Rule 2: '@' symbol in URL
    if "@" in url:
        warnings.append("Contains '@' symbol ❌")

    # Rule 3: Too many '-' in domain
    if url.count('-') > 3:
        warnings.append("Suspicious use of '-' ❌")

    # Rule 4: HTTPS check
    if not url.startswith("https://"):
        warnings.append("Does not use HTTPS ❌")

    # Rule 5: Very long URL
    if len(url) > 75:
        warnings.append("URL length is too long ❌")

    # Final verdict
    if len(warnings) == 0:
        return "✅ Likely Safe", []
    else:
        return "⚠️ Suspicious/Phishing", warnings


# -----------------------------
# Run the detector
# -----------------------------
url = input("Enter a URL to check: ")
status, issues = check_phishing(url)

print("\nResult:", status)
if issues:
    print("Issues Found:")
    for i in issues:
        print("-", i)

