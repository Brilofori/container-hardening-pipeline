import json
import sys

def load_trivy(filepath):
    try:
        with open(filepath) as f:
            data = json.load(f)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1
        return counts
    except Exception:
        return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

def load_grype(filepath):
    try:
        with open(filepath) as f:
            data = json.load(f)
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
        for match in data.get("matches", []):
            sev = match.get("vulnerability", {}).get("severity", "Unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    except Exception:
        return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}

def print_report(trivy_before, trivy_after, grype_before, grype_after):
    print("\n" + "="*55)
    print(" VULNERABILITY COMPARISON REPORT")
    print("="*55)

    print("\n TRIVY RESULTS")
    print(f" {'Severity':<12} {'Before':>8} {'After':>8} {'Change':>8}")
    print(" " + "-"*40)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        before = trivy_before.get(sev, 0)
        after = trivy_after.get(sev, 0)
        change = after - before
        arrow = f"-{abs(change)}" if change < 0 else f"+{change}" if change > 0 else "0"
        print(f" {sev:<12} {before:>8} {after:>8} {arrow:>8}")

    print("\n GRYPE RESULTS")
    print(f" {'Severity':<12} {'Before':>8} {'After':>8} {'Change':>8}")
    print(" " + "-"*40)
    for sev in ["Critical", "High", "Medium", "Low", "Negligible"]:
        before = grype_before.get(sev, 0)
        after = grype_after.get(sev, 0)
        change = after - before
        arrow = f"-{abs(change)}" if change < 0 else f"+{change}" if change > 0 else "0"
        print(f" {sev:<12} {before:>8} {after:>8} {arrow:>8}")

    print("\n" + "="*55)
    print(" SUMMARY")
    print("="*55)
    trivy_critical_before = trivy_before.get("CRITICAL", 0)
    trivy_critical_after = trivy_after.get("CRITICAL", 0)
    trivy_high_before = trivy_before.get("HIGH", 0)
    trivy_high_after = trivy_after.get("HIGH", 0)
    grype_critical_before = grype_before.get("Critical", 0)
    grype_critical_after = grype_after.get("Critical", 0)

    print(f" Trivy Critical: {trivy_critical_before} → {trivy_critical_after} ({trivy_critical_before - trivy_critical_after} reduction)")
    print(f" Trivy High:     {trivy_high_before} → {trivy_high_after} ({trivy_high_before - trivy_high_after} reduction)")
    print(f" Grype Critical: {grype_critical_before} → {grype_critical_after} ({grype_critical_before - grype_critical_after} reduction)")
    print("="*55 + "\n")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 summarise.py <trivy_before> <trivy_after> <grype_before> <grype_after>")
        sys.exit(1)

    trivy_before = load_trivy(sys.argv[1])
    trivy_after = load_trivy(sys.argv[2])
    grype_before = load_grype(sys.argv[3])
    grype_after = load_grype(sys.argv[4])

    print_report(trivy_before, trivy_after, grype_before, grype_after)
