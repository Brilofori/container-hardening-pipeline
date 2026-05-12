import json
import sys

def load_standards(filepath="standards.json"):
    with open(filepath) as f:
        return json.load(f)

def load_trivy(filepath):
    with open(filepath) as f:
        return json.load(f)

def get_vulnerable_packages(data, severities=["CRITICAL", "HIGH"]):
    packages = []
    counts = {"CRITICAL": 0, "HIGH": 0}
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "")
            if sev in severities:
                counts[sev] = counts.get(sev, 0) + 1
                pkg = vuln.get("PkgName")
                if pkg and pkg not in packages:
                    packages.append(pkg)
    return packages, counts

def check_standards(dockerfile_lines, trivy_counts, standards):
    results = {}

    critical = trivy_counts.get("CRITICAL", 0)
    results["max_critical_cves"] = {
        "pass": critical <= standards["max_critical_cves"],
        "detail": f"Found {critical} critical CVEs (max allowed: {standards['max_critical_cves']})"
    }

    high = trivy_counts.get("HIGH", 0)
    results["max_high_cves"] = {
        "pass": high <= standards["max_high_cves"],
        "detail": f"Found {high} high CVEs (max allowed: {standards['max_high_cves']})"
    }

    has_user = any(l.strip() == "USER nonroot" for l in dockerfile_lines)
    results["required_nonroot"] = {
        "pass": has_user,
        "detail": "Non-root USER directive found" if has_user else "Container runs as root"
    }

    dockerfile_text = " ".join(dockerfile_lines)
    found_forbidden = [pkg for pkg in standards["forbidden_packages"] if pkg in dockerfile_text]
    results["forbidden_packages"] = {
        "pass": len(found_forbidden) == 0,
        "detail": "Forbidden packages removed" if not found_forbidden else f"Forbidden packages still present: {found_forbidden}"
    }

    found_volumes = [vol for vol in standards["forbidden_volumes"] if any(vol in line for line in dockerfile_lines)]
    results["forbidden_volumes"] = {
        "pass": len(found_volumes) == 0,
        "detail": "No sensitive volumes exposed" if not found_volumes else f"Sensitive volumes exposed: {found_volumes}"
    }

    from_line = next((l for l in dockerfile_lines if l.strip().startswith("FROM")), "")
    correct_base = standards["min_base_image"] in from_line
    results["min_base_image"] = {
        "pass": correct_base,
        "detail": f"Base image updated to {standards['min_base_image']}" if correct_base else f"Base image not updated — found: {from_line.strip()}"
    }

    return results

def apply_fixes(dockerfile_lines, vulnerable_packages, standards):
    new_lines = []
    fixes = []
    all_to_remove = list(set(standards["forbidden_packages"] + vulnerable_packages))
    in_apt_block = False
    skip_run_block = False

    for line in dockerfile_lines:
        stripped = line.strip()

        # Skip debian:10 archive repository lines
        if "archive.debian.org" in line or "buster-updates" in line:
            continue

        # Skip the RUN sed block that fixes debian:10 repos
        if stripped.startswith("RUN sed") and "deb.debian.org" in line:
            skip_run_block = True
            continue

        if skip_run_block:
            if line.rstrip().endswith("\\"):
                continue
            else:
                skip_run_block = False
                continue

        # Fix 1 — update base image
        if stripped.startswith("FROM") and standards["min_base_image"] not in line:
            new_lines.append(f"FROM {standards['min_base_image']}\n")
            fixes.append(f"Updated base image to {standards['min_base_image']}")
            continue

        # Fix 2 — detect apt-get install block
        if "apt-get install" in line or "apt install" in line:
            in_apt_block = True
            new_lines.append(line)
            continue

        # Fix 2 continued — remove forbidden packages inside block
        if in_apt_block:
            pkg_name = stripped.rstrip("\\").strip()
            if pkg_name in all_to_remove:
                fixes.append(f"Removed package: {pkg_name}")
                if not line.rstrip().endswith("\\"):
                    in_apt_block = False
                continue
            if not line.rstrip().endswith("\\") and pkg_name != "&&":
                in_apt_block = False
            new_lines.append(line)
            continue

        # Fix 3 — remove sensitive volumes
        if stripped.startswith("VOLUME"):
            for vol in standards["forbidden_volumes"]:
                if vol in line:
                    fixes.append(f"Removed sensitive VOLUME: {vol}")
                    break
            else:
                new_lines.append(line)
            continue

        # Fix 4 — remove USER root
        if stripped == "USER root":
            fixes.append("Removed USER root directive")
            continue

        new_lines.append(line)

    # Fix 5 — add nonroot user if missing
    has_nonroot = any(l.strip() == "USER nonroot" for l in new_lines)
    if standards["required_nonroot"] and not has_nonroot:
        new_lines.append("\nRUN useradd -m nonroot\n")
        new_lines.append("USER nonroot\n")
        fixes.append("Added non-root user and switched to nonroot")

    return new_lines, fixes

def print_standards_report(label, results):
    print(f"\n{'='*50}")
    print(f" STANDARDS COMPLIANCE REPORT — {label}")
    print(f"{'='*50}")
    passed = sum(1 for r in results.values() if r["pass"])
    total = len(results)
    print(f" Overall: {passed}/{total} standards passing\n")
    for standard, result in results.items():
        status = "PASS" if result["pass"] else "FAIL"
        print(f" [{status}] {standard}")
        print(f"       {result['detail']}")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 harden.py <trivy_json> <dockerfile>")
        sys.exit(1)

    trivy_file = sys.argv[1]
    dockerfile_path = sys.argv[2]

    standards = load_standards()
    trivy_data = load_trivy(trivy_file)
    vulnerable_packages, trivy_counts = get_vulnerable_packages(trivy_data)

    with open(dockerfile_path) as f:
        dockerfile_lines = f.readlines()

    before_results = check_standards(dockerfile_lines, trivy_counts, standards)
    print_standards_report("BEFORE HARDENING", before_results)

    print("Applying fixes...\n")
    new_lines, fixes = apply_fixes(dockerfile_lines, vulnerable_packages, standards)

    print(f" Fixes applied: {len(fixes)}")
    for fix in fixes:
        print(f"  + {fix}")

    hardened_path = dockerfile_path.replace("Dockerfile", "Dockerfile.hardened")
    with open(hardened_path, "w") as f:
        f.writelines(new_lines)

    print(f"\n Hardened Dockerfile saved to: {hardened_path}")
    print(" Rebuild the image then re-run standards check to verify improvement.")

