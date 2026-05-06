#!/usr/bin/env python3
"""
scripts/manage.py — CLI management tool for Q-BOM AI.

Usage:
  python scripts/manage.py seed-db       — Seed knowledge base with NIST docs
  python scripts/manage.py init-db       — Run Alembic migrations
  python scripts/manage.py scan <url>    — Trigger a scan from CLI
  python scripts/manage.py eval          — Run evaluation batch
  python scripts/manage.py stats         — Print system statistics
"""
import asyncio
import sys
import json
import httpx

API = "http://localhost:8000"
API_KEY = "qbom-demo-key-2025"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}


async def seed_db():
    print("🌱 Seeding knowledge base with NIST algorithm documentation…")
    r = httpx.post(f"{API}/api/knowledge/seed", headers=HEADERS, timeout=60)
    data = r.json()
    print(f"✓ {data.get('message', data)}")


async def init_db():
    print("🗄️  Running database migrations…")
    import subprocess
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        cwd="backend",
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("✓ Migrations complete")
    else:
        print(f"✗ Migration failed:\n{result.stderr}")
        sys.exit(1)


async def scan(target: str, target_type: str = "repo", sensitivity: str = "medium"):
    print(f"🔍 Scanning {target_type}: {target}")
    r = httpx.post(f"{API}/api/scan", headers=HEADERS, timeout=30, json={
        "target": target, "target_type": target_type, "data_sensitivity": sensitivity
    })
    data = r.json()
    scan_id = data["scan_id"]
    print(f"   Scan ID: {scan_id}")

    # Poll
    for i in range(40):
        await asyncio.sleep(10)
        r = httpx.get(f"{API}/api/scan/{scan_id}", headers=HEADERS)
        status_data = r.json()
        status = status_data.get("status")
        print(f"   [{i+1}/40] {status}…")
        if status == "complete":
            print(f"\n✅ Scan complete!")
            print(f"   Risk Level : {status_data['risk_level'].upper()}")
            print(f"   HNDL Score : {status_data['hndl_score']:.2f} / 10")
            print(f"   Findings   : {status_data['finding_count']}")

            # Download BOM
            r = httpx.get(f"{API}/api/scan/{scan_id}/bom", headers=HEADERS)
            bom_file = f"qbom-{scan_id[:8]}.cdx.json"
            with open(bom_file, "w") as f:
                json.dump(r.json(), f, indent=2)
            print(f"   BOM saved  : {bom_file}")
            return
        elif status == "failed":
            print(f"✗ Scan failed")
            sys.exit(1)

    print("✗ Scan timed out")
    sys.exit(1)


async def run_eval():
    print("🧪 Running DeepEval + RAGAS evaluation batch…")
    r = httpx.get(f"{API}/api/eval/run", headers=HEADERS, timeout=120)
    data = r.json()
    print(json.dumps(data, indent=2))


async def stats():
    print("📊 Q-BOM AI Statistics")
    r = httpx.get(f"{API}/api/scans?page_size=100", headers=HEADERS)
    data = r.json()
    scans = data.get("scans", [])

    statuses = {}
    for s in scans:
        statuses[s["status"]] = statuses.get(s["status"], 0) + 1

    completed = [s for s in scans if s["status"] == "complete"]
    avg_hndl = sum(s["hndl_score"] or 0 for s in completed) / len(completed) if completed else 0

    print(f"  Total scans    : {data['total']}")
    for status, count in statuses.items():
        print(f"  {status:12s} : {count}")
    print(f"  Avg HNDL score : {avg_hndl:.2f}")

    r2 = httpx.get(f"{API}/api/knowledge/algorithms", headers=HEADERS)
    ka = r2.json()
    print(f"  KB algorithms  : {ka['total']}")


async def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "seed-db":
        await seed_db()
    elif cmd == "init-db":
        await init_db()
    elif cmd == "scan":
        if len(sys.argv) < 3:
            print("Usage: python manage.py scan <url> [repo|website] [sensitivity]")
            sys.exit(1)
        target = sys.argv[2]
        target_type = sys.argv[3] if len(sys.argv) > 3 else "repo"
        sensitivity = sys.argv[4] if len(sys.argv) > 4 else "medium"
        await scan(target, target_type, sensitivity)
    elif cmd == "eval":
        await run_eval()
    elif cmd == "stats":
        await stats()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
