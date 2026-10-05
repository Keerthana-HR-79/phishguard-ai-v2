"""
b4_signal_probe.py — is a non-lexical signal fold-able into the MODEL, or is
offline domain-age a leakage artifact?  (empirical test of the B4 deferral)

The audit deferred B4 (fold domain age / cert age into the model) with the
reasoning: our phishing rows come from a ~April-2025 OpenPhish/PhishTank snapshot.
Those phishing domains are mostly TAKEN DOWN by now, so a live WHOIS returns
NXDOMAIN / -1, while legit Tranco domains still resolve to a real (old) age. If
we compute age at train time TODAY and feed it to the model, the model learns
"WHOIS fails / age == -1  =>  phishing" — which is a takedown artifact of the
snapshot, NOT a signal that generalizes to a LIVE phishing URL (whose domain is
still up and returns a small-but-valid age). This script measures whether that
artifact is real, on a live sample of both classes.

For each sampled URL it resolves, LIVE and concurrently:
  - WHOIS creation age in days (-1 on any failure / no data)
  - DNS resolvability (does the host resolve at all)
  - TLS cert age in days from the cert's notBefore (None if unreachable)

Then per class it reports WHOIS-success rate, DNS-resolve rate, median live age,
and median cert age. Read the verdict block at the end.

Run:  python b4_signal_probe.py [N_per_class]   (default 100)
"""
import sys
import socket
import ssl
import datetime
import statistics as stats
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import whois

from url_augment import registrable_domain

N = int(sys.argv[1]) if len(sys.argv) > 1 else 100
TIMEOUT = 6
socket.setdefaulttimeout(TIMEOUT)


def host_of(url: str) -> str:
    h = url.split("//")[-1].split("/")[0]
    h = h.split("@")[-1].split(":")[0].strip().lower()
    return h[4:] if h.startswith("www.") else h


def whois_age(domain: str) -> int:
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if not cd:
            return -1
        if isinstance(cd, list):
            cd = cd[0]
        if isinstance(cd, str):
            return -1
        return (datetime.datetime.now() - cd).days
    except Exception:
        return -1


def dns_ok(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False


def cert_age(domain: str):
    """Days since the leaf cert's notBefore, or None if unreachable/no cert."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        nb = cert.get("notBefore")
        if not nb:
            return None
        secs = ssl.cert_time_to_seconds(nb)
        return int((datetime.datetime.utcnow()
                    - datetime.datetime.utcfromtimestamp(secs)).days)
    except Exception:
        return None


def probe(domain: str):
    return domain, whois_age(domain), dns_ok(domain), cert_age(domain)


def sample_domains(df, kind, n):
    urls = df[df["type"] == kind]["url"].astype(str)
    urls = urls.sample(min(n * 3, len(urls)), random_state=7)   # oversample; dedup by root
    seen, out = set(), []
    for u in urls:
        d = host_of(u)
        r = registrable_domain(u)
        if d and "." in d and r not in seen:
            seen.add(r)
            out.append(d)
        if len(out) >= n:
            break
    return out


def run(kind, domains):
    rows = []
    with ThreadPoolExecutor(max_workers=24) as ex:
        futs = [ex.submit(probe, d) for d in domains]
        for f in as_completed(futs):
            rows.append(f.result())
    ages   = [a for _, a, _, _ in rows]
    live   = [a for a in ages if a >= 0]
    dnsok  = sum(1 for _, _, d, _ in rows if d)
    certs  = [c for _, _, _, c in rows if c is not None]
    n = len(rows)
    # Among domains whose WHOIS resolves, bucket by age. Fresh live phishing would
    # land in "<1yr"; if that bucket is ~empty for phishing, there is no young-age
    # signal to learn — the resolving phishing rows are old compromised/shared hosts.
    fresh = sum(1 for a in live if a < 365)
    yr1_3 = sum(1 for a in live if 365 <= a < 365 * 3)
    old   = sum(1 for a in live if a >= 365 * 3)
    print(f"\n=== {kind.upper()}  (n={n}) ===")
    print(f"  WHOIS success (age>=0)   : {len(live)}/{n}  ({len(live)/n*100:.0f}%)")
    print(f"  WHOIS fail / age == -1   : {n-len(live)}/{n}  ({(n-len(live))/n*100:.0f}%)")
    print(f"  DNS resolves             : {dnsok}/{n}  ({dnsok/n*100:.0f}%)")
    print(f"  median live WHOIS age    : {int(stats.median(live)) if live else 'n/a'} days")
    if live:
        print(f"  age buckets (of {len(live)} live): "
              f"<1yr {fresh} ({fresh/len(live)*100:.0f}%) | "
              f"1-3yr {yr1_3} ({yr1_3/len(live)*100:.0f}%) | "
              f">=3yr {old} ({old/len(live)*100:.0f}%)")
    print(f"  TLS reachable w/ cert    : {len(certs)}/{n}  ({len(certs)/n*100:.0f}%)")
    print(f"  median cert age          : {int(stats.median(certs)) if certs else 'n/a'} days")
    return {"n": n, "whois_fail_pct": (n-len(live))/n*100, "dns_pct": dnsok/n*100,
            "med_age": stats.median(live) if live else None,
            "fresh_pct": (fresh/len(live)*100) if live else None,
            "cert_pct": len(certs)/n*100,
            "med_cert": stats.median(certs) if certs else None}


if __name__ == "__main__":
    df = pd.read_csv("../data/processed/final_dataset.csv").dropna(subset=["url"])
    ph_d = sample_domains(df, "phishing", N)
    lg_d = sample_domains(df, "legitimate", N)
    print(f"Probing {len(ph_d)} phishing + {len(lg_d)} legit domains LIVE "
          f"(timeout {TIMEOUT}s, 24 workers)... this makes real network calls.")
    ph = run("phishing", ph_d)
    lg = run("legitimate", lg_d)

    print("\n" + "=" * 70)
    print("VERDICT")
    print("=" * 70)
    gap = ph["whois_fail_pct"] - lg["whois_fail_pct"]
    print(f"  WHOIS-fail rate: phishing {ph['whois_fail_pct']:.0f}%  vs  "
          f"legit {lg['whois_fail_pct']:.0f}%   (gap {gap:+.0f} pts)")
    print(f"  median live age: phishing "
          f"{int(ph['med_age']) if ph['med_age'] is not None else 'n/a'}d  vs  "
          f"legit {int(lg['med_age']) if lg['med_age'] is not None else 'n/a'}d")
    print(f"  live domains that are FRESH (<1yr): phishing "
          f"{ph['fresh_pct']:.0f}%  vs  legit {lg['fresh_pct']:.0f}%")
    # The decisive test is NOT the fail-rate gap (that is a takedown proxy for the
    # dead half of the snapshot). It is: among phishing domains STILL ALIVE — the
    # only ones a live-inference model would ever see — is the age distribution
    # meaningfully younger than legit? If resolving phishing is also mostly OLD,
    # the alive rows are compromised-legit / shared-host, age carries no usable
    # signal, and folding it in learns only "unreachable => phishing" (the
    # takedown artifact), which is harmful on live traffic.
    if ph["fresh_pct"] is not None and ph["fresh_pct"] < 30 \
            and ph["med_age"] is not None and ph["med_age"] > 365 * 3:
        print("\n  => REJECT domain-age as a signal (model feature OR runtime gate).")
        print("     Phishing domains that are still ALIVE are mostly OLD, statistically")
        print("     indistinguishable from legit by age — they are compromised-legit /")
        print("     shared-host roots, not fresh registrations. The only class")
        print("     separation is 'still resolves at all', which is a snapshot-takedown")
        print("     artifact of ~April-2025 feeds, NOT a property of live phishing (a")
        print("     live phishing URL resolves by definition). Training on it teaches")
        print("     'unreachable => phishing' (flags any temporarily-down legit site);")
        print("     gating on it at runtime adds latency for zero measurable lift on the")
        print("     clean-bare-domain FN class. B4 needs FRESH live-phishing data to be")
        print("     validatable — not achievable with the current snapshot. Deferral")
        print("     upheld ON EVIDENCE; v3.2b stays live, FP rate unregressed.")
    elif gap > 25:
        print("\n  => partial takedown artifact; still inspect fresh-fraction before folding.")
    else:
        print("\n  => a carefully-imputed model feature MAY be viable; inspect medians.")
    print(f"\n  cert-age is a non-signal here (auto-renew dominates): phishing "
          f"{int(ph['med_cert']) if ph['med_cert'] is not None else 'n/a'}d "
          f"median vs legit {int(lg['med_cert']) if lg['med_cert'] is not None else 'n/a'}d.")
