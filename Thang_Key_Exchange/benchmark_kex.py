"""Small reproducible benchmark for ECDH and ML-KEM key establishment."""

from __future__ import annotations

import argparse
import csv
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

from classical_kex import derive_shared_secret, generate_keypair, key_sizes
from ml_kem import MLKEM, available_variants


def time_ms(operation: Callable[[], object], repeats: int) -> tuple[float, float]:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    mean = statistics.fmean(samples)
    stdev = statistics.stdev(samples) if repeats > 1 else 0.0
    return mean, stdev


def benchmark_ecdh(repeats: int) -> list[dict[str, object]]:
    alice = generate_keypair("P-256")
    bob = generate_keypair("P-256")
    keygen_mean, keygen_sd = time_ms(lambda: generate_keypair("P-256"), repeats)
    agreement_mean, agreement_sd = time_ms(
        lambda: derive_shared_secret(alice.private_key, bob.public_key, "P-256"),
        repeats,
    )
    sizes = key_sizes("P-256")
    return [
        {
            "algorithm": "ECDH-P-256",
            "operation": "KeyGen",
            "mean_ms": keygen_mean,
            "stdev_ms": keygen_sd,
            "public_key_bytes": sizes["public_key"],
            "private_key_bytes": sizes["private_key"],
            "ciphertext_bytes": 0,
            "shared_secret_bytes": sizes["shared_secret"],
        },
        {
            "algorithm": "ECDH-P-256",
            "operation": "KeyAgreement",
            "mean_ms": agreement_mean,
            "stdev_ms": agreement_sd,
            "public_key_bytes": sizes["public_key"],
            "private_key_bytes": sizes["private_key"],
            "ciphertext_bytes": 0,
            "shared_secret_bytes": sizes["shared_secret"],
        },
    ]


def benchmark_ml_kem(repeats: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for variant in available_variants():
        kem = MLKEM(variant)
        keypair = kem.keygen()
        encapsulation = kem.encapsulate(keypair.public_key)
        keygen_mean, keygen_sd = time_ms(kem.keygen, repeats)
        encaps_mean, encaps_sd = time_ms(lambda: kem.encapsulate(keypair.public_key), repeats)
        decaps_mean, decaps_sd = time_ms(
            lambda: kem.decapsulate(keypair.private_key, encapsulation.ciphertext),
            repeats,
        )
        sizes = kem.sizes()
        for operation, mean, stdev in (
            ("KeyGen", keygen_mean, keygen_sd),
            ("Encaps", encaps_mean, encaps_sd),
            ("Decaps", decaps_mean, decaps_sd),
        ):
            rows.append(
                {
                    "algorithm": variant,
                    "operation": operation,
                    "mean_ms": mean,
                    "stdev_ms": stdev,
                    "public_key_bytes": sizes["public_key"],
                    "private_key_bytes": sizes["private_key"],
                    "ciphertext_bytes": sizes["ciphertext"],
                    "shared_secret_bytes": sizes["shared_secret"],
                }
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10, help="Number of repetitions per operation (default: 10)")
    parser.add_argument("--output", type=Path, default=Path("benchmark_kex.csv"), help="CSV output path")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be at least 1")

    rows = benchmark_ecdh(args.repeats) + benchmark_ml_kem(args.repeats)
    metadata = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "repeats": args.repeats,
    }
    fieldnames = list(rows[0]) + ["python", "platform", "processor", "repeats"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, **metadata})

    print(f"Wrote {len(rows)} benchmark rows to {args.output}")
    for row in rows:
        print(
            f"{row['algorithm']:>12} {row['operation']:<12} "
            f"{row['mean_ms']:9.3f} ms ± {row['stdev_ms']:.3f}"
        )


if __name__ == "__main__":
    main()
