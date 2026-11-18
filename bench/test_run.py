#!/usr/bin/env python3
"""Unit tests for benchmark bookkeeping; no servers or network access required."""
import importlib.util
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("bench_run", pathlib.Path(__file__).with_name("run.py"))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class BenchmarkTests(unittest.TestCase):
    def test_eight_cpu_scenarios(self):
        self.assertEqual(bench.BENCH_CPUS, 8)
        self.assertNotIn("native-16x4", bench.SCENARIOS)
        self.assertTrue(all(s["client"]["procs"] <= 8 for s in bench.SCENARIOS.values()))

    def test_run_order_balances_slots(self):
        servers = list(range(6))
        orders = [bench.run_order(servers, i) for i in range(12)]
        for server in servers:
            for slot in range(6):
                self.assertEqual(sum(order[slot] == server for order in orders), 2)

    def test_measurement_intervals(self):
        self.assertTrue(bench.measurement_interval_ok(10, 10.0, 10.1))
        self.assertFalse(bench.measurement_interval_ok(10, 7.868, 10.0))
        self.assertFalse(bench.measurement_interval_ok(10, 10.0, 20.0))
        self.assertFalse(bench.measurement_interval_ok(10, 12.1, 12.1))

    def test_memory_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            for name, value in {
                "memory.current": "1000\n", "memory.high": "max\n", "memory.max": "4096\n",
                "memory.stat": "anon 50\nsock 125\n", "memory.events": "low 0\nhigh 2\n",
                "memory.pressure": "some avg10=0.00 total=100\nfull avg10=0.00 total=50\n",
            }.items():
                (root / name).write_text(value)
            old = bench.BENCH_MEMORY_CGROUP
            try:
                bench.BENCH_MEMORY_CGROUP = root
                self.assertEqual(bench.memory_snapshot(), {
                    "current": 1000, "high_limit": None, "max_limit": 4096,
                    "sock": 125, "high_events": 2, "full_us": 50,
                })
                (root / "memory.current").unlink()
                self.assertIsNone(bench.memory_snapshot())
            finally:
                bench.BENCH_MEMORY_CGROUP = old


if __name__ == "__main__":
    unittest.main()
