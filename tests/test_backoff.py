"""Reconnect backoff: 1/2/4/8/16/30 s, ±20 % jitter, capped."""

import unittest

import _support  # noqa: F401
from omclip import backoff


class Backoff(unittest.TestCase):
    def test_sequence(self):
        self.assertEqual(backoff.sequence(8), [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0, 30.0])

    def test_starts_at_one_second_and_doubles(self):
        self.assertEqual([backoff.base_delay(i) for i in range(5)], [1, 2, 4, 8, 16])

    def test_capped_at_thirty(self):
        for attempt in (5, 6, 50, 10 ** 6):
            self.assertEqual(backoff.base_delay(attempt), 30.0)

    def test_negative_attempt_is_zero(self):
        self.assertEqual(backoff.base_delay(-3), 1.0)

    def test_jitter_bounds(self):
        # rand() == 0 → -20 %, rand() → 1 → +20 %.
        self.assertAlmostEqual(backoff.delay(0, rand=lambda: 0.0), 0.8)
        self.assertAlmostEqual(backoff.delay(0, rand=lambda: 0.5), 1.0)
        self.assertAlmostEqual(backoff.delay(0, rand=lambda: 0.999999), 1.2, places=4)
        self.assertAlmostEqual(backoff.delay(5, rand=lambda: 0.0), 24.0)

    def test_jitter_never_exceeds_twenty_percent(self):
        values = [backoff.delay(3, rand=lambda i=i / 100.0: i) for i in range(101)]
        base = backoff.base_delay(3)
        self.assertGreaterEqual(min(values), base * 0.8 - 1e-9)
        self.assertLessEqual(max(values), base * 1.2 + 1e-9)

    def test_real_random_stays_in_band(self):
        for _ in range(200):
            value = backoff.delay(2)
            self.assertGreaterEqual(value, 4 * 0.8)
            self.assertLessEqual(value, 4 * 1.2)


if __name__ == "__main__":
    unittest.main()
