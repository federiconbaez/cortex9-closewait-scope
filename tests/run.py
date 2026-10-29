"""Corre la suite. Un test salteado hace fallar la corrida (un skip silencioso es una falla)."""
import sys
import unittest

suite = unittest.defaultTestLoader.discover("tests", pattern="test_*.py", top_level_dir=".")
res = unittest.TextTestRunner(verbosity=2).run(suite)
print(f"RESUMEN tests={res.testsRun} fallas={len(res.failures)} errores={len(res.errors)} salteados={len(res.skipped)}")
if res.skipped:
    print("ERROR: hay tests salteados; se trata como falla")
sys.exit(0 if res.wasSuccessful() and not res.skipped else 1)
