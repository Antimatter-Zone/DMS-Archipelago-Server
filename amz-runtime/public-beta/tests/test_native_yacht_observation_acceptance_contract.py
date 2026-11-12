"""Discover the inert acceptance contracts in the existing Linux source lane.

This loads only source-contract tests; it never invokes the actual-image
entrypoint, imports an engine or fabricates native qualification evidence.
"""
import importlib.util
from pathlib import Path

FILE = Path(__file__).resolve().parents[2] / 'public-beta-observations/acceptance/test_qualify_native_context.py'
SPEC = importlib.util.spec_from_file_location('native_yacht_observation_acceptance_contracts', FILE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromModule(MODULE)
