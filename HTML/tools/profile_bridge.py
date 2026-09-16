#!/usr/bin/python3
"""Validate with the existing controller without importing its SDE hardware dependencies."""
import importlib.util
import json
import os
import sys
import types

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
base = types.ModuleType('bfruntime_client_base_tests')
base.BfRuntimeTest = type('BfRuntimeTest', (), {})
sys.modules[base.__name__] = base
pkg = types.ModuleType('bfrt_grpc')
pkg.__path__ = []
sys.modules[pkg.__name__] = pkg
pkg.client = types.ModuleType('bfrt_grpc.client')
sys.modules['bfrt_grpc.client'] = pkg.client
spec = importlib.util.spec_from_file_location('source', os.path.join(root, '..', 'test_nmap', 'test.py'))
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
try:
    value = legacy.validate_fingerprint(json.load(sys.stdin))
    if not isinstance(value.get('OS'), str) or not 1 <= len(value['OS']) <= 160:
        raise ValueError('OS must be a nonempty name, at most 160 characters')
    print(json.dumps({'ok': True, 'value': value}))
except Exception as error:
    print(json.dumps({'ok': False, 'error': str(error)}))
    sys.exit(1)
