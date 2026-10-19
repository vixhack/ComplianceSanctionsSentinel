import os
import sys
import importlib.util
import importlib.machinery
import pytest

# 1. GenLayer stdlib finder redirection
GENLAYER_STD_PATH = os.path.expanduser(
    r"~/.cache/gltest-direct/extracted/v0.2.16/py-lib-genlayer-std/11rhn002yfajawsz7fai6mykznbxkxs6l91iskj5cm82c92qhy3v"
)

if os.path.exists(GENLAYER_STD_PATH):
    class GenLayerFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path, target=None):
            if fullname == "genlayer" or fullname.startswith("genlayer."):
                rel_parts = fullname.split(".")
                target_dir = os.path.join(GENLAYER_STD_PATH, *rel_parts)
                init_file = os.path.join(target_dir, "__init__.py")
                if os.path.isdir(target_dir) and os.path.isfile(init_file):
                    return importlib.machinery.PathFinder.find_spec(fullname, [os.path.dirname(target_dir)])
                py_file = target_dir + ".py"
                if os.path.isfile(py_file):
                    return importlib.machinery.PathFinder.find_spec(fullname, [os.path.dirname(target_dir)])
            return None

    if not any(isinstance(f, GenLayerFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, GenLayerFinder())


# 2. Windows fd lock workaround for Direct Mode loader
_real_unlink = os.unlink

def _safe_unlink(path, *args, **kwargs):
    try:
        _real_unlink(path, *args, **kwargs)
    except PermissionError:
        pass

os.unlink = _safe_unlink


# 3. Reset known contract registry to avoid duplicate class registration in pytest
@pytest.fixture(autouse=True)
def reset_contract_registry():
    yield
    try:
        import genlayer.gl.genvm_contracts as gc
        gc.__known_contract__ = None
    except Exception:
        pass
