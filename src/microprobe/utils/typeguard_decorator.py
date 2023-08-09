import sys
from typing import Any

def typeguard_testsuite(dec: Any) -> Any:
    """Only perform runtime type checking when running testsuite"""
    if 'unittest' in sys.modules.keys():
        # running in testsuite, enable runtime type checking
        import typeguard
        return typeguard.typechecked(dec)

    return dec
