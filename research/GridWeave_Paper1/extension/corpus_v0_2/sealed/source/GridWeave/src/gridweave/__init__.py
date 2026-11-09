"""GridWeave: reproducible, oracle-separated datasets for VERCLO."""

__version__ = "0.2.1"


def generate(*args, **kwargs):
    from .dataset import generate
    return generate(*args, **kwargs)


def validate(*args, **kwargs):
    from .dataset import validate
    return validate(*args, **kwargs)


def run(*args, **kwargs):
    from .dataset import run
    return run(*args, **kwargs)
