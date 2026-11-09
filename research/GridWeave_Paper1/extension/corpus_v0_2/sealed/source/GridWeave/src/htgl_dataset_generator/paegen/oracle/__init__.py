"""Privileged PaEGen oracle surface; never import from observer-facing code."""

from .builder import build_ground_truth_artifact

__all__ = ["build_ground_truth_artifact"]

