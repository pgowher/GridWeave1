"""Catalog, data-object, replica, and custody generation."""

from .builder import (
    CatalogBuild,
    CatalogBuildError,
    CatalogDiagnostics,
    CustodyEdge,
    REQUIRED_OBJECT_TYPES,
    REQUIRED_REPLICA_ROLES,
    build_catalog,
    validate_catalog,
)

__all__ = [
    "CatalogBuild",
    "CatalogBuildError",
    "CatalogDiagnostics",
    "CustodyEdge",
    "REQUIRED_OBJECT_TYPES",
    "REQUIRED_REPLICA_ROLES",
    "build_catalog",
    "validate_catalog",
]
