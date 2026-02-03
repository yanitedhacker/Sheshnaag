"""
Pagination utilities.

Author: Security Enhancement

Provides reusable pagination logic for API responses.
"""

from typing import TypeVar, Generic, List, Any, Optional
from pydantic import BaseModel, Field

T = TypeVar('T')


class PaginationParams(BaseModel):
    """Pagination parameters."""
    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")

    @property
    def offset(self) -> int:
        """Calculate offset for database query."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Get limit for database query."""
        return self.page_size


class PaginatedResponse(BaseModel):
    """
    Generic paginated response model.

    Can be used as a base for typed paginated responses.
    """
    results: List[Any] = Field(default_factory=list, description="List of items")
    total: int = Field(description="Total number of items")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    total_pages: int = Field(description="Total number of pages")
    has_next: bool = Field(description="Whether there is a next page")
    has_previous: bool = Field(description="Whether there is a previous page")

    @classmethod
    def create(
        cls,
        results: List[Any],
        total: int,
        page: int,
        page_size: int
    ) -> "PaginatedResponse":
        """
        Create a paginated response.

        Args:
            results: List of items for current page
            total: Total number of items across all pages
            page: Current page number (1-indexed)
            page_size: Number of items per page

        Returns:
            PaginatedResponse instance
        """
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0

        return cls(
            results=results,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_previous=page > 1
        )


def calculate_total_pages(total: int, page_size: int) -> int:
    """
    Calculate total number of pages.

    Args:
        total: Total number of items
        page_size: Items per page

    Returns:
        Total number of pages
    """
    if page_size <= 0:
        return 0
    return (total + page_size - 1) // page_size


def calculate_offset(page: int, page_size: int) -> int:
    """
    Calculate offset for database query.

    Args:
        page: Page number (1-indexed)
        page_size: Items per page

    Returns:
        Offset value
    """
    return (max(1, page) - 1) * page_size


def paginate_list(items: List[T], page: int, page_size: int) -> tuple[List[T], int]:
    """
    Paginate an in-memory list.

    Args:
        items: Full list of items
        page: Page number (1-indexed)
        page_size: Items per page

    Returns:
        Tuple of (paginated items, total count)
    """
    total = len(items)
    offset = calculate_offset(page, page_size)
    end = offset + page_size

    return items[offset:end], total


class Paginator:
    """
    Helper class for building paginated queries and responses.

    Usage:
        paginator = Paginator(page=1, page_size=20)
        query = session.query(Model).offset(paginator.offset).limit(paginator.limit)
        total = session.query(Model).count()
        results = query.all()
        return paginator.response(results, total)
    """

    def __init__(self, page: int = 1, page_size: int = 20, max_page_size: int = 100):
        """
        Initialize paginator.

        Args:
            page: Page number (1-indexed)
            page_size: Items per page
            max_page_size: Maximum allowed page size
        """
        self.page = max(1, page)
        self.page_size = min(max(1, page_size), max_page_size)

    @property
    def offset(self) -> int:
        """Get offset for database query."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Get limit for database query."""
        return self.page_size

    def response(self, results: List[Any], total: int) -> dict:
        """
        Build paginated response dictionary.

        Args:
            results: List of items for current page
            total: Total number of items

        Returns:
            Paginated response dictionary
        """
        total_pages = calculate_total_pages(total, self.page_size)

        return {
            "results": results,
            "total": total,
            "page": self.page,
            "page_size": self.page_size,
            "total_pages": total_pages,
            "has_next": self.page < total_pages,
            "has_previous": self.page > 1
        }

    def paginated_response(self, results: List[Any], total: int) -> PaginatedResponse:
        """
        Build PaginatedResponse model.

        Args:
            results: List of items for current page
            total: Total number of items

        Returns:
            PaginatedResponse instance
        """
        return PaginatedResponse.create(
            results=results,
            total=total,
            page=self.page,
            page_size=self.page_size
        )
