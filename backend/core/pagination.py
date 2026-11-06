from rest_framework.pagination import PageNumberPagination


class StandardPagination(PageNumberPagination):
    """?page= and ?page_size= (1 to 100, default 25), as in api-contract.md section 4.1."""

    page_size = 25
    page_size_query_param = "page_size"
    max_page_size = 100
