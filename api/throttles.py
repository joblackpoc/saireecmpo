"""
Custom throttling classes for API rate limiting.
"""

from rest_framework.throttling import UserRateThrottle, AnonRateThrottle


class BurstRateThrottle(UserRateThrottle):
    """
    Throttle for burst requests (short-term limit).
    """
    scope = 'burst'
    rate = '60/min'


class SustainedRateThrottle(UserRateThrottle):
    """
    Throttle for sustained requests (long-term limit).
    """
    scope = 'sustained'
    rate = '1000/hour'


class AuthRateThrottle(AnonRateThrottle):
    """
    Stricter throttle for authentication endpoints.
    """
    scope = 'auth'
    rate = '5/hour'


class SearchRateThrottle(UserRateThrottle):
    """
    Throttle for search endpoints.
    """
    scope = 'search'
    rate = '30/min'