from __future__ import annotations

from typing import Annotated

from fastapi import Path, Query

# PostgreSQL integer columns hold at most this; a larger value bound to one is
# a database error, so every identifier and number a route reads is bounded
# here and refused as a validation error instead.
DB_INT_MAX = 2**31 - 1
DbId = Annotated[int, Path(ge=1, le=DB_INT_MAX)]
PageLimit = Annotated[int, Query(ge=1, le=200)]
PageOffset = Annotated[int, Query(ge=0, le=1_000_000)]
OptionalDbId = Annotated[int | None, Query(ge=1, le=DB_INT_MAX)]
QueryDbId = Annotated[int, Query(ge=1, le=DB_INT_MAX)]
# A search term: long enough for any name the catalogue holds.
SearchText = Annotated[str | None, Query(max_length=200)]
