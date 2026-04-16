from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionMaker


async def get_db() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionMaker() as session:
        yield session
