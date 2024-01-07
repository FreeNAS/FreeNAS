import asyncio


async def asyncio_map(func, arguments, limit=None, *, semaphore=None):
    if limit is not None and semaphore is not None:
        raise ValueError("`limit` and `semaphore` can not be specified simultaneously")

    if limit is not None or semaphore is not None:
        if semaphore is None:
            semaphore = asyncio.BoundedSemaphore(limit)

        real_func = func

        async def func(arg):
            async with semaphore:
                return await real_func(arg)

    futures = [func(arg) for arg in arguments]
    return await asyncio.gather(*futures)
