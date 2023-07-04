import contextlib

from middlewared.test.integration.utils import call


@contextlib.contextmanager
def replication_task(data):
    task = call("replication.create", data)

    try:
        yield task
    finally:
        call("replication.delete", task["id"])
