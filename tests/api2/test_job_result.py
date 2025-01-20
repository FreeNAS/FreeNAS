from middlewared.test.integration.utils import call, mock


def test_job_result():

    with mock("test.test1", """
        from middlewared.service import job
        from middlewared.schema import returns, Password

        @job()
        @returns(Password("my_password"))
        def mock(self, job, *args):
            return "canary"
    """):
        job_id = call("test.test1")

        result = call("core.job_wait", job_id, job=True)
        # Waiting for result should give unredacted version
        assert result == "canary"

        # Querying by default should redact
        job = call("core.get_jobs", [["id", "=", job_id]], {"get": True})
        assert job["result"] == "********"

        # but we should also be able to get unredacted result if needed
        job = call("core.get_jobs", [["id", "=", job_id]], {"get": True, "extra": {"raw_result": True}})
        assert job["result"] == "canary"
