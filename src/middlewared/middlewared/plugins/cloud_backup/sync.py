import asyncio
from datetime import datetime
import itertools
import subprocess

from middlewared.plugins.cloud.path import get_remote_path, check_local_path
from middlewared.plugins.cloud.remotes import REMOTES
from middlewared.plugins.zfs_.utils import zvol_name_to_path, zvol_path_to_name
from middlewared.schema import accepts, Bool, Dict, Int
from middlewared.service import CallError, Service, item_method, job, private
from middlewared.utils import Popen


async def restic(middleware, job, cloud_backup, dry_run):
    await middleware.call("network.general.will_perform_activity", "cloud_backup")

    remote = REMOTES[cloud_backup["credentials"]["provider"]]

    snapshot = None
    clone = None
    stdin = None
    cmd = None
    try:
        local_path = cloud_backup["path"]
        if local_path.startswith("/dev/zvol"):
            await middleware.call("cloud_backup.validate_zvol", local_path)

            name = f"cloud_backup-{cloud_backup.get('id', 'onetime')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            snapshot = (await middleware.call("zfs.snapshot.create", {
                "dataset": zvol_path_to_name(local_path),
                "name": name,
                "suspend_vms": True,
                "vmware_sync": True,
            }))["name"]

            clone = zvol_path_to_name(local_path) + f"-{name}"
            try:
                await middleware.call("zfs.snapshot.clone", {
                    "snapshot": snapshot,
                    "dataset_dst": clone,
                })
            except Exception:
                clone = None
                raise

            # zvol device might take a while to appear
            for i in itertools.count():
                try:
                    stdin = await middleware.run_in_thread(open, zvol_name_to_path(clone), "rb")
                except FileNotFoundError:
                    if i >= 5:
                        raise

                    await asyncio.sleep(1)
                else:
                    break

            cmd = ["--stdin", "--stdin-filename", "volume"]
        else:
            await check_local_path(middleware, local_path)

        if cmd is None:
            cmd = [local_path]

        remote_path = get_remote_path(remote, cloud_backup["attributes"])

        url, env = remote.get_restic_config(cloud_backup)

        cmd = ["restic", "-r", f"{remote.rclone_type}:{url}/{remote_path}", "--verbose", "backup"] + cmd
        if dry_run:
            cmd.append("-n")

        env["RESTIC_PASSWORD"] = cloud_backup["password"]

        job.middleware.logger.debug("Running %r", cmd)
        proc = await Popen(
            cmd,
            env=env,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        check_progress = asyncio.ensure_future(restic_check_progress(job, proc))
        cancelled_error = None
        try:
            try:
                await proc.wait()
            except asyncio.CancelledError as e:
                cancelled_error = e
                try:
                    await middleware.call("service.terminate_process", proc.pid)
                except CallError as e:
                    job.middleware.logger.warning(f"Error terminating restic on cloud backup abort: {e!r}")
        finally:
            await asyncio.wait_for(check_progress, None)

        if cancelled_error is not None:
            raise cancelled_error
        if proc.returncode != 0:
            message = "".join(job.internal_data.get("messages", []))
            if message and proc.returncode != 1:
                if not message.endswith("\n"):
                    message += "\n"
                message += f"restic failed with exit code {proc.returncode}"
            raise CallError(message)
    finally:
        if stdin:
            try:
                stdin.close()
            except Exception as e:
                middleware.logger.warning(f"Error closing snapshot device: {e!r}")

        if clone is not None:
            try:
                await middleware.call("zfs.dataset.delete", clone)
            except Exception as e:
                middleware.logger.warning(f"Error deleting cloned dataset {clone}: {e!r}")

        if snapshot is not None:
            try:
                await middleware.call("zfs.snapshot.delete", snapshot)
            except Exception as e:
                middleware.logger.warning(f"Error deleting snapshot {snapshot}: {e!r}")


async def restic_check_progress(job, proc):
    try:
        while True:
            read = (await proc.stdout.readline()).decode("utf-8", "ignore")
            if read == "":
                break

            await job.logs_fd_write(read.encode("utf-8", "ignore"))

            job.internal_data.setdefault("messages", [])
            job.internal_data["messages"] = job.internal_data["messages"][-4:] + [read]
    finally:
        pass


class CloudBackupService(Service):

    class Config:
        cli_namespace = "task.cloud_backup"
        namespace = "cloud_backup"

    @item_method
    @accepts(Int("id"))
    @job()
    def init(self, job_id, id_):
        """
        Initializes the repository for the cloud backup job `id`.
        """
        self.middleware.call_sync("network.general.will_perform_activity", "cloud_backup")

        cloud_backup = self.middleware.call_sync("cloud_backup.get_instance", id_)

        remote = REMOTES[cloud_backup["credentials"]["provider"]]

        remote_path = get_remote_path(remote, cloud_backup["attributes"])

        url, env = remote.get_restic_config(cloud_backup)

        try:
            subprocess.run([
                "restic", "init", "-r", f"{remote.rclone_type}:{url}/{remote_path}",
            ], env={
                "RESTIC_PASSWORD": cloud_backup["password"],
                **env,
            }, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            raise CallError(e.stderr)

    @item_method
    @accepts(
        Int("id"),
        Dict(
            "cloud_backup_sync_options",
            Bool("dry_run", default=False),
            register=True,
        )
    )
    @job(lock=lambda args: "cloud_backup:{}".format(args[-1]), lock_queue_size=1, logs=True, abortable=True)
    async def sync(self, job, id_, options):
        """
        Run the cloud backup job `id`.
        """

        cloud_backup = await self.middleware.call("cloud_backup.get_instance", id_)
        if cloud_backup["locked"]:
            await self.middleware.call("cloud_backup.generate_locked_alert", id_)
            raise CallError("Dataset is locked")

        await self._sync(cloud_backup, options, job)

    async def _sync(self, cloud_backup, options, job):
        job.set_progress(0, "Starting")
        try:
            await restic(self.middleware, job, cloud_backup, options["dry_run"])

            if "id" in cloud_backup:
                await self.middleware.call("alert.oneshot_delete", "CloudBackupTaskFailed", cloud_backup["id"])
        except Exception:
            if "id" in cloud_backup:
                await self.middleware.call("alert.oneshot_create", "CloudBackupTaskFailed", {
                    "id": cloud_backup["id"],
                    "name": cloud_backup["description"],
                })
            raise

    @item_method
    @accepts(Int("id"))
    async def abort(self, id_):
        """
        Aborts cloud backup task.
        """
        cloud_backup = await self.middleware.call("cloud_backup.get_instance", id_)

        if cloud_backup["job"] is None:
            return False

        if cloud_backup["job"]["state"] not in ["WAITING", "RUNNING"]:
            return False

        await self.middleware.call("core.job_abort", cloud_backup["job"]["id"])
        return True

    @private
    async def validate_zvol(self, path):
        dataset = zvol_path_to_name(path)
        if not (
            await self.middleware.call("vm.query_snapshot_begin", dataset, False) or
            await self.middleware.call("vmware.dataset_has_vms", dataset, False)
        ):
            raise CallError("Backed up zvol must be used by a local or VMware VM")
