import os


BACKUP_NAME_PREFIX = 'ix-apps-backup-'


def applications_ds_name(pool: str) -> str:
    return os.path.join(pool, 'ix-apps')
