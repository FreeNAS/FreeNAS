from contextlib import suppress
from logging import getLogger
from pathlib import Path

from libsg3.ses import EnclosureDevice
from .enclosure_class import Enclosure

logger = getLogger(__name__)


def get_ses_enclosure_status(bsg_path):
    try:
        return EnclosureDevice(bsg_path).status()
    except OSError:
        logger.error('Error querying enclosure status for %r', bsg_path, exc_info=True)


def get_ses_enclosures(dmi):
    rv = list()
    with suppress(FileNotFoundError):
        for i in Path('/sys/class/enclosure').iterdir():
            bsg = f'/dev/bsg/{i.name}'
            if (status := get_ses_enclosure_status(bsg)):
                sg = next((i / 'device/scsi_generic').iterdir())
                rv.append(Enclosure(bsg, f'/dev/{sg.name}', dmi, status).asdict())

    return rv
