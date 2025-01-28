#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
from base64 import b64decode, urlsafe_b64encode
from datetime import date, datetime
from enum import Enum
from json import loads, dumps
from os import fwrite, getcwd, makedirs, path, scandir
import smtplib
import os
import subprocess
import socket
import uuid
from sys import exit, stderr
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# V 0.09
# Stand alone script to send email via Truenas


class ConfigEnum(Enum):
    EMAIL_LOG_DIR_NAME: str = "sendemail_logs"
    BAD_EXIT_CODE: int = 1
    EMAIL_LOG_FILE_NAME_FORMAT: str = "%Y%m%d_%H%M%S"


def log_and_exit(errmsg: str, exit_code: int = ConfigEnum.BAD_EXIT_CODE.value) -> None:
    """Log a `msg` to stderr exiting afterwards"""
    print(errmsg, file=stderr, flush=True)
    exit(exit_code)


def validate_arguments(args: Namespace) -> None:
    """Function to validate command line arguments passed
    to this script."""
    if not args.mail_bulk and not args.mail_body_html:
        log_and_exit(
            "Error: You must provide at least --mail_bulk or --mail_body_html."
        )
    elif args.mail_body_html and (not args.subject or not args.to_address):
        log_and_exit(
            "Error: If --mail_body_html is provided, both --subject and --to_address are required."
        )


def create_log_files_dir() -> str:
    """Create the parent directory where all log files will
    be stored.

    NOTE: The parent directory will be set to whatever directory
    this script is running in."""
    log_files_dir = path.join(getcwd(), ConfigEnum.EMAIL_LOG_DIR_NAME.value)
    try:
        # NOTE: should probably specify mode but also note
        # mode does not get applied if directory already
        # exists, will need to change chmod everytime
        # (i.e. os.chmod(log_files_dir, <mode>))
        makedirs(log_files_dir, exist_ok=True)
    except Exception as e:
        log_and_exit(f"Unexpected failure creating {log_files_dir!r}: {e}")
    return log_files_dir


def remove_old_log_file(
    log_files_dir: str, max_log_file_count: int = 15, log_fd: int | None = None
) -> None:
    """Iterate over `log_files_dir` and keep track of how
    many log files are contained within. If count of log
    files is greater than or equal to `max_log_file_count`,
    then remove the oldest file. The oldest file is based
    off the ctime attribute of the file.

    Args:
        log_files_dir: str absolute path to the directory where
            new log file will be created
        max_log_file_count: int the maximum number of log files
            to be kept before the oldest (based on ctime) will
            be removed
        log_fd: int the open log file file descriptor

    NOTE: Not the best design since iterating over a directory
    can produce crazy results since there is no way to guarantee
    what is in said directory. Proper design would be to write
    last created file to a sqlite database and store the database
    in a known location. Would be vastly more efficient in the
    situation this script is called within a directory that has
    100K+ files (yes, this happens and we (iXsystems) have seen it)."""
    try:
        log_files: list[tuple[str, float]] = list()
        log_files_count = 0
        append_log(f"Scanning {log_file_dir!r} for old files", log_fd=log_fd)
        with scandir(log_files_dir) as sdir:
            for i in filter(lambda x: x.is_file(), sdir):
                if i.name.endswith(".txt"):
                    # TODO: probably need better validation here
                    # other than just checking if file ends with
                    # ".txt" suffix
                    log_files_count += 1
                    log_files.append((i.path, i.stat().st_ctime))
    except Exception as e:
        log_and_exit(f"Unexpected failure enumerating log files: {e}")

    if log_files_count >= max_log_file_count:
        if oldest_entry := min(log_files):
            try:
                append_log(f"Removing old log file {oldest_entry!r}", log_fd=log_fd)
                os.remove(oldest_entry[0])
            except FileNotFoundError:
                # maybe someone (or thing) removed this
                # while this was running, either way, it
                # shouldn't be fatal.
                append_log(f"Old log file {oldest_entry!r} does not exist, ignoring")
                pass
            except Exception as e:
                errmsg = (
                    f"Unexpected failure removing old log file {oldest_entry!r}: {e}"
                )
                append_log(errmsg, log_fd=log_fd)
                log_and_exit(errmsg)


def create_new_log_file(log_files_dir: str) -> tuple[str, int]:
    """Create a new log file in `log_files_dir` ignoring
    an existing log file with the same name (if it exists).

    NOTE: cf. docstring in the `remove_old_log_file` function
    for how to better design this functionality so that this
    function wouldn't need to exist."""
    new_log_file = path.join(
        log_files_dir,
        date.strftime(datetime.now(), ConfigEnum.EMAIL_LOG_FILE_NAME_FORMAT.value),
    )
    try:
        with open(new_log_file, "x"):
            pass
    except FileExistsError:
        pass
    except Exception as e:
        log_and_exit(f"Unexpected failure creating log file {new_log_file!r}: {e}")

    return new_log_file, open(new_log_file, "a+")


def setup_logging() -> tuple[str, int]:
    """Entry point for setting up all things related
    to log file management for this script."""
    log_file_dir = create_log_files_dir()
    log_fd = create_new_log_file(log_file_dir)
    remove_old_log_file(log_file_dir, log_fd=log_fd)
    return log_file_dir, log_fd


def append_log(logmsg: str, log_fd: int, keep_open: bool = True) -> None:
    """Helper function for appending log messages
    to a log file.

    Args:
        logmsg: str the message to append to the log file
        log_fd: int the file descriptor of the open log file
        keep_open: bool if False, will close the log file
    """
    try:
        fwrite(log_fd, f"{logmsg}\n")
    except Exception as e:
        log_and_exit(str(e))


def process_output(error, detail="", exit_code=None):
    """
    Centralized output response
    - error bool detail string exit_code 0 (ok) 1 (ko) or None (ignore)
    """
    response = dumps(
        {
            "error": error,
            "detail": detail,
            "logfile": log_file,
            "total_attach": attachment_count,
            "ok_attach": attachment_ok_count,
        },
        ensure_ascii=False,
    )
    append_log(f"{detail}")
    print(
        response
    )  # caller must intercept this if wanna do something with the result of this process
    if exit_code is not None:
        exit(exit_code)


def read_config_data():
    """
    function for read the mail.config from midclt
    """
    append_log("trying read mail.config")
    midclt_output = subprocess.run(
        ["midclt", "call", "mail.config"], capture_output=True, text=True
    )
    if midclt_output.returncode != 0:
        process_output(
            True, f"Failed to call midclt: {midclt_output.stderr.strip()}", 1
        )

    append_log("read mail.config successfully")
    midclt_config = loads(midclt_output.stdout)
    return midclt_config


def load_html_content(input_content):
    """
    use this fuction to switch from achieve nor a file to read and a plain text/html
    """
    try:
        if len(input_content) > 255:
            append_log("body can't be a file, too much long")
            return input_content
        elif os.path.exists(input_content):
            with open(input_content, "r") as f:
                append_log("body is a file")
                return f.read()
        else:
            append_log("no file found, plain text/html output")
            return input_content
    except Exception as e:
        process_output(True, f"Something wrong on body content {e}", 1)


def validate_base64_content(input_content):
    """
    use this funtcion to validate that an input is base64encoded. Return error if not
    """
    try:
        b64decode(input_content, validate=True)
        append_log("Base64 message is valid.")
    except Exception as e:
        process_output(True, f"Error: Invalid Base64 content. {e}", 1)


def calc_attachment_count(attachment_input):
    """
    improved attachments output
    """
    total_attachments = len(attachment_input) if attachment_input else 0
    return total_attachments


def attach_files(msg, attachment_files, attachment_ok_count):
    """
    Function to attach files!
    """
    for attachment_file in attachment_files:
        try:
            with open(attachment_file, "rb") as f:
                file_data = f.read()
                part = MIMEBase("application", "octet-stream")
                part.set_payload(file_data)
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{attachment_file.split("/")[-1]}"',
                )
                msg.attach(part)
                attachment_ok_count += 1
                append_log(f"OK {attachment_file}")

        except Exception as e:
            append_log(f"KO {attachment_file}: {e}")
    return attachment_ok_count


def getMRconfigvalue(key):
    """
    Function to get eventually multi report value from config, passing the key > the name of the setting
    """
    config_file = "multi_report_config.txt"  # default

    if not os.path.exists(config_file):
        append_log(f"{config_file} not found")
        return ""

    try:
        with open(config_file, "r") as file:
            for line in file:
                line = line.strip()
                key_value_pair, _, comment = line.partition(
                    "#"
                )  # necessary to not get dirty values
                key_value_pair = key_value_pair.strip()

                if key_value_pair.startswith(key + "="):
                    append_log(f"{key} found")
                    value = key_value_pair.split("=")[1].strip().strip('"')
                    return value
    except Exception as e:
        append_log(f"{config_file} not found. {e}")
        return ""

    return ""


def send_email(
    subject,
    to_address,
    mail_body_html,
    attachment_files,
    email_config,
    provider,
    bulk_email,
):
    """
    Function to send an email via SMTP or Gmail OAuth based on the provider available
    """
    attachment_ok_count = 0
    if provider == "smtp":  # smtp version
        try:
            append_log("parsing smtp config")
            smtp_security = email_config["security"]
            smtp_server = email_config["outgoingserver"]
            smtp_port = email_config["port"]
            smtp_user = email_config["user"]
            smtp_password = email_config["pass"]
            smtp_fromemail = email_config["fromemail"]
            smtp_fromname = email_config["fromname"]

            append_log("switch from classic send and bulk email")
            if mail_body_html:
                append_log("mail hmtl provided")
                append_log("parsing html content")
                html_content = load_html_content(mail_body_html)

                append_log("start parsing headers")
                msg = MIMEMultipart()
                append_log("parsing data from config")
                if smtp_fromname:
                    msg["From"] = f"{smtp_fromname} <{smtp_fromemail}>"
                    append_log(f"using fromname {smtp_fromname}")
                else:
                    msg["From"] = smtp_fromemail
                    append_log(f"using fromemail {smtp_fromemail}")
                msg["To"] = to_address
                msg["Subject"] = subject
                msg.attach(MIMEText(html_content, "html"))

                append_log(f"generate a message ID using {smtp_user}")
                try:
                    messageid_domain = smtp_user.split("@")[1]
                except Exception:
                    append_log(
                        f"{smtp_user} not a valid address, tryng on {smtp_fromemail}"
                    )
                    try:
                        messageid_domain = smtp_fromemail.split("@")[1]
                    except Exception:
                        append_log(
                            f"{smtp_fromemail} not a valid address, need to use a fallback "
                        )
                        messageid_domain = "local.me"
                append_log(f"domain: {messageid_domain}")
                messageid_uuid = f"{datetime.now().strftime('%Y_%m_%d_%H_%M_%S_%f')[:-3]}{uuid.uuid4()}"
                append_log(f"uuid: {messageid_uuid}")
                messageid = f"<{messageid_uuid}@{messageid_domain}>"
                append_log(f"messageid: {messageid}")
                msg["Message-ID"] = messageid
                msg["Date"] = formatdate(localtime=True)

                append_log("check for attachements...")
                if attachment_files:
                    append_log("attachments found")
                    attachment_ok_count = attach_files(
                        msg, attachment_files, attachment_ok_count
                    )
                    append_log(f"{attachment_ok_count} ok attachments")

                append_log("get hostname")
                hostname = socket.getfqdn()
                if not hostname:
                    hostname = socket.gethostname()
                append_log(f"hostname retrieved: {hostname}")

            elif bulk_email:
                append_log("using bulk email provided")
                msg = load_html_content(bulk_email)
                validate_base64_content(msg)
            else:
                process_output(True, "Something wrong with the data input", 1)

            append_log(
                f"establing connection based on security level set on TN: {smtp_security}"
            )
            if smtp_security == "TLS":
                with smtplib.SMTP(smtp_server, smtp_port) as server:
                    append_log(f"entered {smtp_security} path")
                    # server.set_debuglevel(1)  #### this line can be uncommented if more debug is needed
                    append_log("adding ehlo to the message")
                    server.ehlo(hostname)
                    append_log("establing TLS connection")
                    server.starttls()
                    append_log("entering credentials")
                    server.login(smtp_user, smtp_password)
                    append_log(f"sending {smtp_security} email")
                    server.sendmail(smtp_user, to_address, msg.as_string())
            elif smtp_security == "SSL":
                with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                    append_log(f"entered {smtp_security} path")
                    # server.set_debuglevel(1)  #### this line can be uncommented if more debug is needed
                    append_log("adding ehlo to the message")
                    server.ehlo(hostname)
                    append_log("entering credentials")
                    server.login(smtp_user, smtp_password)
                    append_log(f"sending {smtp_security} email")
                    server.sendmail(smtp_user, to_address, msg.as_string())
            elif smtp_security == "PLAIN":
                with smtplib.SMTP(smtp_server, smtp_port) as server:
                    append_log(f"entered {smtp_security} path")
                    # server.set_debuglevel(1)  #### this line can be uncommented if more debug is needed
                    append_log("adding ehlo to the message")
                    server.ehlo(hostname)
                    append_log("entering credentials")
                    server.login(smtp_user, smtp_password)
                    append_log(f"sending {smtp_security} email")
                    server.sendmail(smtp_user, to_address, msg.as_string())
            else:
                process_output(
                    True, "KO: something wrong switching SMTP security level", 1
                )

            append_log("Email Sent via SMTP")

        except Exception as e:
            process_output(True, f"KO: {e}", 1)

    elif provider == "gmail":  # gmail version
        try:
            append_log("parsing Oauth config")
            credentials = Credentials.from_authorized_user_info(email_config["oauth"])
            service = build("gmail", "v1", credentials=credentials)

            append_log("switch from classic send and bulk email")
            if mail_body_html:
                append_log("mail hmtl provided")
                append_log("start parsing headers")
                msg = MIMEMultipart()
                append_log("parsing data from config")
                fallback_fromname = getMRconfigvalue(
                    "FromName"
                )  # we need a FromName setting into mr config
                fallback_fromemail = getMRconfigvalue("From")

                if fallback_fromname and fallback_fromemail:
                    msg["From"] = f"{fallback_fromname} <{fallback_fromemail}>"
                    append_log("using fallback fromname")
                elif fallback_fromemail:
                    msg["From"] = fallback_fromemail
                    append_log("using fallback fromemail")
                else:
                    append_log(
                        "can't find a from setting. Gmail will apply the default"
                    )

                msg["to"] = to_address
                msg["subject"] = subject

                append_log("parsing html content")
                html_content = load_html_content(mail_body_html)
                msg.attach(MIMEText(html_content, "html"))

                append_log("check for attachements...")
                if attachment_files:
                    append_log("attachments found")
                    attachment_ok_count = attach_files(
                        msg, attachment_files, attachment_ok_count
                    )
                    append_log(f"{attachment_ok_count} ok attachments")

                append_log("Encoding message")
                raw_message = msg.as_bytes()
                msg = urlsafe_b64encode(raw_message).decode("utf-8")

            elif bulk_email:
                append_log("using bulk email provided")
                msg = load_html_content(bulk_email)
                validate_base64_content(msg)
            else:
                process_output(True, "Something wrong with the data input", 1)

            append_log("sending email")
            service.users().messages().send(userId="me", body={"raw": msg}).execute()
            append_log("Email Sent via Gmail")
            return attachment_ok_count

        except Exception as e:
            process_output(True, f"KO: {e}", 1)

    else:
        process_output(True, "No valid email configuration found.", 1)


def setup_args() -> Namespace:
    """Setup arguments for this script."""
    parser = ArgumentParser(
        description="Workaround to send email easily in Multi Report"
    )
    parser.add_argument("--subject", help="Email subject")
    parser.add_argument("--to_address", help="Recipient")
    parser.add_argument(
        "--mail_body_html",
        help="File path for the email body, or just a plain text/html",
    )
    parser.add_argument(
        "--attachment_files",
        nargs="*",
        help="OPTIONAL attachments as json file path array. No encoding needed",
    )
    parser.add_argument(
        "--mail_bulk",
        help="Bulk email with all necessary parts, encoded and combined. File path or plain text supported",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = setup_args()
    validate_arguments(args)
    log_file_dir, log_fd = setup_logging()

    try:
        attachment_count = calc_attachment_count(args.attachment_files)
        attachment_ok_count = 0  # avoid error if except are raised
        append_log(f"Total attachments: {attachment_count}")

        email_config = read_config_data()
        append_log("Switching for the right provider")
        provider = ""
        if (
            "smtp" in email_config
            and email_config["smtp"]
            and not email_config.get("oauth")
        ):
            provider = "smtp"
            append_log("** SMTP Version **")
        elif "oauth" in email_config and email_config["oauth"]:
            provider = "gmail"
            append_log("** Gmail OAuth version **")
        else:
            process_output(True, "Can't switch provider", 1)

        attachment_ok_count = send_email(
            args.subject,
            args.to_address,
            args.mail_body_html,
            args.attachment_files,
            email_config,
            provider,
            args.mail_bulk,
        )

        if attachment_ok_count is None:
            attachment_ok_count = 0

        if attachment_ok_count == attachment_count:
            process_output(False, ">> All is Good <<", 0)
        else:
            process_output(
                False,
                ">> Soft warning: something wrong with 1 or more attachments, check logs for more info >>",
                0,
            )
    except Exception as e:
        process_output(True, f"Error: {e}", 1)
