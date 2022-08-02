import datetime
import time

from CTFd.utils import get_config


def ctftime():
    """ Checks whether it's CTF time or not. """

    start = get_config("start")
    end = get_config("end")

    start = int(start) if start else 0
    end = int(end) if end else 0
    if start and end and start < time.time() < end:
        # Within the two time bounds
        return True

    if start < time.time() and end == 0:
        # CTF starts on a date but never ends
        return True

    return True if start == 0 and time.time() < end else start == 0 and end == 0


def ctf_paused():
    return bool(get_config("paused"))


def ctf_started():
    return time.time() > int(get_config("start") or 0)


def ctf_ended():
    if int(get_config("end") or 0):
        return time.time() > int(get_config("end") or 0)
    return False


def view_after_ctf():
    return get_config("view_after_ctf")


def unix_time(dt):
    return int((dt - datetime.datetime(1970, 1, 1)).total_seconds())


def unix_time_millis(dt):
    return unix_time(dt) * 1000


def unix_time_to_utc(t):
    return datetime.datetime.utcfromtimestamp(t)


def isoformat(dt):
    return f"{dt.isoformat()}Z"
