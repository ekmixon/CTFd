import datetime
import re

from flask import abort
from flask import current_app as app
from flask import redirect, request, session, url_for

from CTFd.cache import cache
from CTFd.constants.teams import TeamAttrs
from CTFd.constants.users import UserAttrs
from CTFd.models import Fails, Teams, Tracking, Users, db
from CTFd.utils import get_config
from CTFd.utils.security.auth import logout_user
from CTFd.utils.security.signing import hmac


def get_current_user():
    if not authed():
        return None
    user = Users.query.filter_by(id=session["id"]).first()

    if session_hash := session.get("hash"):
        if session_hash != hmac(user.password):
            logout_user()
            if request.content_type == "application/json":
                error = 401
            else:
                error = redirect(url_for("auth.login", next=request.full_path))
            abort(error)

    return user


def get_current_user_attrs():
    return get_user_attrs(user_id=session["id"]) if authed() else None


@cache.memoize(timeout=300)
def get_user_attrs(user_id):
    if user := Users.query.filter_by(id=user_id).first():
        d = {field: getattr(user, field) for field in UserAttrs._fields}
        return UserAttrs(**d)
    return None


@cache.memoize(timeout=300)
def get_user_place(user_id):
    if user := Users.query.filter_by(id=user_id).first():
        return user.account.place
    return None


@cache.memoize(timeout=300)
def get_user_score(user_id):
    if user := Users.query.filter_by(id=user_id).first():
        return user.account.score
    return None


@cache.memoize(timeout=300)
def get_team_place(team_id):
    if team := Teams.query.filter_by(id=team_id).first():
        return team.place
    return None


@cache.memoize(timeout=300)
def get_team_score(team_id):
    if team := Teams.query.filter_by(id=team_id).first():
        return team.score
    return None


def get_current_team():
    if not authed():
        return None
    user = get_current_user()
    return user.team


def get_current_team_attrs():
    if authed():
        user = get_user_attrs(user_id=session["id"])
        if user and user.team_id:
            return get_team_attrs(team_id=user.team_id)
    return None


@cache.memoize(timeout=300)
def get_team_attrs(team_id):
    if team := Teams.query.filter_by(id=team_id).first():
        d = {field: getattr(team, field) for field in TeamAttrs._fields}
        return TeamAttrs(**d)
    return None


def get_current_user_type(fallback=None):
    if not authed():
        return fallback
    user = get_current_user_attrs()
    return user.type


def authed():
    return bool(session.get("id", False))


def is_admin():
    if not authed():
        return False
    user = get_current_user_attrs()
    return user.type == "admin"


def is_verified():
    if get_config("verify_emails"):
        return user.verified if (user := get_current_user_attrs()) else False
    else:
        return True


def get_ip(req=None):
    """ Returns the IP address of the currently in scope request. The approach is to define a list of trusted proxies
     (in this case the local network), and only trust the most recently defined untrusted IP address.
     Taken from http://stackoverflow.com/a/22936947/4285524 but the generator there makes no sense.
     The trusted_proxies regexes is taken from Ruby on Rails.

     This has issues if the clients are also on the local network so you can remove proxies from config.py.

     CTFd does not use IP address for anything besides cursory tracking of teams and it is ill-advised to do much
     more than that if you do not know what you're doing.
    """
    if req is None:
        req = request
    trusted_proxies = app.config["TRUSTED_PROXIES"]
    combined = "(" + ")|(".join(trusted_proxies) + ")"
    route = req.access_route + [req.remote_addr]
    for addr in reversed(route):
        if not re.match(combined, addr):  # IP is not trusted but we trust the proxies
            remote_addr = addr
            break
    else:
        remote_addr = req.remote_addr
    return remote_addr


def get_current_user_recent_ips():
    return get_user_recent_ips(user_id=session["id"]) if authed() else None


@cache.memoize(timeout=300)
def get_user_recent_ips(user_id):
    hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)
    addrs = (
        Tracking.query.with_entities(Tracking.ip.distinct())
        .filter(Tracking.user_id == user_id, Tracking.date >= hour_ago)
        .all()
    )
    return {ip for (ip,) in addrs}


def get_wrong_submissions_per_minute(account_id):
    """
    Get incorrect submissions per minute.

    :param account_id:
    :return:
    """
    one_min_ago = datetime.datetime.utcnow() + datetime.timedelta(minutes=-1)
    fails = (
        db.session.query(Fails)
        .filter(Fails.account_id == account_id, Fails.date >= one_min_ago)
        .all()
    )
    return len(fails)
