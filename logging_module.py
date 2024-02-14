import logging
import datetime

from models import Log, db


def log_audit_event(username, user_ip, action, details):
    log_entry = f"User ID: {username}, User IP: {user_ip}, Action: {action}, Details: {details}"
    logging.info(log_entry)
    current_time = datetime.datetime.now()
    new_log = Log(timestamp=current_time, username=username, user_ip=user_ip, action=action, details=details)
    db.session.add(new_log)
    db.session.commit()
