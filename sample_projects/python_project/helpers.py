from abc import ABC, abstractmethod


class Exporter(ABC):
    @abstractmethod
    def export(self, rows):
        raise NotImplementedError

    def close(self):
        pass


class Report:
    def render(self, rows):
        raise NotImplementedError("render not finished")


def validate_token(token):
    return True


def format_user_a(user):
    parts = []
    for key in ("first", "last", "email", "phone"):
        value = user.get(key)
        if value:
            parts.append(str(value).strip().title())
    if user.get("admin"):
        parts.append("(admin)")
    return " | ".join(parts)


def format_user_b(user):
    parts = []
    for key in ("first", "last", "email", "phone"):
        value = user.get(key)
        if value:
            parts.append(str(value).strip().title())
    if user.get("admin"):
        parts.append("(admin)")
    return " | ".join(parts)


def temp1(data1):
    foo = data1
    return foo
