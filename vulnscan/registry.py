"""Plugin registry. Add a check by decorating a function; nothing else to wire up.

web_passive : fn(page, ctx)  -> Iterable[Finding]   (analyses crawled responses only)
web_active  : fn(pages, ctx) -> Iterable[Finding]   (sends test payloads; opt-in)
code_check  : fn(path, text) -> Iterable[Finding]   (static analysis of one file)
"""
WEB_PASSIVE, WEB_ACTIVE, CODE_CHECKS = [], [], []


def web_passive(fn):
    WEB_PASSIVE.append(fn)
    return fn


def web_active(fn):
    WEB_ACTIVE.append(fn)
    return fn


def code_check(fn):
    CODE_CHECKS.append(fn)
    return fn
