"""Fail-closed settings for a standalone, dedicated portal deployment."""
import re
from urllib.parse import urlsplit

_AZURE_DEFAULT = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z][a-z0-9]*-[0-9]{2})?\.azurewebsites\.net")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_BLOB_ACCOUNT = re.compile(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net")
_CONTAINER = re.compile(r"[a-z0-9](?:[a-z0-9-]{1,61})[a-z0-9]")

def deployment_host(origin):
    """Require an exact lower-case HTTPS DNS origin with no port or path."""
    u=urlsplit(origin)
    host=u.hostname or ""
    if (origin!="https://"+host or u.scheme!="https" or len(host)>253 or "." not in host
            or not all(_DNS_LABEL.fullmatch(label) for label in host.split("."))
            or not host.rsplit(".",1)[-1][0].isalpha()):
        raise ValueError("Use a dedicated HTTPS DNS origin with no trailing slash or port")
    return host

def cookie_domain_mode(origin,mode="auto"):
    host=deployment_host(origin)
    if mode not in {"auto","host","azure-exact-domain"}:
        raise ValueError("Cookie mode must be auto, host, or azure-exact-domain")
    # Azure Functions' cookie adapter can emit an empty Domain. Avoid that only for
    # a dedicated default Azure hostname, or an expressly selected custom host.
    if mode=="host":
        return False
    if mode=="azure-exact-domain":
        if len(host.split("."))<3:
            raise ValueError("Exact-domain compatibility requires a dedicated subdomain")
        if host.endswith(".azurewebsites.net") and not _AZURE_DEFAULT.fullmatch(host):
            raise ValueError("Use a dedicated default Azure Functions hostname")
        return True
    return bool(_AZURE_DEFAULT.fullmatch(host))

def storage_settings(account_url,state_container,quarantine_container):
    u=urlsplit(account_url);host=u.hostname or ""
    if account_url not in {"https://"+host,"https://"+host+"/"} or not _BLOB_ACCOUNT.fullmatch(host):
        raise ValueError("Use the dedicated Azure Blob HTTPS account origin")
    if (state_container==quarantine_container or any(not _CONTAINER.fullmatch(c) or "--" in c
            for c in (state_container,quarantine_container))):
        raise ValueError("Configure two distinct valid private Azure Blob container names")
    return account_url.rstrip("/"),state_container,quarantine_container
