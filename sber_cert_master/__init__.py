"""sber-cert-master: keeps Sber Business API (Sber API) credentials alive.

One process owns the refresh_token / client_secret / TLS material and publishes
a fresh access_token plus TLS files for agents. Agents keep calling the bank
directly; nothing is proxied.
"""

__version__ = "0.1.0"
