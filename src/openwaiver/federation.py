"""RFC 9068-style access-token authentication with administrator-pinned trust.

No token-supplied URLs are fetched. JWT roles, emails and project claims never grant
permissions. Explicit issuer/subject/client bindings resolve to existing principals.
This validates access tokens; it is not an OAuth authorization-code login client.
"""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import jwt
from pydantic import Field, StrictInt, model_validator

from .models import Model, Principal


class InvalidAccessToken(ValueError):
    pass


class FederationUnavailable(ValueError):
    pass


def strict_object(text: str):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError("duplicate JSON key")
            obj[k] = v
        return obj
    return json.loads(text, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


class Binding(Model):
    subject: str = Field(min_length=1, max_length=1000)
    client_ids: list[str] = Field(min_length=1, max_length=100)
    principal: Principal

    @model_validator(mode="after")
    def limited(self):
        if self.principal.projects is None:
            raise ValueError("federated principals require explicit project grants")
        if (len(self.client_ids) != len(set(self.client_ids))
                or any(not x.strip() for x in self.client_ids)):
            raise ValueError("client IDs must be distinct and nonblank")
        return self


class FederationConfig(Model):
    schema_version: Literal[1] = 1
    issuer: str = Field(min_length=1, max_length=2000)
    audience: str = Field(min_length=1, max_length=2000)
    jwks: dict
    bindings: list[Binding] = Field(min_length=1, max_length=10000)
    required_scopes: list[str] = Field(default_factory=lambda: ["openwaiver"])
    max_lifetime_seconds: Annotated[StrictInt, Field(ge=1, le=86400)] = 3600
    leeway_seconds: Annotated[StrictInt, Field(ge=0, le=60)] = 0
    revoked_jtis: list[str] = Field(default_factory=list, max_length=10000)
    disabled_subjects: list[str] = Field(default_factory=list, max_length=10000)
    issued_after: dict[str, Annotated[StrictInt, Field(ge=0)]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def trust(self):
        url = urlsplit(self.issuer)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("issuer must be an exact HTTPS identifier")
        if set(self.jwks) != {"keys"} or not isinstance(self.jwks["keys"], list) or not 1 <= len(self.jwks["keys"]) <= 32:
            raise ValueError("JWKS must contain 1..32 public keys")
        kids = set()
        for key in self.jwks["keys"]:
            if (not isinstance(key, dict) or key.get("kty") != "RSA" or key.get("alg") != "RS256"
                    or key.get("use") != "sig" or not isinstance(key.get("kid"), str)
                    or not 1 <= len(key["kid"]) <= 200 or key["kid"] in kids
                    or set(key) - {"kty", "kid", "alg", "use", "key_ops", "n", "e"}
                    or key.get("key_ops", ["verify"]) != ["verify"]):
                raise ValueError("expected unique, public RS256 signing keys only")
            public = jwt.PyJWK.from_dict(key, algorithm="RS256").key
            if public.key_size < 2048 or public.key_size > 8192:
                raise ValueError("RSA key size must be 2048..8192 bits")
            kids.add(key["kid"])
        subjects = [b.subject for b in self.bindings]
        if len(subjects) != len(set(subjects)):
            raise ValueError("duplicate subject binding")
        # Multiple subjects may intentionally map to the SAME human identity, but
        # cannot use that to acquire inconsistent permissions.
        principals = {}
        for binding in self.bindings:
            name = binding.principal.name
            if name in principals and principals[name] != binding.principal:
                raise ValueError("aliases for a principal must have identical grants")
            principals[name] = binding.principal
        if (len(self.required_scopes) != len(set(self.required_scopes))
                or any(not x or any(c.isspace() for c in x) for x in self.required_scopes)):
            raise ValueError("invalid required scopes")
        return self


@lru_cache(maxsize=8)
def _checked(raw: bytes) -> FederationConfig:
    return FederationConfig.model_validate(strict_object(raw.decode("utf-8")))


def load_config(path: str | Path) -> FederationConfig:
    try:
        if Path(path).is_symlink():
            raise ValueError("symlink trust configuration rejected")
        with Path(path).open("rb") as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("config byte limit")
        return _checked(raw)
    except Exception as exc:
        raise FederationUnavailable("federation trust configuration unavailable") from exc


def validate_access_token(token: str, config: FederationConfig) -> Principal:
    try:
        if not isinstance(token, str) or len(token) > 16384 or token.count(".") != 2:
            raise ValueError("invalid token size or structure")
        # Reject duplicate header/claim keys before the JWT library parses them.
        header_raw, payload_raw, _ = token.split(".")
        header = strict_object(jwt.utils.base64url_decode(header_raw).decode("utf-8"))
        payload = strict_object(jwt.utils.base64url_decode(payload_raw).decode("utf-8"))
        if (not isinstance(header, dict) or set(header) - {"alg", "kid", "typ"}
                or header.get("alg") != "RS256" or header.get("typ") not in ("at+jwt", "application/at+jwt")
                or not isinstance(header.get("kid"), str)):
            raise ValueError("unexpected token header or ID token")
        if not isinstance(payload, dict):
            raise ValueError("claims must be an object")
        for claim in ("exp", "iat"):
            if type(payload.get(claim)) is not int:
                raise ValueError("numeric dates must be integers")
        if "nbf" in payload and type(payload["nbf"]) is not int:
            raise ValueError("numeric dates must be integers")
        keys = [key for key in config.jwks["keys"] if key["kid"] == header["kid"]]
        if len(keys) != 1:
            raise ValueError("unknown signing key")
        public = jwt.PyJWK.from_dict(keys[0], algorithm="RS256").key
        claims = jwt.decode(token, public, algorithms=["RS256"], issuer=config.issuer,
            audience=config.audience, leeway=config.leeway_seconds,
            options={"require": ["iss", "aud", "exp", "iat", "sub", "jti", "client_id"], "strict_aud": True})
        for name in ("sub", "jti", "client_id"):
            if not isinstance(claims[name], str) or not 1 <= len(claims[name]) <= 1000:
                raise ValueError("invalid identity claim")
        if not 0 < claims["exp"] - claims["iat"] <= config.max_lifetime_seconds:
            raise ValueError("token lifetime outside policy")
        if (claims["jti"] in config.revoked_jtis or claims["sub"] in config.disabled_subjects
                or claims["iat"] < config.issued_after.get(claims["sub"], 0)):
            raise ValueError("access revoked")
        scopes = claims.get("scope", "")
        if not isinstance(scopes, str) or not set(config.required_scopes) <= set(scopes.split()):
            raise ValueError("required scope absent")
        binding = next((b for b in config.bindings if b.subject == claims["sub"]), None)
        if binding is None or claims["client_id"] not in binding.client_ids:
            raise ValueError("subject/client not provisioned")
        return binding.principal.model_copy(deep=True)
    except Exception as exc:
        # Never return token contents, key material, or claim-specific diagnostics to clients.
        raise InvalidAccessToken("invalid access token") from exc
