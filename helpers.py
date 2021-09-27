import asyncio
import json

from okta_jwt_verifier import JWTVerifier


loop = asyncio.get_event_loop()


def is_access_token_valid(token, issuer, client_id):
    # this method verifies if the access token is valid
    jwt_verifier = JWTVerifier(issuer, client_id, 'api://default')
    try:
        loop.run_until_complete(jwt_verifier.verify_access_token(token))
        return True
    except Exception:
        return False


def is_id_token_valid(token, issuer, client_id, nonce):
    jwt_verifier = JWTVerifier(issuer, client_id, 'api://default')
    try:
        loop.run_until_complete(jwt_verifier.verify_id_token(token, nonce=nonce))
        return True
    except Exception:
        return False


def load_config(fname='./client_secrets.json'):
    # method to load the configuration from the client_secrets.json file
    config = None
    with open(fname) as f:
        config = json.load(f)
    return config


config = load_config()
