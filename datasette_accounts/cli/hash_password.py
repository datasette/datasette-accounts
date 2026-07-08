"""``datasette accounts hash-password`` — hash a password with the PBKDF2 scheme."""

import click

from ..passwords import hash_password
from .base import accounts


@accounts.command(name="hash-password")
@click.argument("password", required=False)
def hash_password_command(password):
    """Hash a password with the datasette-accounts PBKDF2 scheme."""
    if not password:
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    click.echo(hash_password(password))
