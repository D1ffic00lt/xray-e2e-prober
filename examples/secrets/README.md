# Secret-file examples

The `*.example` files contain unusable placeholders and are safe to commit.
Do not replace them in place with real values. Create ignored files instead
from Bash (the values are read without terminal echo or command-line arguments):

```bash
umask 077
mkdir -p secrets
read -r -s -p 'Subscription URL: ' PROBER_SECRET_INPUT; printf '\n'
printf '%s' "$PROBER_SECRET_INPUT" > secrets/subscription-url
unset PROBER_SECRET_INPUT
read -r -s -p 'Authorization value: ' PROBER_SECRET_INPUT; printf '\n'
printf '%s' "$PROBER_SECRET_INPUT" > secrets/subscription-authorization
unset PROBER_SECRET_INPUT
```

Point Compose at them without putting either value on the command line:

```console
export PROBER_SUBSCRIPTION_URL_FILE="$PWD/secrets/subscription-url"
export PROBER_SUBSCRIPTION_AUTHORIZATION_FILE="$PWD/secrets/subscription-authorization"
docker compose up -d
```

The Authorization file contains only the header value, not YAML and not the
`Authorization:` header name. On Compose implementations that ignore secret
`uid`/`gid`/`mode`, host file permissions remain the primary protection; verify
the effective mount permissions before using a shared host.
