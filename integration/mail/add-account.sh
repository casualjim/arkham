#!/bin/bash
# Runs before supervisord, so `postfix-accounts.cf` exists when
# docker-mailserver builds the Dovecot user database. `setup email add`
# inside user-patches.sh is too late: that script runs after the database
# is built. The password comes from the container environment.
set -euo pipefail

if ! setup email list | grep -q 'agent@demo.test'; then
  setup email add agent@demo.test "${ARKHAM_SMTP_PASS:?ARKHAM_SMTP_PASS is required}"
fi

exec supervisord -c /etc/supervisor/supervisord.conf
