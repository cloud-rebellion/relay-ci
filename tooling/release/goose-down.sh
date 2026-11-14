# Exact Stage GooseDownRehearsal body from 91f821a3d5895a901569954d2aa50c173582ff13.

# Reversibility: roll back the last 3 migrations and replay them.
for i in 1 2 3; do
  if out="$(goose down 2>&1)"; then
    printf '%s\n' "$out" | tail -1
    continue
  fi
  # Non-zero means one of two very different things. Match the benign one
  # explicitly and treat everything else as a real failure, so a broken down
  # step cannot hide behind "probably just no down step".
  if printf '%s\n' "$out" | grep -qiE 'no migrations to run|no next version found|no migration found|no previous version|no current version found'; then
    echo "goose down: nothing left to roll back (ok)"
    break
  fi
  echo "FAIL: goose down failed on an EXISTING down step:" >&2
  printf '%s\n' "$out" >&2
  exit 1
done
