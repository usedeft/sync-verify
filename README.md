# sync-verify

Checks that a note stored by Deft Sync is encrypted with your key: fetches a record and its blob from the server, decrypts them, and confirms the blob's id is the keyed HMAC of its decrypted contents.

Requires Deft with Sync set up and at least one note synced.

## Dependencies

Python 3 with `pynacl`, `zstandard`, and `secret-tool` on Linux.

```sh
pip install pynacl zstandard
```

## 1. Get your key and token

Your key and token can be found in your OS keychain under service `com.usedeft.deft`.

Export the token.

```sh
export TOKEN=$(secret-tool lookup service com.usedeft.deft username sync-token)     # Linux
export TOKEN=$(security find-generic-password -s com.usedeft.deft -a sync-token -w) # macOS
```

On Windows, copy the `sync-token` entry from Credential Manager and paste it in:

```powershell
$env:TOKEN = Read-Host "Token" -MaskInput
```

Your key is the 32 hex characters under username `sync-master-key`. You'll paste it in step 2:

```sh
secret-tool lookup service com.usedeft.deft username sync-master-key     # Linux
security find-generic-password -s com.usedeft.deft -a sync-master-key -w # macOS
```

## 2. Verify

```sh
python verify.py
```

Paste your key (found in the OS keychain) when asked. The script fetches the first note and you should see its path and size confirmed as verified. Pass a note's path (`python verify.py notes/todo.md`) to check that note instead. Add `--print` to see its contents.
