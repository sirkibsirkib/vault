




# Vault

Vault is an offline, secure persistent key-multivalue store.
At its core, it offers the user the ability to append string values to lists,
where each list is associated with a key. Appended values are automatically
annotated with a timestamp and stored in order. 

The primary goal is to facilitate _backup storage_ of sensitive data like
passwords, pincodes, and small notes. For those that don't want to rely on
a fully-fledged password manager that takes control of your passwords, this
store is intended as a fallback for when you've forgotten your strong passwords.
In turn, users should feel more at liberty to choose strong passwords.

Use of the vault involves interacting with a REPL to 'atomically' append and query
your stored values by key.

# How it Works

All your persistent data is stored in a single user-passed (or configured) directory.
Vault relies on hashing to obfuscate the keys your store has populated, and uses
AES encryption to hide the values associated with those keys. 

To make sense of any of this, the user must provide a super-password at startup,
whose hash is used to salt the other security functions. As a result, several different
vaults could exist in the same directory without them being able to read one another's data at all,
and without stepping on each other's toes (except for highly unliekly 128-bit hash collisions).
