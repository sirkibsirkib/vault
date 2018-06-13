All interactions with persistent data rely on one singular _super-password_
we will call `S`.
At the start of every session, you are prompted to enter `S`,
which is hashed to produce your `session key`. Next, the program enters a REPL,
and listens for commands `{get, push, ...}` to operate on your persistent data.

Each operation is performed on your persistent data in isolation. It is loaded
from file first, operated on, and then written back if necessary. Nothing is
stored in memory so no explicit saving is necessary. 

Under the hood, each key-value pair is stored in a separate file. The name of the file is how the program finds the data, but it isn't stored in plain-text. Rather, the name is generated from a hash of numerous values, including your `session key`. This means that _without `S`, an attacker cannot even tell which keys you are using_. The contents of each file is the list of values associated with that key. This data is AES encrypted using your `session key`.

Hash(password) --> h_password
Hash(h_password, plain_key) --> h_key
AES(h_password, padded_value) -> enc_value
AES(h_password, enc_value) -> padded_value
padded_value = (value, bogus)


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

# What an outsider sees
So you've fired up the program, used it for a few minutes,
killed it with `CTRL+C` and cleared your terminal. An outsider now sits down and
attempts to access your private information. Assuming they find your `config.json`, the attacker is able to find your persistent storage directory. (For those that would want to avoid _even this_, the program will also interpret a command-line argument as the storage path, allowing you to remove your `config.json` and hide your storage directory somewhere).

* The persistent files have base-64 encoded hash values as names. Eg: `AfrJXlLIRXpRm6yvJW5KTZaSm9wSO6+LaUDQpx+$L$Q=`
* Each persistent storage element is padded with a random-length sequence of random bytes. Attackers cannot deduce much from the _size_ of a persistent file.
* Each file's contents are AES-encrypted using your `session key`, which is a function of the _one_ password you do have to remember.


# What an insider sees
Upon login, you are prompted for a password that hashes to create your session key.
Thereafter, the program enters a REPL,
facilitating simple commands `{push, get, list, rm, filename, ?}`.

Each command that interacts with a key-value entry uses a hash of the key to identify

