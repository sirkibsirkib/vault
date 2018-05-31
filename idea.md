
# Idea
You run the program and are prompted for a password.
that gets saved to var `key`.

you then enter a cmdline loop.
commands:
* get k
* push k v
* pop k i
* rm k

everything you do (except for get) will be checked by an 'are you sure' and warnings that you will overwrite stuff
Under the hood, you are interacting with persistent storage of key-value pairs.
keys are arbitrary strings.
values are vectors of type (string, date).
the idea is that you, the user, will append values to these lists. the date-field is filled in for you.
using 'get' you can display the contents of a key.

persistent data is stored in a folder you provide in a config file expected to be in the path of the executable.
there is a path to a folder in there which will be used as the store.
the store is a flat directory containing a shitload of files.
their names are b64-encoded h values. an h value is a hash of (session_passwd, plaintext_key)
