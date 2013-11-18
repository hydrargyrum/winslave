WinSlave is an HTTPS server for controlling the host's files and run tasks, transforming it into a slave. It was made to be an extremely-cheap replacement for an SSH server, which is a pain to run on Windows.
WinSlave exposes reading and writing files on the host, and also running commands.
Due to the degree of control permitted on the slave machine, it can easily become a backdoor if not secured properly. To avoid this, WinSlave takes a few measures:

- WinSlave is an HTTPS server, TLS over HTTP, meaning that eavesdropping the traffic will not disclose any data
- WinSlave requires client-side certificate-based authentication with a certificate whitelist, or a custom CA, meaning that authentication is not based on a simple passphrase but on a SSL certificate
- a default deny-all ACL must be configured per-user (based on the certificate) to grant rights.


## Features ##

Files can be read or written, under a certain directory, called fs_root. Files outside this directory cannot be accessed at all.

A basic "shell" can be open, allowing any commands to be passed in without restriction. Due to the way how HTTP works, all commands will be read first, then passed to the shell, and the output will be returned. No interactivity is possible in a request.

Also, "commands" can be run, restricted to binaries present under a certain directory, called command_root. Arguments can be passed to those commands.

It is preferrable to have a dedicated dir with only a few commands inside (and use that as command_root) rather than allow full shell access.

## Self-signed certificates ##

Self-signed certificates are perfectly allowed and fine. Only those that are in the whitelist will be accepted.

The server requires a server private key, in order to cipher its traffic and identify itself. The client should have the server public key, to ensure the server is not a man-in-the-middle attacker.

The clients have private keys, to cipher and identify themselves. The server must have the clients' public keys, in a whitelist, and will reject everything that's not in the whitelist.

Multiple keys can be put in a same file ".pem", by just concatenating multiple ".pem". The server private key file typically contains the private key and the public key of the server.
The clients whitelist on the server also contains all the public keys of all the clients to be allowed.

Example to run the server:

```
winslave -k SERVER-PRIVATE-KEY.PEM -c CLIENTS-PUBLIC-KEYS.PEM
```

Example to run a client, with curl:

```
curl -E CLIENT-PRIVATE-KEY.PEM --cacert SERVER-PUBLIC-KEY.PEM https://address.of.server:9000/...
```

## CA-based certificates ##

Certificates based on a CA are also allowed, then it's possible to have only the CA public certificate in the whitelist file. A custom CA is preferrable, to narrow the allowed clients.

## ACL ##

The certificates are for ciphering data and also for authenticating both the server and the clients. The granting of the rights is done in the ACL. The default ACL is to deny all requests, so the configuration is necessary else nothing is allowed.

Each non-rejected client (based on the keys) is then identified by the "common name" of its certificate.

The configuration is an INI file, consisting of a number of sections, each section used for setting the rights of a client. The section name is the "common name" of the certificate used by the client.
Inside a section, options grant separate access to read or write, set the fs_root where files can be accessed, and nowhere else. Shell can be toggled. Command access can be also toggled, and the command_root can be set to the dir in which runnable binaries are allowed, and no other runnables will be allowed.
Options can be omitted, their default is to deny.


Configuration example:

```
[foo.local]
# this config will allow a client presenting a certificate with commonName="foo.local"
read_file=True # default=False
write_file=False # default=False
fs_root=~/files # default=~
# the ~ refers to the home of the _user running WinSlave_, not any user identified by certificate or anything else

exec_shell=False # default=False

exec_commands=True
command_root=~/my-commands # default=~/bin

# commonName=foo.local # allows to override the common name, not rely on the section name as commonName

[bar.local]
# deny all for bar.local (the section can just be omitted)
```

## Protocol ##

### Read a file ###
```
GET https://<SERVER>/fs/<path/to/file>
```

In case of success, code 200 is returned, with file data as the response body.
If file is not found, 404 is returned.
If access to path or to reading is denied or outside fs_root dir, 403 is returned.

### Write a file ###
```
PUT https://<SERVER>/fs/<path/to/file>
[file data as request body, Content-Length header is mandatory]
```

In case of success, code 201 is returned.
If parent directory is not found, 404 is returned.
If access to path or to writing is denied or outside fs_root dir, 403 is returned.

### Running a script in a shell ###
```
POST https://<SERVER>/exec_shell
[shell script as request body, Content-Length header is mandatory]
```

If shell access is allowed, code 200 is returned. The response body will contain stdout and stderr of the shell.
Else, 403 is returned.

### Running commands ###
```
POST https://<SERVER>/exec_command/<COMMAND>?<ARGS%20ESCAPED>
[stdin of the command as request body, Content-Length header is mandatory]
```

If command access is allowed, and command found, code 200 is returned. The response body will contain stdout and stderr of the command.
If command access is denied or outside of command_root dir, 403 is returned.
If command is not found, 404 is returned.

## Security ##

- Shell use is discouraged. It nullifies the files restrictions from fs_root, read_file, write_file (`cat` and `tee` are 2 common commands to circumvent them)
- /bin and /usr/bin shall not be put as command_root, for the same reason
- fs_root should not contain command_root, else scripts can be written inside command_root, effectively enabling exec_shell
- allowed commands should not write inside command_root
- Though best effort is done not to follow symlinks (they are followed, but the destination is not read/written if outside fs_root), commands allowed should not attempt to follow them either, but WinSlave cannot control what the allowed commands do
- To mitigate attacks, prefer rejection whenever possible even if creating false-positives. Deny symlinks, deny absolute paths, deny writing, use your judgement.
