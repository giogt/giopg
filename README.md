giopg
=====

A command line tool to encrypt / decrypt files using symmetric keys written in
Rust.

The tool is using encryption standard algorithms from the libsodium library,
adding some extra data scrambling.
This ensures that, even if your symmetric key gets compromised, it will still
be quite hard for attackers to decrypt your data if they don't know the
algorithm implemented by this tool.
