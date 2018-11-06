# Vault Plugin: Cloud Foundry Auth Method

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows for Pivotal Cloud Foundry accounts to authenticate with Vault.


## Quick Links
    - Vault Website: https://www.vaultproject.io
    - Main Project Github: https://www.github.com/hashicorp/vault

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Usage

See below for an example of enabling the plugin in a running Vault server:

```sh
$ vault write sys/plugins/catalog/cf \
         sha_256=80f926861606bab6ffb5d35dc1cc519633dd5a4898e71fd2971ba1a7ee9e0cf3 \
         command="vault-plugin-auth-cf"
Success! Data written to: sys/plugins/catalog/cf

$ vault auth enable -plugin-name='cf' plugin
Success! Enabled cf plugin at: cf/

$ vault write auth/cf/config uaa_url=https://uaa.sys.example.com api_url=https://api.sys.example.com
Success! Data written to: auth/cf/config

$ vault write auth/cf/role/vault bound_guids=ff66be1a-ac19-42d8-8345-1db0e9957194
Success! Data written to: auth/cf/role/vault

$ vault write auth/cf/login role=vault jwt=eyJ...
Key                     Value
---                     -----
token                   6d4FgFJZcYWmmitvycyUq9cI
token_accessor          5j7rr8ex349N9yDm39lETFvE
token_duration          768h
token_renewable         true
token_policies          ["default"]
identity_policies       []
policies                ["default"]
token_meta_role         vault
token_meta_user_id      53e8e5b0-4dad-432a-9240-9691c0dd3998
token_meta_user_name    lance
```

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine.

For local dev first make sure Go is properly installed, including
setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).
Next, clone this repository into
`$GOPATH/src/github.com/lanceplarsen/vault-plugin-auth-cf`.
You can then download any required build tools by bootstrapping your
environment:

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make
$ make dev
```

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://www.vaultproject.io/docs/configuration/index.html#plugin_directory)
in the Vault config used to start the server.

```json
...
plugin_directory = "path/to/plugin/directory"
...
```

Start a Vault server with this config file:
```sh
$ vault server -config=path/to/config.json ...
...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog):

```sh
$ vault write sys/plugins/catalog/cf \
        sha_256=<expected SHA256 Hex value of the plugin binary> \
        command="vault-plugin-auth-cf"
...
Success! Data written to: sys/plugins/catalog/cf
```

Note you should generate a new sha256 checksum if you have made changes
to the plugin. Example using openssl:

```sh
openssl dgst -sha256 $GOPATH/vault-plugin-auth-cf
...
SHA256(.../go/bin/vault-plugin-auth-cf)= 896c13c0f5305daed381952a128322e02bc28a57d0c862a78cbc2ea66e8c6fa1
```

Enable the auth plugin backend using the CF auth plugin:

```sh
$ vault auth enable -plugin-name='cf' plugin
...

Successfully enabled 'plugin' at 'cf'!
```

#### Tests

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the tests.

To run the tests, invoke `make test`:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='--run=TestConfig'
```
