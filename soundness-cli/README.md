# Soundness CLI

A command-line interface tool for interacting with Soundness Layer testnet.

## Quick Installation

Install the CLI with a single command:

```bash
curl -sSL https://raw.githubusercontent.com/soundnesslabs/soundness-layer/main/soundnessup/install | bash
```

After installation, restart your terminal or run:

```bash
source ~/.bashrc  # for bash
# or
source ~/.zshenv  # for zsh
```

Then you can use the CLI:

```bash
soundnessup install  # Install the CLI
soundnessup update   # Update to the latest version
```

## Docker Installation

You can also build and run the CLI using Docker:

```bash
# Build the Docker image
docker compose build

# Run the CLI (replace [command] with any soundness-cli command)
docker compose run --rm soundness-cli [command]

# Example: Generate a new key pair
docker compose run --rm soundness-cli generate-key --name my-key
```

Wallet data will be saved in folder `.soundness`

## Manual Installation

If you prefer to install manually, you can use Cargo:

```bash
cargo install --path .
```

## Usage

### Generating a Key Pair

To generate a new key pair for signing requests:

```bash
soundness-cli generate-key --name my-key
```

### Importing a Key Pair

To import an existing key pair from a mnemonic phrase:

```bash
soundness-cli import-key --name my-key
```

### Listing Key Pairs

To view all stored key pairs and their associated public keys:

```bash
soundness-cli list-keys
```

### Exporting Key Mnemonic

To export the mnemonic phrase for a stored key pair:

```bash
soundness-cli export-key --name my-key
```

> ⚠️ **Warning**: Keep your mnemonic phrase secure and never share it with anyone. Anyone with your mnemonic can access your key pair.