# MC Status

[Forked from 5vx](https://github.com/5vx/rustcraft.git)

A Rust-based command-line tool for querying Minecraft server status.

## Features

- Supports modern and legacy Minecraft protocols (including SRV)
- Retrieves server info: version, player count, MOTD
- Fetches Forge and mod details

## Quick Start

1. [Install Rust](https://www.rust-lang.org/tools/install)

2. Clone the repository:
   ```
   git clone https://gitcove.com/melon/mcstatus.git
   cd mcstatus
   ```

3. Build the project:
   ```
   cargo build --release
   ```

4. Run mcstatus:
   ```
   ./target/release/mcstatus <hostname> -p <port>
   ```

   The port will be discovered using SRV records, or default to 25565.

   Example:
   ```
   ./target/release/mcstatus mc.example.com -p 25565
   ```
