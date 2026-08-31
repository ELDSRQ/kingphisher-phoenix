"""Forward a local TCP port to another local port.

The operator console's local dependency probe is hardcoded to 127.0.0.1:5432,
while the E2E-lane PostgreSQL publishes 5433. This keeps the probe truthful
without changing product behaviour.
"""

import asyncio
import sys

SOURCE_PORT = int(sys.argv[1])
DESTINATION_PORT = int(sys.argv[2])


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    try:
        server_reader, server_writer = await asyncio.open_connection("127.0.0.1", DESTINATION_PORT)
    except OSError:
        client_writer.close()
        return
    await asyncio.gather(
        pipe(client_reader, server_writer),
        pipe(server_reader, client_writer),
    )


async def main() -> None:
    server = await asyncio.start_server(handle, "127.0.0.1", SOURCE_PORT)
    async with server:
        await server.serve_forever()


asyncio.run(main())
