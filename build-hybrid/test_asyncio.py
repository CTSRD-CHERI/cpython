import asyncio

async def main():
    server = await asyncio.start_server(
    lambda r, w: None, '127.0.0.1', 0
                            )
    addr = server.sockets[0].getsockname()
    print("Listening at", addr)

    # Wait a moment to ensure the event loop finishes setup
    await asyncio.sleep(2)
    
    try:
        reader, writer = await asyncio.open_connection(*addr)
        print("Connected")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print("Connection failed:", e)

    server.close()
    await server.wait_closed()

asyncio.run(main())
