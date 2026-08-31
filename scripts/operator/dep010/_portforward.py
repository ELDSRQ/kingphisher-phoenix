import asyncio, sys
SRC, DST = int(sys.argv[1]), int(sys.argv[2])
async def pipe(r, w):
    try:
        while (b := await r.read(65536)):
            w.write(b); await w.drain()
    except Exception: pass
    finally:
        try: w.close()
        except Exception: pass
async def handle(cr, cw):
    try: sr, sw = await asyncio.open_connection("127.0.0.1", DST)
    except Exception:
        cw.close(); return
    await asyncio.gather(pipe(cr, sw), pipe(sr, cw))
async def main():
    s = await asyncio.start_server(handle, "127.0.0.1", SRC)
    async with s: await s.serve_forever()
asyncio.run(main())
