import asyncio
from lab3 import run_node, load_members

if __name__ == "__main__":
    member = load_members()
    asyncio.run(run_node("my_key.pem", 8093, member, is_registrar=True))
