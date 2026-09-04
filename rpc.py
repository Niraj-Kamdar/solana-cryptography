import requests


def getLatestBlockhash() -> str:
    resp = requests.post(
        "https://api.devnet.solana.com",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "confirmed"}],
        },
    )

    assert resp.ok is True and resp.status_code == 200
    return resp.json()["result"]["value"]["blockhash"]


def simulateTransaction(txData: str) -> str:
    resp = requests.post(
        "https://api.devnet.solana.com",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "simulateTransaction",
            "params": [
                txData,
                {
                    "commitment": "confirmed",
                    "encoding": "base58",
                    "replaceRecentBlockhash": True,
                },
            ],
        },
    )

    assert resp.ok is True and resp.status_code == 200
    return resp.json()["result"]["value"]


if __name__ == "__main__":
    assert getLatestBlockhash() is not None
