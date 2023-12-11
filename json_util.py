import json
import base64
from crypto_custom import aes_encrypt, aes_decrypt


def decode_message(input: bytes) -> tuple[str, str, str]:
    json_msg = input.decode()
    msg = json.loads(json_msg)
    return msg["operation"], msg["data"], msg["ref"]


def session_decode_object(input: str, skey: bytes) -> object:
    return json.loads(aes_decrypt(skey, base64.b64decode(input)))


def jsonify(operation: str, data: object = "", ref: str = "") -> bytes:
    json_obj = {}
    json_obj["operation"] = operation
    json_obj["data"] = data
    json_obj["ref"] = ref
    return json.dumps(json_obj, separators=(",", ":")).encode()


def session_encode_object(data: object, skey) -> str:
    return base64.b64encode(
        aes_encrypt(skey, json.dumps(data, separators=(",", ":")).encode())
    ).decode()


def print_json(json_obj: dict | list) -> None:
    print(json.dumps(json_obj, sort_keys=True, indent=4))


def load_json_file(path: str) -> dict:
    with open(path, "r") as file:
        return json.load(file)


def write_json_file(json_obj: dict | list, path: str) -> None:
    with open(path, "w") as file:
        json.dump(json_obj, file, indent=4)


# main for testing functions
if __name__ == "__main__":
    print("====TEST 1====")
    json_bytes = b'{"operation":"sessionKey","data":{"p":12345678,"q":90909090}}'
    op, data = decode_message(json_bytes)
    print(f"decoded: op: {op} <=> data: {data}")
    assert op == "sessionKey"
    assert data == {"p": 12345678, "q": 90909090}

    print("====TEST 2====")
    json_msg_bytes = jsonify(op, data)
    print(json_msg_bytes)
    assert json_bytes == json_msg_bytes

    print("====TEST 3====")
    print_json(
        json.loads('{"operation":"sessionKey","data":{"p":12345678,"q":90909090}}')
    )
    print_json(json.loads('["file1", "file2", "file3", [1,2,3,4,5   ]]'))

    print("====TEST 4====")
    print_json(load_json_file("broker/passwords.json"))

    some_bytes = session_encode_object(
        [
            "file1",
            "file2",
            "file3",
            "file4",
            "file5",
        ]
    )
    print("jsonify_object:", some_bytes)
    print("decode_object", session_decode_object(some_bytes))
