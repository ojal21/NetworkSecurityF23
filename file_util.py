import os


def get_files_in_directory(path: str) -> list:
    files = os.listdir(path)
    return files


def get_file_contents(path: str, padding: int = 0) -> bytes:
    print("Reading file at path:", path)
    content = None
    with open(path, "rb") as file:
        content = file.read()
    if padding != 0:
        content += b"\0" * (padding - len(content))
    return content


def save_text_file(path: str, data: bytes) -> None:
    if b"\0" in data:
        data = data[: data.index(b"\0")]
    with open(path, "wb") as file:
        file.write(data)


# main for testing functions
if __name__ == "__main__":
    path = "merchant/products"
    files = get_files_in_directory(path)
    print(f"Files located at {path} are:")
    print(files)

    for file in files:
        print(f"Displaying contents of {file}")
        content = get_file_contents(path + "/" + file, 100)
        print(content)
        print("Length =", len(content))
