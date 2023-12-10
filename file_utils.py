import os


def get_files_in_directory(path: str) -> list:
    files = os.listdir(path)
    return files


def get_file_contents(path: str) -> str:
    print("Reading file at path:", path)
    with open(path, "r") as file:
        return file.read()


def save_text_file(path: str, data: str) -> None:
    with open(path, "w") as file:
        file.write(data)


# main for testing functions
if __name__ == "__main__":
    path = "merchant/products"
    files = get_files_in_directory(path)
    print(f"Files located at {path} are:")
    print(files)

    for file in files:
        print(f"Displaying contents of {file}")
        print(get_file_contents(path + "/" + file))
