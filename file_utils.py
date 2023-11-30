import os


def getFilesInDirectory(path: str) -> list:
    files = os.listdir(path)
    return files


def getFileContents(path: str) -> str:
    print("Reading file at path:", path)
    with open(path, "r") as file:
        return file.read()


# main for testing functions
if __name__ == "__main__":
    path = "merchant/products"
    files = getFilesInDirectory(path)
    print(f"Files located at {path} are:")
    print(files)

    for file in files:
        print(f"Displaying contents of {file}")
        print(getFileContents(path + "/" + file))
