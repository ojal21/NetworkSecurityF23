import argparse
import configparser


def load_config() -> configparser.ConfigParser:
    # config and setup related
    config = configparser.ConfigParser()
    config.read("config")  # filename: 'config'
    return config


def load_args() -> list:
    argParser = argparse.ArgumentParser()
    argParser.add_argument(
        "-m",
        "--mode",
        help="select mode: 'client', 'broker', 'merchant'",
        choices=["client", "broker", "merchant"],
        required=True,
    )
    argParser.add_argument("-i", "--ip", help="IP address", required=False)
    argParser.add_argument("-p", "--port", help="Port for socket", required=False)

    args = argParser.parse_args()
    print("Args:", args)
    return args
