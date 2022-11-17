import server


if __name__ == "__main__":
    try:
        server.open_the_server()
    except Exception as e:
        print("[-] Error: " + str(e))
        print("[!] The server crashed!")


