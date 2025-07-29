file_path = input("Enter the file path: ")

while True:
    try:
        xor_key = int(input("Enter the XOR key (0-255): "))
        if not 0 <= xor_key <= 255:
            raise ValueError("XOR key must be between 0 and 255.")

    
        with open(file_path, 'rb') as file:
            content = file.read()

    
            xored_content = bytes([b ^ xor_key for b in content])

   
        with open(file_path, 'wb') as file:
            file.write(xored_content)

        print(f"File has been {'encrypted' if content != xored_content else 'decrypted'} successfully!")

    except FileNotFoundError:
        print("The file does not exist. Please check the path and try again.")
    except ValueError as ve:
        print(f"Invalid input: {ve}")
    except Exception as e:
        print(f"An error occurred: {e}")
