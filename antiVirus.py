
import os

def scan_file_path(path):

    try:
        print(f"Scanning file path: {path}")
        for root, dirs, files in os.walk(path):
            print(f"\nCurrent file path: {root}")

           
            if dirs:
                print("Sub File Paths:")
                for d in dirs:
                    print(f"  - {os.path.join(root, d)}")

            
            if files:
                print("Files:")
                for f in files:
                    print(f"  - {os.path.join(root, f)}")

    except Exception as e:
        print(f"Error scanning file path {path}: {e}")


while True:
    file_path = input("Enter the file path to scan: ")
    if os.path.exists(file_path):
        scan_file_path(file_path)
    else:
        print("Invalid file path. Please check and try again.")



