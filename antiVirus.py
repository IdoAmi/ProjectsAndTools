import hashlib
import requests
import os

# פונקציה לחישוב Hash של קובץ (SHA-256)
def calculate_hash(file_path):
    try:
        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):  # קריאה במקטעים
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        print(f"שגיאה בחישוב ה-Hash: {e}")
        return None

# פונקציה לשליחת ה-Hash ל-API של Virus Total
def check_file_hash(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print("ה-Hash לא נמצא במאגר של Virus Total.")
            return None
        else:
            print(f"שגיאה מהשרת: {response.status_code}")
            return None
    except Exception as e:
        print(f"שגיאה בשליחת הבקשה ל-API: {e}")
        return None

# פונקציה ראשית לבדיקת קובץ
def main():
    api_key = "הכנס_כאן_את_מפתח_ה-API_שלך"

    # בקשת מסלול מהמשתמש
    file_path = input("הזן את המסלול של הקובץ לבדיקה: ")

    # בדיקה אם הקובץ קיים
    if not os.path.exists(file_path):
        print("הקובץ לא קיים. בדוק את המסלול והפעל שוב.")
        return

    # חישוב ה-Hash
    file_hash = calculate_hash(file_path)
    if not file_hash:
        return

    print(f"ה-Hash של הקובץ: {file_hash}")

    # בדיקה מול ה-API
    result = check_file_hash(api_key, file_hash)
    if result:
        attributes = result.get("data", {}).get("attributes", {})
        malicious_votes = attributes.get("last_analysis_stats", {}).get("malicious", 0)
        if malicious_votes > 0:
            print(f"הקובץ זוהה כזדוני על ידי {malicious_votes} תוכנות אנטי־וירוס.")
        else:
            print("הקובץ בטוח לשימוש לפי המאגר של Virus Total.")

# הרצת הפונקציה הראשית
if __name__ == "__main__":
    main()
