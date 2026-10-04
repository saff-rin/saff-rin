import json
 
#   Simulated Windows Security/Sysmon Events representing browser process spawns
log_data = [
    {"EventID": 1, "ParentImage": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c powershell -ExecutionPolicy Bypass -WindowStyle Hidden"},
    {"EventID": 1, "ParentImage": "C:\\Windows\\explorer.exe", "Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe"}
]
def analyze_logs(logs):
    print(" Scanning logs for 2026 ClickFix")
    browsers = ["chrome.exe", "msedge.exe", "firefox.exe"]
    
    for log in logs:
        if log.get("EventID") == 1:
            parent = log.get("ParentImage", "").lower()
            image = log.get("Image", "").lower()
            
            # Check if a browser directly spawned a command line interpreter
            if any(b in parent for b in browsers) and ("cmd.exe" in image or "powershell.exe" in image):
                print(f"\n ALERT: Potential ClickFix Attack Detected!")
                print(f"  Parent Process: {log['ParentImage']}")
                print(f"  Spawned Process: {log['Image']}")
                print(f"  Command Line: {log['CommandLine']}")

if __name__ == "__main__":
    analyze_logs(log_data)
