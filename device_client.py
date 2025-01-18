import requests
import json

# Base URL of the running FastAPI server
BASE_URL = "http://127.0.0.1:8354"

# Step 5.2: Register a new device (Interactive)
def register_device():
    print("\n=== Register a New Device ===")
    device_id = input("Enter device ID (e.g., 'smart_bulb_1'): ")
    role = input("Enter device role (e.g., 'sensor', 'actuator', 'admin'): ")

    # Optional metadata input
    metadata = {}
    add_metadata = input("Do you want to add metadata for the device? (yes/no): ").strip().lower()
    if add_metadata == "yes":
        print("Enter metadata as key-value pairs (e.g., manufacturer=AwesomeDevices).")
        while True:
            pair = input("Enter metadata (or press Enter to finish): ")
            if not pair:
                break
            try:
                key, value = pair.split("=")
                metadata[key.strip()] = value.strip()
            except ValueError:
                print("Invalid format. Use key=value format.")

    # Register the device
    url = f"{BASE_URL}/register"
    payload = {
        "device_id": device_id,
        "role": role,
        "metadata": metadata
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        print(f"Device '{device_id}' registered successfully!")
        print("Public Key:", response.json()["public_key"])
    else:
        print(f"Failed to register device '{device_id}'.")
        print("Error:", response.json())

# Step 5.3: Generate a token (Interactive)
def generate_token():
    print("\n=== Generate Token for a Device ===")
    device_id = input("Enter device ID for token generation: ")
    url = f"{BASE_URL}/token"
    payload = {
        "username": device_id,
        "password": "your_device_password"  # Replace with actual logic if needed
    }
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        print(f"Token for device '{device_id}' generated successfully!")
        print("Token:", response.json()["access_token"])
    else:
        print(f"Failed to generate token for device '{device_id}'.")
        print("Error:", response.json())

# Step 5.4: Define rules (Interactive)
def define_rule():
    print("\n=== Define a Communication Rule ===")
    from_role = input("Enter the sender role (e.g., 'sensor'): ")
    to_role = input("Enter the receiver role (e.g., 'actuator'): ")
    allow = input("Allow communication? (yes/no): ").strip().lower() == "yes"

    # Define the rule
    url = f"{BASE_URL}/define-rule"
    payload = {
        "from_role": from_role,
        "to_role": to_role,
        "allow": allow
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        print(f"Rule from '{from_role}' to '{to_role}' defined successfully!")
    else:
        print(f"Failed to define rule from '{from_role}' to '{to_role}'.")
        print("Error:", response.json())

# Menu-driven interface
def main():
    while True:
        print("\n=== Smart Home Device Manager ===")
        print("1. Register a new device")
        print("2. Generate a token for a device")
        print("3. Define a communication rule")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            register_device()
        elif choice == "2":
            generate_token()
        elif choice == "3":
            define_rule()
        elif choice == "4":
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
