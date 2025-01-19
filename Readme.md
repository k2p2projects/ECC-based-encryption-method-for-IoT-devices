# Smart Home Device Manager

## Overview
The **Smart Home Device Manager** is a system designed to enable secure, efficient, and organized communication between devices in a smart home environment. The platform ensures device authentication, role-based communication rules, and secure key management for encrypted data exchange.

This project was developed by :
- [**KANCHAN PATKAR**](https://github.com/k2p2projects)
- [**ALOK SINGH**](https://github.com/aloks1490)
- [**RUDRESH BIJAWE**](https://github.com/bijawerudresh)
- [**SAMYAK DANDE**](https://github.com/samyakdande)

## Tech stack
- Languages & Frameworks:
  1. Python with FastAPI for API development.
  2. Cryptography library for ECC and Fernet-based encryption.
  3. JWT for secure and tokenized device authentication.

- Architecture Overview:
  1. Backend: FastAPI handles device registration, authentication, and communication rule management.
  2. Encryption: ECC generates secure key pairs, and Fernet encrypts sensitive data.
  3. Tokenization: JWT tokens ensure secure and time-limited access.
  
## Key Features
1. **Device Registration**:
   - Devices can be registered with unique IDs and roles (e.g., sensor, actuator, admin).
   - Metadata can be added for additional device details.

2. **Role-Based Communication Rules**:
   - Define communication permissions between devices based on their roles.
   - Granular control to allow or restrict interactions between devices.

3. **Secure Token-Based Authentication**:
   - Devices use secure JWT-based tokens for authentication and communication.
   - Prevents unauthorized access and ensures integrity.

4. **ECC-Based Key Management**:
   - Devices generate ECC (Elliptic Curve Cryptography) key pairs for secure communication.
   - Shared keys are derived using ECDH (Elliptic Curve Diffie-Hellman) for encrypted data exchange.

5. **Database Encryption**:
   - Device details and private keys are securely stored using strong encryption (Fernet).

6. **CORS Support**:
   - The server supports cross-origin requests, allowing integration with a React-based frontend.

7. **Interactive Client Application**:
   - A Python CLI-based client for device registration, token generation, and rule definition.

## Installation

### Prerequisites
- Python 3.8 or higher
- Virtual environment (optional but recommended)
- Required Python libraries (see `requirements.txt`)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/smart-home-device-manager.git
   cd smart-home-device-manager
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
3. Start the FastAPI server:
   ```bash
   python server.py
4. Use the CLI client:
   ```bash
   python device_client.py

## Usage
### 1. Device Registration
1. Start the client application.
2. Select the option to register a device.
3. Provide the required details (device ID, role, metadata).
### 2. Token Generation
1. Choose the option to generate a token for a device.
2. Provide the device ID to obtain a secure access token.
### 3. Define Communication Rules
1. Select the option to define a rule.
2. Provide the sender and receiver roles and set the permission.
### 4. Encrypted Key Agreement
- Use the /key-agreement endpoint to derive a shared key between two devices for secure communication.
## Problem-Solving Capabilities
The **Smart Home Device Manager** addresses critical challenges in managing smart home devices:

1. **Unauthorized Access Prevention:**

 - Ensures only registered devices with valid tokens can communicate within the network.
2. **Role-Based Communication:**

 - Allows fine-grained control over which devices can interact, minimizing security risks.
3. **Secure Communication:**

 - ECC and derived shared keys ensure that communication between devices is encrypted and tamper-proof.
4. **Dynamic and Scalable Management:**

 - Administrators can add, update, or define rules for devices dynamically, ensuring adaptability to changing requirements.
5. **Data Integrity and Confidentiality:**

 - Sensitive device information is encrypted before storage, preventing data breaches.
6. **Ease of Integration:**

 - RESTful API design with CORS support enables seamless integration with web-based or mobile applications.


## API Endpoints

| Endpoint               | Method | Description                                    |
|------------------------|--------|------------------------------------------------|
| `/register`            | POST   | Registers a new device                        |
| `/token`               | POST   | Generates an access token for a device        |
| `/public-key`          | GET    | Retrieves the public key of a device          |
| `/define-rule`         | POST   | Defines a communication rule between roles    |
| `/update-device/{id}`  | PUT    | Updates device role or metadata               |
| `/devices`             | GET    | Lists all registered devices                  |
| `/key-agreement`       | GET    | Derives a shared key between two devices      |



## Future Enhancements
- Support for more advanced device roles and interactions.
- Web-based dashboard for easier device and rule management.
- Real-time event monitoring for devices.
