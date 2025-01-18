from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import Dict, List
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from datetime import datetime, timedelta
import jwt
from cryptography.fernet import Fernet
import logging

# Configuration Constants
SECRET_KEY = "your_strong_secret_key"  # Replace with a strong secret key
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_ENCRYPTION_KEY = Fernet.generate_key()  # Strong encryption key for database

fernet = Fernet(DATABASE_ENCRYPTION_KEY)
logging.basicConfig(level=logging.INFO)

# ECC Key Manager Class
class ECCKeyManager:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_private_key_pem(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

# In-Memory Databases for Devices and Rules
devices_db: Dict[str, Dict] = {}
rules_db: List[Dict[str, str]] = []  # Stores communication rules
roles_db: Dict[str, List[str]] = {
    "admin": [],
    "sensor": [],
    "actuator": []
}

# FastAPI Initialization
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Pydantic Models
class DeviceRegistrationRequest(BaseModel):
    device_id: str = Field(..., pattern="^[a-zA-Z0-9_-]{3,30}$")
    role: str
    metadata: Dict[str, str] = Field(default={})  # Additional device details

class RuleDefinition(BaseModel):
    from_role: str
    to_role: str
    allow: bool

class DeviceUpdateRequest(BaseModel):
    role: str = None
    metadata: Dict[str, str] = None

# JWT Token Management
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Helper Function to Encrypt Data
def encrypt_data(data: bytes) -> bytes:
    return fernet.encrypt(data)

def decrypt_data(data: bytes) -> bytes:
    return fernet.decrypt(data)

# API Endpoints
@app.post("/register")
def register_device(request: DeviceRegistrationRequest):
    if request.role not in roles_db:
        raise HTTPException(status_code=400, detail="Invalid role")

    if request.device_id in devices_db:
        raise HTTPException(status_code=400, detail="Device already registered")

    key_manager = ECCKeyManager()
    devices_db[request.device_id] = {
        "role": request.role,
        "metadata": request.metadata,
        "private_key": encrypt_data(key_manager.get_private_key_pem()),
        "public_key": key_manager.get_public_key_pem()
    }
    roles_db[request.role].append(request.device_id)
    logging.info(f"Device {request.device_id} registered successfully.")
    return {
        "message": "Device registered successfully",
        "public_key": key_manager.get_public_key_pem().decode()
    }

@app.post("/token")
def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    device_id = form_data.username
    if device_id not in devices_db:
        raise HTTPException(status_code=401, detail="Invalid device ID")

    access_token = create_access_token(
        {"sub": device_id}, 
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/public-key")
def get_public_key(device_id: str):
    if device_id not in devices_db:
        raise HTTPException(status_code=404, detail="Device not found")

    return {"public_key": devices_db[device_id]["public_key"].decode()}

@app.post("/define-rule")
def define_rule(rule: RuleDefinition):
    if rule.from_role not in roles_db or rule.to_role not in roles_db:
        raise HTTPException(status_code=400, detail="Invalid roles specified")

    rules_db.append({
        "from_role": rule.from_role,
        "to_role": rule.to_role,
        "allow": rule.allow
    })
    logging.info(f"Rule defined: {rule}")
    return {"message": "Rule defined successfully"}

@app.put("/update-device/{device_id}")
def update_device(device_id: str, update: DeviceUpdateRequest):
    if device_id not in devices_db:
        raise HTTPException(status_code=404, detail="Device not found")

    if update.role:
        if update.role not in roles_db:
            raise HTTPException(status_code=400, detail="Invalid role")
        old_role = devices_db[device_id]["role"]
        roles_db[old_role].remove(device_id)
        roles_db[update.role].append(device_id)
        devices_db[device_id]["role"] = update.role

    if update.metadata:
        devices_db[device_id]["metadata"].update(update.metadata)

    logging.info(f"Device {device_id} updated successfully.")
    return {"message": "Device updated successfully"}

@app.get("/devices")
def list_devices():
    return {"devices": devices_db}

@app.get("/key-agreement")
def key_agreement(device_id: str, peer_device_id: str):
    if device_id not in devices_db or peer_device_id not in devices_db:
        raise HTTPException(status_code=404, detail="Device not found")

    private_key = serialization.load_pem_private_key(
        decrypt_data(devices_db[device_id]["private_key"]), password=None
    )
    peer_public_key = serialization.load_pem_public_key(
        devices_db[peer_device_id]["public_key"]
    )

    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'smart_home'
    ).derive(shared_key)

    return {"derived_key": derived_key.hex()}



from fastapi.middleware.cors import CORSMiddleware

# Add CORS middleware to allow requests from React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React frontend URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

if __name__ == "__main__":
    print("Starting the server...")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8354)

