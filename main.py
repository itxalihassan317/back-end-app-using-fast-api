from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()

# Secret key
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Fake databases
users_db = {}
students = {}

# Security
security = HTTPBearer()

# Models
class User(BaseModel):
    username: str
    password: str

# ---------------- AUTH FUNCTIONS ---------------- #

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Token")

# ---------------- ROUTES ---------------- #

@app.get("/")
def home():
    return {"message": "API is running"}

# Register
@app.post("/register")
def register(user: User):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    users_db[user.username] = hash_password(user.password)
    return {"message": "User registered successfully"}

# Login
@app.post("/login")
def login(user: User):
    if user.username not in users_db:
        raise HTTPException(status_code=400, detail="User not found")

    if not verify_password(user.password, users_db[user.username]):
        raise HTTPException(status_code=400, detail="Wrong password")

    token = create_token({"username": user.username})
    return {"access_token": token}

# ---------------- PROTECTED STUDENT CRUD ---------------- #

# Create student
@app.post("/students")
def create_student(id: int, name: str, user=Depends(verify_token)):
    students[id] = name
    return {"message": "Student added", "data": students}

# Read all students
@app.get("/students")
def get_students(user=Depends(verify_token)):
    return students

# Update student
@app.put("/students/{id}")
def update_student(id: int, name: str, user=Depends(verify_token)):
    if id not in students:
        raise HTTPException(status_code=404, detail="Student not found")

    students[id] = name
    return {"message": "Updated", "data": students}

# Delete student
@app.delete("/students/{id}")
def delete_student(id: int, user=Depends(verify_token)):
    if id not in students:
        raise HTTPException(status_code=404, detail="Student not found")

    del students[id]
    return {"message": "Deleted"}