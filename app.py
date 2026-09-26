import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from livekit.api import AccessToken, VideoGrants
from dotenv import load_dotenv

load_dotenv()

# ================= CONFIG =================
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-in-production-xyz123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

LIVEKIT_URL = os.getenv("LIVEKIT_URL", "wss://your-livekit-server.livekit.cloud")
LIVEKIT_API_KEY = os.getenv("LIVEKIT_API_KEY", "APIxxxxxxxx")
LIVEKIT_API_SECRET = os.getenv("LIVEKIT_API_SECRET", "secretxxxxxxxx")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./livestream.db")

# ================= DB =================
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="LiveStream Pro API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static uploads
os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


# ================= MODELS =================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Room(Base):
    __tablename__ = "rooms"
    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(String(36), unique=True, index=True, nullable=False)
    title = Column(String(200), nullable=False)
    host_username = Column(String(50), nullable=False)
    is_public = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    viewer_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    thumbnail = Column(String(500), nullable=True)  # optional image url


Base.metadata.create_all(bind=engine)


# ================= SCHEMAS =================
class UserCreate(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class RoomCreate(BaseModel):
    title: str
    is_public: bool = True


class RoomOut(BaseModel):
    room_id: str
    title: str
    host_username: str
    is_public: bool
    is_active: bool
    viewer_count: int
    created_at: datetime
    thumbnail: Optional[str] = None

    class Config:
        from_attributes = True


class TokenRequest(BaseModel):
    room_id: str
    identity: str
    role: str = "viewer"  # host | viewer | cohost


# ================= HELPERS =================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


def create_livekit_token(identity: str, room_name: str, role: str = "viewer") -> str:
    """Generate LiveKit access token.
    All roles can publish so Co-host works after Host approves.
    (Host still controls who is allowed via the app UI.)
    """
    token = AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET)
    token.with_identity(identity).with_name(identity)

    grant = VideoGrants(
        room_join=True,
        room=room_name,
        can_publish=True,          # needed for Co-host to publish camera
        can_subscribe=True,
        can_publish_data=True,
        can_update_own_metadata=True,
    )
    token.with_grants(grant)
    return token.to_jwt()


# ================= ROUTES =================
@app.get("/")
def root():
    return {"status": "ok", "app": "LiveStream Pro API"}


@app.post("/register", status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if len(user.username) < 3:
        raise HTTPException(status_code=400, detail="Username too short")
    if len(user.password) < 4:
        raise HTTPException(status_code=400, detail="Password too short")

    db_user = User(
        username=user.username,
        hashed_password=get_password_hash(user.password),
    )
    db.add(db_user)
    db.commit()
    return {"message": "User created successfully"}


@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer", "username": user.username}


@app.post("/rooms", response_model=RoomOut)
def create_room(
    room: RoomCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    room_id = str(uuid.uuid4())[:8]  # short nice id
    db_room = Room(
        room_id=room_id,
        title=room.title or "Live Stream",
        host_username=current_user.username,
        is_public=room.is_public,
        is_active=True,
        viewer_count=0,
    )
    db.add(db_room)
    db.commit()
    db.refresh(db_room)
    return db_room


@app.get("/rooms", response_model=List[RoomOut])
def list_rooms(
    active_only: bool = True,
    public_only: bool = True,
    db: Session = Depends(get_db),
):
    """List active public lives for the Discover / Feed page"""
    q = db.query(Room)
    if active_only:
        q = q.filter(Room.is_active == True)
    if public_only:
        q = q.filter(Room.is_public == True)
    rooms = q.order_by(Room.created_at.desc()).limit(50).all()
    return rooms


@app.get("/rooms/{room_id}", response_model=RoomOut)
def get_room(room_id: str, db: Session = Depends(get_db)):
    room = db.query(Room).filter(Room.room_id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    return room


@app.post("/rooms/{room_id}/end")
def end_room(
    room_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    room = db.query(Room).filter(Room.room_id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    if room.host_username != current_user.username:
        raise HTTPException(status_code=403, detail="Only host can end the live")
    room.is_active = False
    room.ended_at = datetime.utcnow()
    db.commit()
    return {"message": "Live ended"}


@app.post("/token")
def get_token(
    req: TokenRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    room = db.query(Room).filter(Room.room_id == req.room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    if not room.is_active:
        raise HTTPException(status_code=400, detail="This live has ended")

    # Only host can request host role
    role = req.role
    if role == "host" and room.host_username != current_user.username:
        role = "viewer"

    # Update viewer count roughly
    room.viewer_count = (room.viewer_count or 0) + 1
    db.commit()

    token = create_livekit_token(
        identity=req.identity or current_user.username,
        room_name=req.room_id,
        role=role,
    )
    return {
        "token": token,
        "url": LIVEKIT_URL,
        "room_id": req.room_id,
        "role": role,
    }


@app.post("/upload")
async def upload_image(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    """Upload image/GIF for overlay or thumbnail"""
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    ext = file.filename.split(".")[-1] if file.filename and "." in file.filename else "jpg"
    filename = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join("uploads", filename)

    content = await file.read()
    if len(content) > 5 * 1024 * 1024:  # 5MB limit
        raise HTTPException(status_code=400, detail="File too large (max 5MB)")

    with open(path, "wb") as f:
        f.write(content)

    # Return public URL (relative – frontend should prepend API_URL)
    return {"url": f"/uploads/{filename}", "filename": filename}


@app.patch("/rooms/{room_id}/thumbnail")
def set_thumbnail(
    room_id: str,
    url: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    room = db.query(Room).filter(Room.room_id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    if room.host_username != current_user.username:
        raise HTTPException(status_code=403, detail="Only host can set thumbnail")
    room.thumbnail = url
    db.commit()
    return {"message": "Thumbnail updated"}


# Health
@app.get("/health")
def health():
    return {"status": "healthy"}
