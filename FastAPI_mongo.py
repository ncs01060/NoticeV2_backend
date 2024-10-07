from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import datetime
import base64
from bson import ObjectId

SECRET_KEY = "youngmin"  # 보안을 위해 실제 비밀 키를 사용하세요
ALGORITHM = "HS256"

uri = "mongodb+srv://youngmin:youngmin@cluster0.crahbwt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri, server_api=ServerApi('1'))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()

# CORS 설정
origins = [
    "http://localhost:3000",  # React 개발 서버
    "http://127.0.0.1:3000"  # React 개발 서버의 또 다른 형태
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    email: str
    coin:int
    name: str
    password: str

class CheckUser(BaseModel):
    email:str

class UserLogin(BaseModel):
    email: str
    password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        name:str = payload.get("name")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"email":email,"name":name}
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/")
def main():
    return {"message": "hello"}

@app.get("/check")
def check():
    db = client['Cluster0']
    data = db.list_collection_names()
    bytes = str(data).encode('UTF-8')
    result = base64.b64encode(bytes)
    result_str = result.decode('ascii')
    return {"names": result_str}

@app.post("/signup")
def signup(user: User):
    db = client['Cluster0']
    user.password = get_password_hash(user.password)
    post = {
        "email": user.email,
        "name": user.name,
        "coin":user.coin,
        "password": user.password,
        "date": datetime.datetime.utcnow()
    }
    users = db.users
    user_id = users.insert_one(post).inserted_id
    access_token_expires = datetime.timedelta(minutes=30)  # 만료 시간을 30분으로 설정
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login")
def login(user: UserLogin):
    db = client['Cluster0']
    users = db.users
    user_record = users.find_one({"email": user.email})
    if not user_record or not verify_password(user.password, user_record['password']):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    access_token_expires = datetime.timedelta(minutes=30)
    name = user_record['name']  # 만료 시간을 30분으로 설정
    access_token = create_access_token(data={"sub": user.email,"name":name}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected-endpoint")
async def protected_route(token: str = Depends(oauth2_scheme)):
    dic = verify_access_token(token)
    db = client['Cluster0']
    users = db.users
    coins = users.find_one({"email": dic['email']})
    coins = coins['coin']+1
    users.update_one({"email":dic["email"]}, {"$set":{"coin" :coins}})
    return {"message": f"이 보호된 데이터에 접근할 수 있습니다! 사용자: {dic['email']} | name : {dic['name']} | {coins}"}


@app.get("/search_posts")
async def search_posts(token: str = Depends(oauth2_scheme)):
    dic = verify_access_token(token)
    db = client['Cluster0']
    posts = db.posts
    
    # MongoDB에서 _id와 title 필드만 가져오기
    results = posts.find({}, {"_id": 1, "title": 1})
    
    # 결과를 리스트로 변환
    ids_list = []
    title_list = []
    
    for post in results:
        ids_list.append(str(post["_id"]))
        title_list.append(post["title"])
    
    return {"email": dic["email"], "titles": title_list, "ids": ids_list}

@app.get("/Posts/{_id}")
async def search_posts(_id:str,token: str = Depends(oauth2_scheme)):
    dic = verify_access_token(token)
    db = client['Cluster0']
    posts = db.posts
    id = ObjectId(_id)
    
    # MongoDB에서 _id에 해당하는 게시물 가져오기
    result = posts.find_one({'_id': id})

    # 결과를 JSON으로 직렬화 가능하게 변환
    if result:
        result['_id'] = str(result['_id'])  # ObjectId를 문자열로 변환
        return result
    else:
        return {"error": "Post not found"}, 404  # 게시물