from PIL import Image
import time
import PIL.ImageOps
import io
import uvicorn
from fastapi import FastAPI, File, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from fastapi.responses import FileResponse,  StreamingResponse
import datetime
from datetime import datetime, timedelta

app = FastAPI()

#################################################################

# PART 1
"""
1. Endpoint that checks if a given number is prime (range up to 9223372036854775807). We do not assume that the input data is correct.
"""
numbers=range(0,9223372036854775808)

@app.get("/prime/{number}")
async def is_prime(number):
    if number.isnumeric():
        num=int(number)
        if (num in numbers):
            if (num==1 or num==0):
                return f'Number {num} is not prime'
            else:
                for i in range(2,num):
                    if num%i==0:
                        return f'Number {num} is not prime'
            return f'Number {num} is prime'

        return f'Number {num} is not in a range of 0 to 9223372036854775807'
    else:
        return f'It is not a number'

#################################################################

# PART 2 
"""
Endpoint that returns the color inversion of an image. 
	Assumptions:
	* JPG type with a maximum size of 12 MPix.
	* input data are correct
"""

def invert(img):
    inverted_image = PIL.ImageOps.invert(Image.open(io.BytesIO(img)))
    inv = io.BytesIO()
    inverted_image.save(inv, format='JPEG')
    inv.seek(0)
    return inv

@app.post("/picture/invert")
async def invert_image(file: bytes = File(...)):
    return StreamingResponse(invert(file), media_type="image/jpeg")

#################################################################
# PART 3
"""
Endpoint with authentication returning the current time.

Authentication data:
username:joannadeszcz
password:informatics
"""
fake_users_db = {
    "joannadeszcz": {
        "username": "joannadeszcz",
        "hashed_password": "fakehashedinformatyka",
    }
    
}

def fake_hash_password(password: str):
    return "fakehashed" + password


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@app.post("/time")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
        
    return datetime.now().strftime("%H:%M:%S")



