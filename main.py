import jwt
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from starlette import status
from passlib.hash import bcrypt
from tortoise.contrib.fastapi import HTTPNotFoundError, register_tortoise
from fastapi.templating import Jinja2Templates
from models import User, User_Pydantic, UserIn_Pydantic

app = FastAPI()

JWT_SECRET = 'myjwtsecret'

templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


oauth2 = OAuth2PasswordBearer(tokenUrl='token')


async def auth_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user


@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await auth_user(form_data.username, form_data.password)
    if not user:
        return {'error': 'invalid credentials'}
    user_obj = await User_Pydantic.from_tortoise_orm(user)

    token = jwt.encode(user_obj.dict(), JWT_SECRET)

    return {'access_token': token, 'token_type': 'bearer'}


async def get_current_user(token: str = Depends(oauth2)):
    try:
        payload = jwt.encode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Invalid username or password'
                            )
    return await User_Pydantic.from_tortoise_orm(user)


@app.post('/users', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(username=user.username, password=bcrypt.hash(user.password))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)


@app.get('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user

register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)