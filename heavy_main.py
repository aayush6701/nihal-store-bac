from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
import hashlib
from jose import JWTError, jwt
from datetime import datetime, timedelta
from bson import ObjectId
import os
from fastapi import File, UploadFile, Form
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from bson.errors import InvalidId
from typing import List
from typing import Optional
from fastapi.requests import Request
import traceback
from fastapi import Query


# ------------------------------
# FastAPI app
# ------------------------------
app = FastAPI()

# Allow all origins (for dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------
# MongoDB Connection
# ------------------------------
client = MongoClient("mongodb://localhost:27017/")  # change if Atlas
db = client["nihalstore"]
admin_collection = db["admins"]
user_collection = db["users"] 
theme_collection = db["themes"]
category_collection = db["categories"]
product_collection = db["products"]
homepage_collection = db["homepage"]
chat_collection = db["chats"]




# ------------------------------
# Upload directory setup
# ------------------------------
THEME_UPLOAD_DIR = Path("uploads/themes")
THEME_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
CATEGORY_UPLOAD_DIR = Path("uploads/category")
CATEGORY_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
PRODUCT_UPLOAD_DIR = Path("uploads/products")
PRODUCT_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
from fastapi.responses import FileResponse, Response

@app.get("/uploads/{folder}/{filename}")
async def serve_file(folder: str, filename: str):
    file_path = Path("uploads") / folder / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    response = FileResponse(file_path)
    response.headers["Access-Control-Allow-Origin"] = "*"   # allow all origins
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Expose-Headers"] = "*" # expose headers if needed
    return response


# ------------------------------
# JWT Config
# ------------------------------
SECRET_KEY = "supersecretkey"  # 🔴 change in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 hours


def create_access_token(data: dict, expires_delta: timedelta = None):
    """Generate a JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Header(...)):
    """Verify JWT token from header"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Please re-login. Your session has expired or token is invalid."
        )

# ------------------------------
# Models
# ------------------------------
class AdminRegister(BaseModel):
    username: str
    password: str

class AdminLogin(BaseModel):
    username: str
    password: str

class AddAdmin(BaseModel):
    name: str
    email: EmailStr   # ⬅ change from str → EmailStr
    password: str
class EditAdmin(BaseModel):
    name: str
    email: EmailStr
    password: str   # required when editing

class AddHomepageSection(BaseModel):
    category_id: str
    product_ids: List[str]


class EditHomepageSection(BaseModel):
    category_id: str
    product_ids: List[str]
    s_no: Optional[int] = None

# ------------------------------
# Helpers
# ------------------------------
def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

# ------------------------------
# Routes
# ------------------------------



@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    # Special case for expired/invalid token
    if exc.status_code == 401:
        return JSONResponse(
            status_code=401,
            content={
                "error": True,
                "status_code": 401,
                "method": request.method,
                "path": request.url.path,
                "message": "Please re-login. Your session has expired or token is invalid.",
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    # Default handling for all other HTTPExceptions
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "method": request.method,
            "path": request.url.path,
            "message": str(exc.detail),
            "hint": "Check the request payload and headers.",
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


@app.exception_handler(Exception)
async def custom_general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "status_code": 500,
            "method": request.method,
            "path": request.url.path,
            "message": str(exc),
            "trace": traceback.format_exc(limit=2),  # 🔹 last 2 lines of error stack
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


# ✅ Register route
@app.post("/admin/register")
def admin_register(data: AdminRegister):
    # check if username exists
    if admin_collection.find_one({"username": data.username}):
        raise HTTPException(status_code=400, detail="Username already exists")

    # insert new admin with hashed password
    new_admin = {
        "username": data.username,
        "password": hash_password(data.password)
    }
    result = admin_collection.insert_one(new_admin)

    return {"message": "Admin registered successfully", "admin_id": str(result.inserted_id)}

# ✅ Login route (returns JWT token)
@app.post("/admin/login")
def admin_login(data: AdminLogin):
    admin = admin_collection.find_one({"username": data.username})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if admin["password"] != hash_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # create token
    access_token = create_access_token({"sub": data.username})
    return {"access_token": access_token, "token_type": "bearer"}

# ✅ Add Admin (protected)
@app.post("/admin/add")
def add_admin(data: AddAdmin, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # check if email already exists
    if admin_collection.find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Admin with this email already exists")

    # insert new admin with hashed password (no created_by, created_at)
    new_admin = {
        "name": data.name,
        "email": data.email,
        "password": hash_password(data.password)
    }
    admin_collection.insert_one(new_admin)

    return {"message": "Admin added successfully"}




@app.get("/all-users")
def get_all_users(token: dict = Depends(verify_token)):
    admins = list(admin_collection.find({}, {"_id": 1, "name": 1, "email": 1}))
    users = list(user_collection.find({}, {"_id": 1, "name": 1, "email": 1}))

    result = []

    # admins → role = Admin
    for a in admins:
        name = a.get("name") or (a["email"].split("@")[0] if "email" in a else "Unknown")
        result.append({
            "id": str(a["_id"]),
            "name": name,
            "email": a.get("email", ""),
            "role": "Admin"
        })

    # users → role = Customer
    for u in users:
        name = u.get("name") or (u["email"].split("@")[0] if "email" in u else "Unknown")
        result.append({
            "id": str(a["_id"]),
            "name": name,
            "email": u.get("email", ""),
            "role": "Customer"
        })

    return {
        "users": result,
        "total_admins": len(admins),
        "total_users": len(users)
    }

@app.put("/admin/edit/{admin_id}")
def edit_admin(admin_id: str, data: EditAdmin, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # require all fields
    if not all([data.name, data.email, data.password]):
        raise HTTPException(status_code=400, detail="All fields are required")

    updated_admin = {
        "name": data.name,
        "email": data.email,
        "password": hash_password(data.password),
    }

    result = admin_collection.update_one({"_id": ObjectId(admin_id)}, {"$set": updated_admin})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Admin not found")

    return {"message": "Admin updated successfully"}


@app.delete("/admin/delete/{admin_id}")
def delete_admin(admin_id: str, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    result = admin_collection.delete_one({"_id": ObjectId(admin_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Admin not found")

    return {"message": "Admin deleted successfully"}

def get_folder_size(folder: Path) -> float:
    """Return folder size in GB"""
    total_size = 0
    for dirpath, _, filenames in os.walk(folder):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total_size += os.path.getsize(fp)
    return total_size / (1024 ** 3)  # GB

@app.post("/themes/add")
async def add_theme(
    name: str = Form(...),
    file: UploadFile = File(...),
    token: dict = Depends(verify_token)
):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # check upload folder size
    current_size = get_folder_size(Path("uploads"))
    if current_size >= 98:
        raise HTTPException(status_code=507, detail="Database is full (Uploads reached 98GB)")

    # ❌ check if theme name already exists
    if theme_collection.find_one({"name": name}):
        raise HTTPException(status_code=400, detail="Theme with this name already exists")

    # only allow jpeg/png
    if file.content_type not in ["image/jpeg", "image/png"]:
        raise HTTPException(status_code=400, detail="Only JPEG or PNG allowed")

    # unique filename
    file_ext = ".jpg"
    file_name = f"{ObjectId()}{file_ext}"
    file_path = THEME_UPLOAD_DIR / file_name

    # save file to disk
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    # insert into DB
    theme_doc = {
        "name": name,
        "image_url": f"/uploads/themes/{file_name}"
    }
    theme_collection.insert_one(theme_doc)

    return {"message": "Theme added successfully"}



@app.get("/themes/list")
def list_themes(token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    themes = list(theme_collection.find({}, {"_id": 1, "name": 1, "image_url": 1}))
    formatted_themes = [
        {
            "_id": str(theme["_id"]),
            "name": theme["name"],
            "image_url": theme["image_url"],
        }
        for theme in themes
    ]

    return {
        "themes": formatted_themes,
        "total_themes": len(formatted_themes)
    }




@app.put("/themes/edit/{theme_id}")
async def edit_theme(
    theme_id: str,
    name: str = Form(...),
    file: UploadFile = File(None),
    token: dict = Depends(verify_token)
):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    theme = theme_collection.find_one({"_id": ObjectId(theme_id)})
    if not theme:
        raise HTTPException(status_code=404, detail="Theme not found")

    # ❌ check if another theme with same name exists
    if theme_collection.find_one({"name": name, "_id": {"$ne": ObjectId(theme_id)}}):
        raise HTTPException(status_code=400, detail="Theme with this name already exists")

    update_data = {"name": name}

    # if new file is uploaded
    if file:
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Only JPEG or PNG allowed")

        file_ext = ".jpg"
        file_name = f"{ObjectId()}{file_ext}"
        file_path = THEME_UPLOAD_DIR / file_name

        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())

        update_data["image_url"] = f"/uploads/themes/{file_name}"

        # remove old file
        old_path = theme.get("image_url")
        if old_path:
            old_disk_path = Path("." + old_path)
            if old_disk_path.exists():
                try:
                    os.remove(old_disk_path)
                except:
                    pass

    theme_collection.update_one({"_id": ObjectId(theme_id)}, {"$set": update_data})

    return {"message": "Theme updated successfully"}




@app.delete("/themes/delete/{theme_id}")
def delete_theme(theme_id: str, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    theme = theme_collection.find_one({"_id": ObjectId(theme_id)})
    if not theme:
        raise HTTPException(status_code=404, detail="Theme not found")

    # remove file from disk (optional)
    if theme.get("image_url"):
        file_path = Path("." + theme["image_url"])
        if file_path.exists():
            try:
                os.remove(file_path)
            except:
                pass

    theme_collection.delete_one({"_id": ObjectId(theme_id)})
    return {"message": "Theme deleted successfully"}



@app.post("/categories/add")
async def add_category(
    name: str = Form(...),
    file: UploadFile = File(...),
    token: dict = Depends(verify_token)
):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # check folder size
    current_size = get_folder_size(Path("uploads"))
    if current_size >= 98:
        raise HTTPException(status_code=507, detail="Database is full (Uploads reached 98GB)")

    # prevent duplicate names
    if category_collection.find_one({"name": name}):
        raise HTTPException(status_code=400, detail="Category with this name already exists")

    if file.content_type not in ["image/jpeg", "image/png"]:
        raise HTTPException(status_code=400, detail="Only JPEG or PNG allowed")

    file_ext = ".jpg"
    file_name = f"{ObjectId()}{file_ext}"
    file_path = CATEGORY_UPLOAD_DIR / file_name

    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    category_doc = {
        "name": name,
        "image_url": f"/uploads/category/{file_name}"
    }
    category_collection.insert_one(category_doc)

    return {"message": "Category added successfully"}


@app.get("/categories/list")
def list_categories(token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    categories = list(category_collection.find({}, {"_id": 1, "name": 1, "image_url": 1}))
    formatted_categories = [
        {
            "_id": str(cat["_id"]),
            "name": cat["name"],
            "image_url": cat["image_url"],
        }
        for cat in categories
    ]

    return {
        "categories": formatted_categories,
        "total_categories": len(formatted_categories)
    }


@app.put("/categories/edit/{category_id}")
async def edit_category(
    category_id: str,
    name: str = Form(...),
    file: UploadFile = File(None),
    token: dict = Depends(verify_token)
):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    category = category_collection.find_one({"_id": ObjectId(category_id)})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    # check duplicate name
    if category_collection.find_one({"name": name, "_id": {"$ne": ObjectId(category_id)}}):
        raise HTTPException(status_code=400, detail="Category with this name already exists")

    update_data = {"name": name}

    if file:
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Only JPEG or PNG allowed")

        file_ext = ".jpg"
        file_name = f"{ObjectId()}{file_ext}"
        file_path = CATEGORY_UPLOAD_DIR / file_name

        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())

        update_data["image_url"] = f"/uploads/category/{file_name}"

        # delete old file
        old_path = category.get("image_url")
        if old_path:
            old_disk_path = Path("." + old_path)
            if old_disk_path.exists():
                try:
                    os.remove(old_disk_path)
                except:
                    pass

    category_collection.update_one({"_id": ObjectId(category_id)}, {"$set": update_data})

    return {"message": "Category updated successfully"}



@app.delete("/categories/delete/{category_id}")
def delete_category(category_id: str, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    category = category_collection.find_one({"_id": ObjectId(category_id)})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    # delete file
    old_path = category.get("image_url")
    if old_path:
        old_disk_path = Path("." + old_path)
        if old_disk_path.exists():
            try:
                os.remove(old_disk_path)
            except:
                pass

    result = category_collection.delete_one({"_id": ObjectId(category_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")

    return {"message": "Category deleted successfully"}


@app.post("/products/add")
async def add_product(
    name: str = Form(...),
    category_id: str = Form(...),
    theme_id: str = Form(...),
    selling_price: float = Form(...),
    mrp: float = Form(...),
    availability: str = Form(...),
    description: str = Form(...),
    display_image: UploadFile = File(None),
    hover_image: UploadFile = File(None),
    additional_images: list[UploadFile] = File([]),   # optional array
    token: dict = Depends(verify_token)
):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # check folder size limit
    current_size = get_folder_size(Path("uploads"))
    if current_size >= 98:
        raise HTTPException(status_code=507, detail="Database is full (Uploads reached 98GB)")

    # validate availability
    if availability not in ["In Stock", "Sold Out"]:
        raise HTTPException(status_code=400, detail="Invalid availability")

    # helper for saving a file
    async def save_file(file: UploadFile, subfolder="products"):
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Only JPEG or PNG allowed")
        file_name = f"{ObjectId()}.jpg"
        file_path = PRODUCT_UPLOAD_DIR / file_name
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
        return f"/uploads/products/{file_name}"

    # save images
    display_url = await save_file(display_image) if display_image else None
    hover_url = await save_file(hover_image) if hover_image else None
    additional_urls = []
    for file in additional_images:
        if file:
            additional_urls.append(await save_file(file))


    # insert into DB
    product_doc = {
        "name": name,
        "category_id": ObjectId(category_id),
        "theme_id": ObjectId(theme_id),
        "selling_price": selling_price,
        "mrp": mrp,
        "availability": availability,
        "description": description,
        "display_image": display_url,
        "hover_image": hover_url,
        "additional_images": additional_urls,
       
    }
    product_collection.insert_one(product_doc)

    return {"message": "Product added successfully"}


@app.get("/products/list")
def list_products(token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    products = list(product_collection.find({}))
    formatted_products = []
    for p in products:
        cat = category_collection.find_one({"_id": ObjectId(p["category_id"])}, {"name": 1})
        theme = theme_collection.find_one({"_id": ObjectId(p["theme_id"])}, {"name": 1})

        formatted_products.append({
        "_id": str(p["_id"]),
        "name": p["name"],
        "category_id": str(p["category_id"]),   # ✅ include raw ObjectId
        "category_name": cat["name"] if cat else "N/A",
        "theme_id": str(p["theme_id"]),         # ✅ include raw ObjectId
        "theme_name": theme["name"] if theme else "N/A",
        "selling_price": p["selling_price"],
        "mrp": p["mrp"],
        "availability": p["availability"],
        "description": p["description"],
        "display_image": p["display_image"],
        "hover_image": p["hover_image"],
        "additional_images": p.get("additional_images", []),
    })


    return {"products": formatted_products, "total_products": len(formatted_products)}


@app.put("/products/edit/{product_id}")
async def edit_product(
    product_id: str,
    name: str = Form(...),
    category_id: str = Form(...),
    theme_id: str = Form(...),
    selling_price: float = Form(...),
    mrp: float = Form(...),
    availability: str = Form(...),
    description: str = Form(...),
    display_image: UploadFile = File(None),
    hover_image: UploadFile = File(None),
    additional_images: list[UploadFile] = File([]),
    removed_images: str = Form("[]"),   # ✅ NEW field (JSON array)
    token: dict = Depends(verify_token)
):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    product = product_collection.find_one({"_id": ObjectId(product_id)})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # helper to save file
    async def save_file(file: UploadFile):
        if file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Only JPEG or PNG allowed")
        file_name = f"{ObjectId()}.jpg"
        file_path = PRODUCT_UPLOAD_DIR / file_name
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
        return f"/uploads/products/{file_name}"


    update_data = {
        "name": name,
        "selling_price": selling_price,
        "mrp": mrp,
        "availability": availability,
        "description": description,
    }

    # only update if valid ObjectIds are provided
    try:
        if category_id and category_id.strip():
            update_data["category_id"] = ObjectId(category_id)
        if theme_id and theme_id.strip():
            update_data["theme_id"] = ObjectId(theme_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Invalid category_id or theme_id")


    # ✅ handle deletions (from frontend "removed_images")
    import json
    removed = json.loads(removed_images)

    if "display" in removed and product.get("display_image"):
        old_path = Path("." + product["display_image"])
        if old_path.exists():
            try: os.remove(old_path)
            except: pass
        update_data["display_image"] = None

    if "hover" in removed and product.get("hover_image"):
        old_path = Path("." + product["hover_image"])
        if old_path.exists():
            try: os.remove(old_path)
            except: pass
        update_data["hover_image"] = None

    # remove only the marked additional images
    if any(r.startswith("additional") for r in removed):
        current_additional = product.get("additional_images", [])
        remaining = []
        for idx, old in enumerate(current_additional):
            if f"additional_{idx}" in removed:
                old_path = Path("." + old)
                if old_path.exists():
                    try:
                        os.remove(old_path)
                    except:
                        pass
            else:
                remaining.append(old)  # keep unremoved
        update_data["additional_images"] = remaining


    # ✅ handle new display image
    if display_image:
        new_url = await save_file(display_image)
        update_data["display_image"] = new_url
        old = product.get("display_image")
        if old:
            old_path = Path("." + old)
            if old_path.exists():
                try: os.remove(old_path)
                except: pass

    # ✅ handle new hover image
    if hover_image:
        new_url = await save_file(hover_image)
        update_data["hover_image"] = new_url
        old = product.get("hover_image")
        if old:
            old_path = Path("." + old)
            if old_path.exists():
                try: os.remove(old_path)
                except: pass

    # ✅ replace additional images if new ones uploaded
    if additional_images:
        new_urls = []
        for f in additional_images:
            if f:
                new_urls.append(await save_file(f))

        if new_urls:
            # merge with what’s left after removals
            current_remaining = update_data.get("additional_images", product.get("additional_images", []))
            update_data["additional_images"] = current_remaining + new_urls

    product_collection.update_one({"_id": ObjectId(product_id)}, {"$set": update_data})

    return {"message": "Product updated successfully"}


@app.delete("/products/delete/{product_id}")
def delete_product(product_id: str, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    product = product_collection.find_one({"_id": ObjectId(product_id)})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # delete files from disk
    for key in ["display_image", "hover_image"]:
        if product.get(key):
            file_path = Path("." + product[key])
            if file_path.exists():
                try: os.remove(file_path)
                except: pass

    for img in product.get("additional_images", []):
        file_path = Path("." + img)
        if file_path.exists():
            try: os.remove(file_path)
            except: pass

    product_collection.delete_one({"_id": ObjectId(product_id)})

    return {"message": "Product deleted successfully"}

@app.get("/dashboard/stats")
def get_dashboard_stats(token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    total_users = user_collection.count_documents({})
    total_admins = admin_collection.count_documents({})
    total_products = product_collection.count_documents({})
    total_categories = category_collection.count_documents({})
    total_themes = theme_collection.count_documents({})

    # Availability split
    in_stock = product_collection.count_documents({"availability": "In Stock"})
    sold_out = product_collection.count_documents({"availability": "Sold Out"})

    return {
        "total_users": total_users + total_admins,
        "total_admins": total_admins,
        "total_products": total_products,
        "total_categories": total_categories,
        "total_themes": total_themes,
        "in_stock": in_stock,
        "sold_out": sold_out
    }


@app.post("/homepage/add")
def add_homepage_section(data: AddHomepageSection, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # 1. check limit of 4 sections
    count = homepage_collection.count_documents({})
    if count >= 4:
        raise HTTPException(status_code=400, detail="Max 4 homepage sections allowed")

    # 2. validate category exists
    try:
        cat_id = ObjectId(data.category_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid category_id")

    category = category_collection.find_one({"_id": cat_id})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    # 3. validate product ids
    if len(data.product_ids) == 0:
        raise HTTPException(status_code=400, detail="At least 1 product required")
    if len(data.product_ids) > 12:
        raise HTTPException(status_code=400, detail="Max 12 products allowed")

    product_obj_ids = []
    for pid in data.product_ids:
        try:
            product_obj_ids.append(ObjectId(pid))
        except:
            raise HTTPException(status_code=400, detail=f"Invalid product id: {pid}")

    # 4. auto increment s_no
    last_doc = homepage_collection.find_one(sort=[("s_no", -1)])
    next_s_no = (last_doc["s_no"] + 1) if last_doc else 1

    # 5. insert
    doc = {
        "s_no": next_s_no,
        "category_id": cat_id,
        "products": product_obj_ids
    }
    homepage_collection.insert_one(doc)

    return {"message": "Homepage section added", "s_no": next_s_no}


@app.get("/homepage/list")
def list_homepage_sections(token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    sections = list(homepage_collection.find().sort("s_no", 1))
    formatted = []
    for sec in sections:
        # fetch category
        cat = category_collection.find_one({"_id": sec["category_id"]}, {"name": 1})
        # fetch products
        prods = list(product_collection.find({"_id": {"$in": sec["products"]}}, {"name": 1, "display_image": 1}))

        formatted.append({
            "s_no": sec["s_no"],
            "category_id": str(sec["category_id"]),
            "category_name": cat["name"] if cat else "N/A",
            "products": [
                {"_id": str(p["_id"]), "name": p["name"], "display_image": p.get("display_image")}
                for p in prods
            ]
        })

    return {"sections": formatted}


@app.put("/homepage/edit/{s_no}")
def edit_homepage_section(s_no: int, data: EditHomepageSection, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # validate category
    try:
        cat_id = ObjectId(data.category_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid category_id")

    if not category_collection.find_one({"_id": cat_id}):
        raise HTTPException(status_code=404, detail="Category not found")

    # validate products
    if len(data.product_ids) == 0:
        raise HTTPException(status_code=400, detail="At least 1 product required")
    if len(data.product_ids) > 12:
        raise HTTPException(status_code=400, detail="Max 12 products allowed")

    product_obj_ids = []
    for pid in data.product_ids:
        try:
            product_obj_ids.append(ObjectId(pid))
        except:
            raise HTTPException(status_code=400, detail=f"Invalid product id: {pid}")

    # current doc
    current = homepage_collection.find_one({"s_no": s_no})
    if not current:
        raise HTTPException(status_code=404, detail="Homepage section not found")

    new_sno = data.s_no or s_no

    # --- SAFE SWAP LOGIC ---
    if new_sno != s_no:
        other = homepage_collection.find_one({"s_no": new_sno})
        if other:
            # Step 1: put "other" to a temp s_no so no duplicates
            homepage_collection.update_one(
                {"_id": other["_id"]},
                {"$set": {"s_no": -1}}
            )

            # Step 2: update current doc to new_sno
            homepage_collection.update_one(
                {"_id": current["_id"]},
                {"$set": {"category_id": cat_id, "products": product_obj_ids, "s_no": new_sno}}
            )

            # Step 3: move "other" to old s_no
            homepage_collection.update_one(
                {"_id": other["_id"]},
                {"$set": {"s_no": s_no}}
            )
        else:
            # new_sno is free, just update
            homepage_collection.update_one(
                {"_id": current["_id"]},
                {"$set": {"category_id": cat_id, "products": product_obj_ids, "s_no": new_sno}}
            )
    else:
        # no change in s_no
        homepage_collection.update_one(
            {"_id": current["_id"]},
            {"$set": {"category_id": cat_id, "products": product_obj_ids}}
        )

    return {"message": "Homepage section updated successfully"}


@app.delete("/homepage/delete/{s_no}")
def delete_homepage_section(s_no: int, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester:
        raise HTTPException(status_code=401, detail="Unauthorized")

    result = homepage_collection.delete_one({"s_no": s_no})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Homepage section not found")

    return {"message": "Homepage section deleted successfully"}



@app.get("/public/homepage")
def public_homepage():
    sections = list(homepage_collection.find().sort("s_no", 1))
    formatted = []
    for sec in sections:
        # fetch category
        cat = category_collection.find_one({"_id": sec["category_id"]}, {"name": 1})

        # fetch products belonging to this section
        prods = list(product_collection.find(
            {"_id": {"$in": sec["products"]}},
            {"name": 1, "display_image": 1, "hover_image": 1,
             "selling_price": 1, "mrp": 1, "availability": 1}
        ))

        formatted.append({
            "s_no": sec["s_no"],
            "category_id": str(sec["category_id"]),
            "category_name": cat["name"] if cat else "N/A",
            "products": [
                {
                    "_id": str(p["_id"]),
                    "name": p["name"],
                    "display_image": p.get("display_image"),
                    "hover_image": p.get("hover_image"),
                    "price": p.get("selling_price"),
                    "oldPrice": p.get("mrp"),
                    "availability": p.get("availability"),
                }
                for p in prods
            ]
        })

    return {"sections": formatted}


@app.get("/public/categories")
def public_categories():
    categories = list(category_collection.find({}, {"_id": 1, "name": 1, "image_url": 1}))

    formatted_categories = [
        {
            "id": str(cat["_id"]),
            "name": cat["name"],
            "image": cat.get("image_url", "/placeholder.png"),  # 🔹 return only path
            "link": f"/category/{str(cat['_id'])}",
            "products": product_collection.count_documents({"category_id": cat["_id"]})
        }
        for cat in categories
    ]

    return {
        "categories": formatted_categories,
        "total_categories": len(formatted_categories)
    }



@app.get("/public/themes")
def public_themes():
    themes = list(theme_collection.find({}, {"_id": 1, "name": 1, "image_url": 1}))

    formatted_themes = []
    for theme in themes:
        product_count = product_collection.count_documents({"theme_id": theme["_id"]})
        formatted_themes.append({
            "id": str(theme["_id"]),
            "name": theme["name"],
            "image": theme.get("image_url", "/placeholder.png"),  # only path
            "link": f"/theme/{str(theme['_id'])}",                # 🔗 frontend URL
            "products": product_count                             # total products in this theme
        })

    return {
        "themes": formatted_themes,
        "total_themes": len(formatted_themes)
    }


@app.get("/public/category/{category_id}")
def public_category_products(category_id: str):
    try:
        cat_obj = ObjectId(category_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid category_id")

    category = category_collection.find_one({"_id": cat_obj})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    # fetch all products for this category
    prods = list(product_collection.find({"category_id": cat_obj}, {
        "name": 1, "display_image": 1, "hover_image": 1,
        "selling_price": 1, "mrp": 1, "availability": 1
    }))

    return {
        "category": {
            "id": str(category["_id"]),
            "name": category["name"]
        },
        "products": [
            {
                "_id": str(p["_id"]),
                "name": p["name"],
                "display_image": p.get("display_image"),
                "hover_image": p.get("hover_image"),
                "price": p.get("selling_price"),
                "oldPrice": p.get("mrp"),
                "availability": p.get("availability"),
            }
            for p in prods
        ]
    }


@app.get("/public/theme/{theme_id}")
def public_theme_products(theme_id: str):
    try:
        theme_obj = ObjectId(theme_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid theme_id")

    theme = theme_collection.find_one({"_id": theme_obj})
    if not theme:
        raise HTTPException(status_code=404, detail="Theme not found")

    # fetch all products for this theme
    prods = list(product_collection.find({"theme_id": theme_obj}, {
        "name": 1, "display_image": 1, "hover_image": 1,
        "selling_price": 1, "mrp": 1, "availability": 1
    }))

    return {
        "theme": {
            "id": str(theme["_id"]),
            "name": theme["name"]
        },
        "products": [
            {
                "_id": str(p["_id"]),
                "name": p["name"],
                "display_image": p.get("display_image"),
                "hover_image": p.get("hover_image"),
                "price": p.get("selling_price"),
                "oldPrice": p.get("mrp"),
                "availability": p.get("availability"),
            }
            for p in prods
        ]
    }



@app.get("/public/product/{product_id}")
def public_product(product_id: str):
    try:
        prod_obj = ObjectId(product_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid product_id")

    product = product_collection.find_one({"_id": prod_obj})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    category = category_collection.find_one({"_id": product["category_id"]}, {"name": 1})
    theme = theme_collection.find_one({"_id": product["theme_id"]}, {"name": 1})

    return {
        "_id": str(product["_id"]),
        "name": product["name"],
        "description": product.get("description", ""),
        "category_name": category["name"] if category else "N/A",
        "theme_name": theme["name"] if theme else "N/A",
        "price": product.get("selling_price"),
        "oldPrice": product.get("mrp"),
        "availability": product.get("availability"),
        "display_image": product.get("display_image"),
        "hover_image": product.get("hover_image"),
        "additional_images": product.get("additional_images", []),
    }


@app.get("/public/search")
def public_search_products(q: str = Query(..., min_length=1)):
    # Case-insensitive regex match on product name or description
    results = list(product_collection.find(
        {
            "$or": [
                {"name": {"$regex": q, "$options": "i"}},
                {"description": {"$regex": q, "$options": "i"}}
            ]
        },
        {
            "_id": 1,
            "name": 1,
            "display_image": 1,
            "selling_price": 1,
            "mrp": 1,
            "availability": 1
        }
    ).limit(10))  # limit results for performance

    formatted = [
        {
            "_id": str(p["_id"]),
            "name": p["name"],
            "image": p.get("display_image"),
            "price": p.get("selling_price"),
            "oldPrice": p.get("mrp"),
            "availability": p.get("availability"),
        }
        for p in results
    ]
    return {"products": formatted, "total": len(formatted)}


from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from fastapi import HTTPException

class GoogleUser(BaseModel):
    name: str
    email: EmailStr
    mobile: Optional[str] = None
    picture: Optional[str] = None   # ✅ Google profile picture

@app.post("/public/register-google-user")
def register_google_user(user: GoogleUser):
    existing = user_collection.find_one({"email": user.email})
    if existing:
        return {
            "status": "EXISTS",
            "message": "User already exists",
            "user": {
                "id": str(existing["_id"]),
                "name": existing.get("name"),
                "email": existing.get("email"),
                "mobile": existing.get("mobile", ""),
                "picture": existing.get("picture", "")  # ✅ return saved pic
            }
        }

    if not user.mobile:
        return {
            "status": "NEW_USER",
            "message": "Mobile number required for signup",
            "email": user.email,
            "name": user.name,
            "picture": user.picture   # ✅ forward pic
        }

    new_user = {
        "name": user.name,
        "email": user.email,
        "mobile": user.mobile,
        "picture": user.picture,  # ✅ save Google pic
        "created_at": datetime.utcnow()
    }
    result = user_collection.insert_one(new_user)

    return {
        "status": "CREATED",
        "message": "User registered successfully",
        "user": {
            "id": str(result.inserted_id),
            "name": user.name,
            "email": user.email,
            "mobile": user.mobile,
            "picture": user.picture
        }
    }


from fastapi import Body
@app.post("/public/add-to-cart")
def add_to_cart(
    email: str = Body(...),
    product_id: str = Body(...),
    quantity: int = Body(1)   # ✅ new
):
    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if "cart" not in user:
        user["cart"] = []

    # check if product already in cart
    for item in user["cart"]:
        if isinstance(item, dict) and item.get("product_id") == product_id:
            return {"message": "Already in cart", "cart": user["cart"]}

    # add product with quantity
    new_item = {"product_id": product_id, "quantity": quantity}
    user_collection.update_one(
        {"_id": user["_id"]},
        {"$push": {"cart": new_item}}
    )

    return {"message": "Added to cart", "cart": user["cart"] + [new_item]}


@app.get("/public/get-cart")
def get_cart(email: str):
    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    cart = user.get("cart", [])
    detailed_cart = []
    subtotal = 0

    for item in cart:
        product = product_collection.find_one({"_id": ObjectId(item["product_id"])})
        if product:
            subtotal += product.get("selling_price", 0) * item.get("quantity", 1)
            detailed_cart.append({
                "product_id": str(product["_id"]),
                "name": product["name"],
                "price": product.get("selling_price"),
                "oldPrice": product.get("mrp"),
                "image": product.get("display_image"),
                "quantity": item.get("quantity", 1),
            })

    return {"cart": detailed_cart, "subtotal": subtotal}

# ✅ Remove one item from cart
@app.delete("/public/remove-from-cart/{email}/{product_id}")
def remove_from_cart(email: str, product_id: str):
    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_collection.update_one(
        {"_id": user["_id"]},
        {"$pull": {"cart": {"product_id": product_id}}}
    )
    return {"message": "Removed from cart"}

# ✅ Clear all cart items
@app.delete("/public/clear-cart/{email}")
def clear_cart(email: str):
    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"cart": []}}
    )
    return {"message": "Cart cleared"}


from pydantic import BaseModel, EmailStr
from typing import Optional

class UserMessage(BaseModel):
    email: EmailStr     # identify user by email
    text: str
    product_id: Optional[str] = None


@app.post("/public/send-message")
def send_message(data: UserMessage):
    user = user_collection.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_id = str(user["_id"])

    message_entry = {
    "sender": "user",
    "text": data.text,
    "status": "unseen",
    "timestamp": datetime.utcnow().isoformat()  # ✅ add timestamp
}


    # ✅ only add product_id if present
    if data.product_id:
        message_entry["product_id"] = data.product_id

    chat = chat_collection.find_one({"user_id": user_id})

    if chat:
        chat_collection.update_one(
            {"_id": chat["_id"]},
            {"$push": {"messages": message_entry}}
        )
    else:
        chat_doc = {
            "user_id": user_id,
            "messages": [message_entry]
        }
        chat_collection.insert_one(chat_doc)

    return {"message": "Message saved successfully", "data": message_entry}


@app.get("/public/get-messages")
def get_messages(email: str):
    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    chat = chat_collection.find_one({"user_id": str(user["_id"])})
    if not chat:
        return {"messages": [], "unseen_admin_count": 0}

    messages = chat.get("messages", [])

    # count unseen admin msgs before marking them seen
    unseen_admin_count = sum(1 for m in messages if m["sender"] == "admin" and m["status"] == "unseen")

    # now mark them seen
    updated = False
    for m in messages:
        if m["sender"] == "admin" and m["status"] == "unseen":
            m["status"] = "seen"
            updated = True

    if updated:
        chat_collection.update_one(
            {"_id": chat["_id"]},
            {"$set": {"messages": messages}}
        )

    return {"messages": messages, "unseen_admin_count": unseen_admin_count}


@app.get("/admin/chats")
def get_all_chats(token: dict = Depends(verify_token)):
    # ensure caller is admin
    requester = token.get("sub")
    if not requester or not admin_collection.find_one({"username": requester}):
        raise HTTPException(status_code=403, detail="Not an admin")

    chats = []
    for chat in chat_collection.find():
        user = user_collection.find_one({"_id": ObjectId(chat["user_id"])})
        email = user["email"] if user else "Unknown"

        unseen_count = sum(
            1 for m in chat.get("messages", [])
            if m["sender"] == "user" and m["status"] == "unseen"
        )
        last_msg = chat["messages"][-1] if chat.get("messages") else None

        chats.append({
            "chat_id": str(chat["_id"]),
            "user_id": chat["user_id"],
            "email": email,
            "last_message": last_msg,
            "unseen_count": unseen_count
        })

    return {"chats": chats}

@app.get("/admin/chats/{email}")
def get_chat_by_email(email: str, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester or not admin_collection.find_one({"username": requester}):
        raise HTTPException(status_code=403, detail="Not an admin")

    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    chat = chat_collection.find_one({"user_id": str(user["_id"])})
    if not chat:
        return {"messages": [], "scroll_to": None}

    messages = chat.get("messages", [])

    # attach product info if product_id exists
    for m in messages:
        if "product_id" in m:
            m["product_id"] = str(m["product_id"])


    # find first unseen index
    first_unseen_index = next(
        (i for i, m in enumerate(messages) if m["sender"] == "user" and m["status"] == "unseen"),
        None
    )

    # mark unseen → seen
    for m in messages:
        if m["sender"] == "user" and m["status"] == "unseen":
            m["status"] = "seen"

    chat_collection.update_one(
        {"_id": chat["_id"]},
        {"$set": {"messages": messages}}
    )

    return {
        "messages": messages,
        "scroll_to": first_unseen_index
    }


class AdminReply(BaseModel):
    email: EmailStr
    text: str

@app.post("/admin/send-reply")
def send_reply(data: AdminReply, token: dict = Depends(verify_token)):
    requester = token.get("sub")
    if not requester or not admin_collection.find_one({"username": requester}):
        raise HTTPException(status_code=403, detail="Not an admin")

    user = user_collection.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    chat = chat_collection.find_one({"user_id": str(user["_id"])})

    message_entry = {
    "sender": "admin",
    "text": data.text,
    "status": "unseen",
    "timestamp": datetime.utcnow().isoformat()  # ✅ add timestamp
}


    if chat:
        chat_collection.update_one(
            {"_id": chat["_id"]},
            {"$push": {"messages": message_entry}}
        )
    else:
        chat_collection.insert_one({
            "user_id": str(user["_id"]),
            "messages": [message_entry]
        })

    return {"message": "Reply sent", "data": message_entry}



from pydantic import BaseModel, EmailStr

class ClearChatRequest(BaseModel):
    email: EmailStr

@app.delete("/admin/clear-chat/{email}")
def clear_chat(email: str, token: dict = Depends(verify_token)):
    # ensure caller is admin
    requester = token.get("sub")
    if not requester or not admin_collection.find_one({"username": requester}):
        raise HTTPException(status_code=403, detail="Not an admin")

    user = user_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    chat = chat_collection.find_one({"user_id": str(user["_id"])})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    # delete the entire chat document
    chat_collection.delete_one({"_id": chat["_id"]})

    return {"message": "Chat deleted successfully"}

