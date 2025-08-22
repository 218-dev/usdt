from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
import os
import re
from datetime import datetime
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'تغيير_هذا_المفتاح_في_بيئة_الإنتاج')

# الملفات الأساسية
USERS_JSON = "users.json"
REQUESTS_JSON = "requests.json"
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'Trading')

# دالة لتحميل البيانات من JSON
def load_json(file):
    if not os.path.exists(file):
        with open(file, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=4)
    with open(file, 'r', encoding='utf-8') as f:
        return json.load(f)

# دالة لحفظ البيانات إلى JSON
def save_json(file, data):
    with open(file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

# دالة للتحقق من رقم الهاتف الليبي
def validate_libyan_phone(phone):
    # إزالة أي أحرف غير رقمية
    cleaned_phone = re.sub(r'\D', '', phone)
    
    # التحقق من الطول المناسب (9 أرقام)
    return len(cleaned_phone) == 9

# دالة للحصول على رقم الهاتف من المستخدم
def get_user_phone(user_id):
    users = load_json(USERS_JSON)
    for user in users:
        if user["id"] == user_id:
            return user["phone"]
    return None

# الصفحة الرئيسية
@app.route('/')
def index():
    error = request.args.get('error')
    message = request.args.get('message')
    
    # تحميل البيانات
    users = load_json(USERS_JSON)
    requests = load_json(REQUESTS_JSON)
    
    # فرز الطلبات بالأحدث أولاً
    requests.sort(key=lambda x: datetime.strptime(x["created_at"], "%Y-%m-%d %H:%M:%S"), reverse=True)
    
    # إضافة رقم الهاتف لكل طلب
    for req in requests:
        user_phone = get_user_phone(req['user_id'])
        req['user_phone'] = user_phone
    
    # تحديد الطلبات الخاصة بالمستخدم إذا كان مسجلاً
    user_requests = []
    if 'user_id' in session:
        user_requests = [req for req in requests if req['user_id'] == session['user_id']]
        # إضافة رقم الهاتف لطلبات المستخدم
        for req in user_requests:
            user_phone = get_user_phone(req['user_id'])
            req['user_phone'] = user_phone
    
    return render_template('index.html', 
                         page_title="منصة تبادل تدوال",
                         requests=requests,
                         user_requests=user_requests,
                         error=error,
                         message=message)

# تسجيل مستخدم جديد
@app.route('/register', methods=['POST'])
def register():
    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # التحقق من صحة رقم الهاتف
    if not validate_libyan_phone(phone):
        return redirect(url_for('index', error="رقم الهاتف غير صحيح. يجب أن يكون 9 أرقام (بدون 218)"))
    
    # التحقق من تطابق كلمات المرور
    if password != confirm_password:
        return redirect(url_for('index', error="كلمات المرور غير متطابقة"))
    
    users = load_json(USERS_JSON)
    
    # تنظيف رقم الهاتف (إزالة أي أحرف غير رقمية)
    cleaned_phone = re.sub(r'\D', '', phone)
    
    # التحقق من عدم وجود رقم الهاتف مسبقاً
    for user in users:
        user_phone = re.sub(r'\D', '', user["phone"])
        if user_phone == cleaned_phone:
            return redirect(url_for('index', error="رقم الهاتف مسجل مسبقاً"))
    
    # إنشاء مستخدم جديد
    new_user = {
        "id": str(datetime.now().timestamp()),
        "name": name,
        "phone": cleaned_phone,  # تخزينه كـ 9 أرقام فقط
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    users.append(new_user)
    save_json(USERS_JSON, users)
    
    # حفظ بيانات الجلسة
    session['user_id'] = new_user['id']
    session['user_name'] = new_user['name']
    session['user_phone'] = new_user['phone']
    
    return redirect(url_for('index'))

# تسجيل الدخول
@app.route('/login', methods=['POST'])
def login():
    phone = request.form.get('phone', '').strip()
    password = request.form.get('password', '')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # تنظيف رقم الهاتف المدخل
    cleaned_phone = re.sub(r'\D', '', phone)
    
    users = load_json(USERS_JSON)
    
    for user in users:
        user_phone = re.sub(r'\D', '', user["phone"])
        if user_phone == cleaned_phone and user["password"] == hashed_password:
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_phone'] = user['phone']
            return redirect(url_for('index'))
    
    return redirect(url_for('index', error="رقم الهاتف أو كلمة المرور غير صحيحة"))

# تسجيل الخروج
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# إضافة طلب جديد
@app.route('/add_request', methods=['POST'])
def add_request():
    if 'user_id' not in session:
        return redirect(url_for('index', message="login_required"))
    
    type_req = request.form.get('type', '')
    provider = request.form.get('provider', '')
    amount = request.form.get('amount', '')
    price = request.form.get('price', '')
    location = request.form.get('location', '')
    description = request.form.get('description', '')
    
    requests = load_json(REQUESTS_JSON)
    
    new_request = {
        "id": str(datetime.now().timestamp()),
        "user_id": session['user_id'],
        "user_name": session['user_name'],
        "type": type_req,
        "provider": provider,
        "amount": amount,
        "price": price,
        "location": location,
        "description": description,
        "status": "متوفر",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    requests.append(new_request)
    save_json(REQUESTS_JSON, requests)
    
    return redirect(url_for('index'))

# حذف طلب
@app.route('/delete_request', methods=['POST'])
def delete_request():
    if 'user_id' not in session:
        return redirect(url_for('index', message="login_required"))
    
    request_id = request.form.get('request_id', '')
    
    requests = load_json(REQUESTS_JSON)
    
    # البحث عن الطلب وحذفه إذا كان يخص المستخدم
    updated_requests = [req for req in requests if not (req['id'] == request_id and req['user_id'] == session['user_id'])]
    
    save_json(REQUESTS_JSON, updated_requests)
    
    return redirect(url_for('index'))

# تغيير حالة الطلب - الإصلاح الكامل
@app.route('/toggle_status', methods=['POST'])
def toggle_status():
    if 'user_id' not in session:
        return redirect(url_for('index', message="login_required"))
    
    request_id = request.form.get('request_id', '')
    
    requests = load_json(REQUESTS_JSON)
    updated = False
    
    for req in requests:
        if req['id'] == request_id and req['user_id'] == session['user_id']:
            req['status'] = "مكتمل" if req['status'] == "متوفر" else "متوفر"
            updated = True
            break
    
    if updated:
        save_json(REQUESTS_JSON, requests)
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)