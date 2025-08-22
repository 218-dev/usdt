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

# دالة لتشفير البيانات
def encrypt_data(data, key):
    key = hashlib.sha256(key.encode()).digest()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

# دالة لفك تشفير البيانات
def decrypt_data(enc_data, key):
    key = hashlib.sha256(key.encode()).digest()
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:AES.block_size]
    ct = enc_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# دالة للتحقق من رقم الهاتف الليبي
def validate_libyan_phone(phone):
    # إزالة أي أحرف غير رقمية
    cleaned_phone = re.sub(r'\D', '', phone)
    
    # إذا بدأ بـ 218، تأكد أن الطول 12 رقمًا
    if cleaned_phone.startswith('218'):
        return len(cleaned_phone) == 12
    # إذا بدأ بـ 0، تأكد أن الطول 10 أرقام ثم أضف 218
    elif cleaned_phone.startswith('0'):
        return len(cleaned_phone) == 10
    # إذا كان 9 أرقام فقط، أضف 0 في البداية
    elif len(cleaned_phone) == 9:
        return True
    else:
        return False

# دالة لتنسيق رقم الهاتف للواتساب
def format_phone_for_whatsapp(phone):
    # إزالة أي أحرف غير رقمية
    cleaned_phone = re.sub(r'\D', '', phone)
    
    # إذا كان الرقم 9 أرقام، أضف 218 في البداية
    if len(cleaned_phone) == 9:
        return f"218{cleaned_phone}"
    # إذا بدأ بـ 0 وكان 10 أرقام، استبدل 0 بـ 218
    elif cleaned_phone.startswith('0') and len(cleaned_phone) == 10:
        return f"218{cleaned_phone[1:]}"
    # إذا كان يحتوي على 218 بالفعل، اتركه كما هو
    elif cleaned_phone.startswith('218') and len(cleaned_phone) == 12:
        return cleaned_phone
    else:
        return cleaned_phone

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
    
    # تحديد الطلبات الخاصة بالمستخدم إذا كان مسجلاً
    user_requests = []
    if 'user_id' in session:
        user_requests = [req for req in requests if req['user_id'] == session['user_id']]
    
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
    
    # تنسيق رقم الهاتف للتخزين (9 أرقام)
    cleaned_phone = re.sub(r'\D', '', phone)
    if len(cleaned_phone) == 9:
        formatted_phone = cleaned_phone
    elif len(cleaned_phone) == 10 and cleaned_phone.startswith('0'):
        formatted_phone = cleaned_phone[1:]
    else:
        formatted_phone = cleaned_phone[-9:]  # أخذ آخر 9 أرقام
    
    # التحقق من عدم وجود رقم الهاتف مسبقاً
    for user in users:
        user_phone = re.sub(r'\D', '', user["phone"])
        if user_phone.endswith(formatted_phone):
            return redirect(url_for('index', error="رقم الهاتف مسجل مسبقاً"))
    
    # إنشاء مستخدم جديد
    new_user = {
        "id": str(datetime.now().timestamp()),
        "name": name,
        "phone": formatted_phone,  # تخزينه كـ 9 أرقام فقط
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
    if len(cleaned_phone) == 10 and cleaned_phone.startswith('0'):
        cleaned_phone = cleaned_phone[1:]
    elif len(cleaned_phone) > 9:
        cleaned_phone = cleaned_phone[-9:]
    
    users = load_json(USERS_JSON)
    
    for user in users:
        user_phone = re.sub(r'\D', '', user["phone"])
        if user_phone.endswith(cleaned_phone) and user["password"] == hashed_password:
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
        "user_phone": session['user_phone'],
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
    requests = [req for req in requests if not (req['id'] == request_id and req['user_id'] == session['user_id'])]
    
    save_json(REQUESTS_JSON, requests)
    
    return redirect(url_for('index'))

# تغيير حالة الطلب
@app.route('/toggle_status', methods=['POST'])
def toggle_status():
    if 'user_id' not in session:
        return redirect(url_for('index', message="login_required"))
    
    request_id = request.form.get('request_id', '')
    
    requests = load_json(REQUESTS_JSON)
    
    for req in requests:
        if req['id'] == request_id and req['user_id'] == session['user_id']:
            req['status'] = "مكتمل" if req['status'] == "متوفر" else "متوفر"
            break
    
    save_json(REQUESTS_JSON, requests)
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)