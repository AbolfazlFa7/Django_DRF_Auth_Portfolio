<div dir="rtl">

## مقدمه
این پروژه یک API احراز هویت مبتنی بر **Django REST Framework** است که برای نمونه‌سازی (portfolio) طراحی شده است. هدف اصلی این پروژه، ارائه یک سیستم احراز هویت امن با قابلیت‌هایی مانند ثبت‌نام، ورود، خروج، و تأیید هویت دو مرحله‌ای (OTP) از طریق ایمیل یا شماره تلفن است. این پروژه با استفاده از **JWT** (JSON Web Token) و امکانات پیشرفته مانند **throttling**، **pagination** و مستندسازی با **drf-spectacular** پیاده‌سازی شده است.

<img src="README files/img/schema_ui.png" width="100%" height="100%">
<img src="README files/img/schema_redoc.png" width="100%" height="100%">

---

## ویژگی‌ها
- **احراز هویت با JWT**: پشتیبانی از توکن‌های **access** و **refresh** برای مدیریت نشست‌های کاربر.
- **تأیید هویت دو مرحله‌ای (OTP)**: ارسال کد تأیید به ایمیل یا شماره تلفن با استفاده از سرویس‌های **SMTP** و **Kavenegar**.
- **مدیریت کاربران**: امکان ثبت‌نام، مشاهده، ویرایش و حذف کاربران با سطح دسترسی‌های مشخص (ادمین یا صاحب حساب).
- **مستندسازی API**: مستندات کامل با **Swagger** و **Redoc** برای توسعه‌دهندگان.
- **تست‌های خودکار**: تست‌های جامع برای اطمینان از عملکرد صحیح **endpoints** با استفاده از **APITestCase**.
- **امنیت**: اعتبارسنجی قوی برای ایمیل، رمز عبور و شماره تلفن، همراه با **throttling** برای جلوگیری از سوءاستفاده.
- **کش (Cache)**: استفاده از **LocMemCache** برای بهینه‌سازی عملکرد تأیید OTP.
- **پشتیبانی از محیط‌متغیرها**: استفاده از **python-dotenv** برای مدیریت تنظیمات حساس.

---

## تکنولوژی‌های استفاده‌شده
- **زبان برنامه‌نویسی**: Python 3
- **فریم‌ورک وب**: Django 4.2.11
- **فریم‌ورک API**: Django REST Framework
- **احراز هویت**: rest_framework_simplejwt
- **مستندسازی**: drf-spectacular
- **ذخیره‌سازی**: SQLite (برای توسعه)
- **کش**: locmem (برای توسعه)   
- **سرویس‌های خارجی**:
  - **Kavenegar**: برای ارسال پیامک
  - **SMTP Gmail**: برای ارسال ایمیل
- **تست**: Django Test Framework
- **مدیریت محیط‌متغیرها**: python-dotenv

---
### ساختار پروژه
- `core/`: تنظیمات اصلی پروژه (settings.py، urls.py، ...)
- `api/`: اپلیکیشن اصلی شامل مدل‌ها، ویوها، سریالایزرها و تست‌ها
- `utils/`: ابزارهای کمکی مثل اعتبارسنجی و سرویس‌های ایمیل/پیامک
--- 

# نحوه نصب و راه‌اندازی

<div dir="ltr">
  
```
mkdir portfolio
```
```
cd portfolio
```

```
git clone url
```
```
pip install -r requirements.txt
```
```
python manage.py makemigrations
python manage.py migrate
```
```
python manage.py runserver
```
</div>

---

با رفتن به این آدرس به مستندات API میتوانید دسترسی پیدا کنید
<div dir="ltr">
- http://127.0.0.1:8000/api/schema/ui/ <br>
- http://127.0.0.1:8000/api/schema/redoc/
</div>

---
</div>

# Author
## Abolfazl Fallahkar
### telegram ID: @AbolfazlFa7
