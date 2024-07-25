from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password1']
        confirm_password = request.POST['password2']
        
        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'authentication/signup.html')
        
        try:
            if User.objects.get(email=email):
                messages.warning(request, "Email already exists")
                return render(request, 'authentication/signup.html')
        except User.DoesNotExist:
            user = User.objects.create_user(username, email, password)
            user.save()
            messages.success(request, "User created successfully")
            return redirect('handlelogin')  

    return render(request, 'authentication/signup.html')
            
@csrf_protect
def handlelogin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            user = User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)
            if user is not None:
                login(request, user)
                return render(request, "index.html")
            else:
                messages.error(request, 'Invalid email or password')
        except User.DoesNotExist:
            messages.error(request, 'Invalid email or password')
            
    return render(request, 'authentication/login.html')

def handlelogout(request):
    logout(request)
    messages.success(request, "Logged out successfully")
    return redirect('signup')
