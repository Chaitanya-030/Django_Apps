from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.contrib.auth.models import User

# Create your views here.

def signup(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        if password != confirm_password:
            return HttpResponse("password incorrect")
            # return render(request, 'authentication/signup.html')
        
        try:
            if User.objects.get(username=email):
                messages.warning(request, "Password is not matching")
                return redirect(request, 'authentication/signup.html')
        except Exception as idetifier:
            pass

        user = User.objects.create_user(email, email, password)
        user.save()
        return HttpResponse("user created")

    return render(request, 'authentication/signup.html')

def handlelogin(request):
    return render(request, 'authentication/login.html')

def handlelogout(request):
    return redirect('/check/login')
