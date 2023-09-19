from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.views.generic import View
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# from django.utils.encoding import force_bytes
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from .utils import TokenGenerator, generate_token
from django.core.mail import EmailMessage
from django.conf import settings

# Create your views here.

def signup(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        if password != confirm_password:
            messages.warning(request, "Password is not matching")
            return redirect('/check/signup')
        
        try:
            if User.objects.get(username=email):
                messages.info(request, "Username is Taken")
                return redirect('/check/signup')
            
        except Exception as identifier:
            pass

        user = User.objects.create_user(email, email, password)
        user.save()
        user.is_active=False
        email_subject="Activate your account"
        message=render_to_string('authentication/activate.html', {
            'user': user,
            'domain': '127.0.0.1:8000',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })

        email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
        email_message.send()
        messages.success(request, "Activate your account by clicking the link in your email")
        return redirect('/check/login')

    return render(request, 'authentication/signup.html')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid=force_text(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as Identifier:
            user=None
        if User is not None and generate_token.check_token(user, token):
            user.is_active=True
            user.save()
            messages.info(request, "Account activated successfully")
            return redirect('/check/login')
        return render(request, '/authentication/activatefail.html')

def handlelogin(request):
    return render(request, 'authentication/login.html')

def handlelogout(request):
    return redirect('/check/login')
