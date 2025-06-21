from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from .forms import *
from .models import User

from django.contrib import messages

import json
import string
import random

# ✅ 아이디 찾기
@csrf_exempt
def find_id_view(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get("email")

        # 이메일로 등록된 모든 사용자 검색
        users = User.objects.filter(email=email)

        if users.exists():
            # 해당 이메일로 등록된 모든 username 목록 전송
            usernames = [user.username for user in users]
            username_list = "\n".join(usernames)

            send_mail(
                subject="아이디 찾기 결과입니다",
                message=f"해당 이메일로 등록된 아이디 목록입니다:\n\n{username_list}",
                from_email="직돌이 운영팀 <seongjin5743@naver.com>",
                recipient_list=[email],
            )
            return JsonResponse({"success": True, "message": "아이디 목록이 이메일로 전송되었습니다."})
        else:
            return JsonResponse({"success": False, "message": "해당 이메일로 등록된 계정을 찾을 수 없습니다."})


# ✅ 인증번호 저장용 변수
VERIFICATION_CODES = {}   # username: code
VERIFIED_USERS = set()    # 인증 완료된 username 저장

# ✅ 인증번호 생성 함수
def generate_code(length=6):
    return ''.join(random.choices(string.digits, k=length))


# ✅ 비밀번호 재설정: 인증번호 요청
@csrf_exempt
def reset_password_view(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get("email")
        username = data.get("username")

        try:
            # username + email 조합으로 사용자 조회
            user = User.objects.get(username=username, email=email)
            
            # 인증번호 생성 및 저장
            code = generate_code(6)
            VERIFICATION_CODES[username] = code

            # 이메일 발송
            send_mail(
                subject="비밀번호 재설정 인증번호",
                message=f"비밀번호 재설정을 위한 인증번호는 {code} 입니다.",
                from_email="직돌이 운영팀 <seongjin5743@naver.com>",
                recipient_list=[email],
            )

            return JsonResponse({"success": True, "message": "인증번호가 이메일로 전송되었습니다."})
        except User.DoesNotExist:
            return JsonResponse({"success": False, "message": "아이디 또는 이메일이 올바르지 않습니다."})


# ✅ 인증번호 확인
@csrf_exempt
def confirm_verification_code(request):
    if request.method == "POST":
        data = json.loads(request.body)
        username = data.get("username")
        code = data.get("code")

        saved_code = VERIFICATION_CODES.get(username)

        if saved_code == code:
            VERIFIED_USERS.add(username)
            return JsonResponse({"success": True, "message": "인증에 성공했습니다."})
        else:
            return JsonResponse({"success": False, "message": "인증번호가 일치하지 않습니다."})


# ✅ 새 비밀번호 설정
@csrf_exempt
def set_new_password(request):
    if request.method == "POST":
        data = json.loads(request.body)
        username = data.get("username")
        new_password = data.get("new_password")

        # 인증된 사용자만 비밀번호 재설정 가능
        if username not in VERIFIED_USERS:
            return JsonResponse({"success": False, "message": "인증되지 않은 사용자입니다."})

        try:
            user = User.objects.get(username=username)
            user.set_password(new_password)
            user.save()

            # 인증 데이터 정리
            VERIFIED_USERS.discard(username)
            VERIFICATION_CODES.pop(username, None)

            return JsonResponse({"success": True, "message": "비밀번호가 성공적으로 변경되었습니다."})
        except User.DoesNotExist:
            return JsonResponse({"success": False, "message": "사용자를 찾을 수 없습니다."})


# ✅ 로그아웃 처리
@login_required
def logout(request):
    auth_logout(request)  # 세션에서 로그아웃
    return redirect('/')  # 홈으로 리디렉션


# ✅ 홈 접근 시 달력으로 리디렉션
def home(request):
    return redirect('/')


# ✅ 회원가입 / 로그인 처리
def auth_view(request):
    mode = request.GET.get('mode', 'login')

    # POST 요청 처리
    if request.method == 'POST':
        if mode == 'signup':
            signup_form = CustomUserCreationForm(request.POST, request.FILES)
            login_form = CustomAuthenticationForm(request)  # 비워진 로그인 폼

            if signup_form.is_valid():
                user = signup_form.save()
                auth_login(request, user)
                return redirect('cal:calendar')

        else:  # mode == 'login'
            login_form = CustomAuthenticationForm(request, data=request.POST)
            signup_form = CustomUserCreationForm()  # 비워진 회원가입 폼

            if login_form.is_valid():
                user = login_form.get_user()
                auth_login(request, user)
                return redirect('cal:calendar')

    else:
        # GET 요청일 경우
        signup_form = CustomUserCreationForm()
        login_form = CustomAuthenticationForm(request)

    # context에 올바른 폼 전달
    context = {
        'mode': mode,
        'signup_form': signup_form,
        'login_form': login_form,
    }
    return render(request, 'auth.html', context)


# ✅ 사용자명/닉네임 중복 확인
@csrf_exempt
def check_duplicate(request):
    if request.method == "POST":
        data = json.loads(request.body)
        field = data.get("field")  # username 또는 nickname
        value = data.get("value")

        if field not in ["username", "nickname"]:
            return JsonResponse({"success": False, "message": "유효하지 않은 필드입니다."})

        # 중복 여부 확인
        exists = User.objects.filter(**{field: value}).exists()

        if exists:
            return JsonResponse({"success": False, "message": f"{field}이(가) 이미 사용 중입니다."})
        else:
            return JsonResponse({"success": True, "message": f"{field}은(는) 사용 가능합니다."})

@login_required
def mypage(request):
    user = request.user
    password_form = PasswordChangeCustomForm(user)
    nickname_form = NicknameChangeForm(instance=user)
    team_form = TeamChangeForm(instance=user)

    if request.method == 'POST':
        mode = request.POST.get('mode')
        print(mode)
        if mode == 'password':
            password_form = PasswordChangeCustomForm(user, request.POST)
            if password_form.is_valid():
                password_form.save()
                messages.success(request, '비밀번호가 변경되었습니다.')
                return redirect('accounts:mypage')
        elif mode == 'nickname':
            nickname_form = NicknameChangeForm(request.POST, instance=user)
            if nickname_form.is_valid():
                nickname_form.save()
                messages.success(request, '닉네임이 변경되었습니다.')
                return redirect('accounts:mypage')
        elif mode == 'team':
            team_form = TeamChangeForm(request.POST, instance=user)
            if team_form.is_valid():
                team_form.save()
                messages.success(request, '응원팀이 변경되었습니다.')
                return redirect('accounts:mypage')

    context = {
        'password_form': password_form,
        'nickname_form': nickname_form,
        'team_form': team_form,
    }
    return render(request, 'mypage.html', context)

@login_required
def update_profile_image(request):
    # 디버깅을 위해 request.FILES 출력
    print("request.FILES:", request.FILES)

    if request.method == 'POST' and request.FILES.get('profile_image'):
        profile_image = request.FILES['profile_image']
        user = request.user
        
        # 디버깅: 프로필 이미지 파일 확인
        print("프로필 이미지 파일:", profile_image)

        user.profile_image = profile_image
        user.save()

        messages.success(request, '프로필 이미지가 업데이트되었습니다.')
        return redirect('accounts:mypage')
    
    # 요청에 파일이 없을 때 디버깅
    print("파일이 업로드되지 않았습니다.")
    messages.error(request, '이미지 업로드에 실패했습니다.')
    return redirect('accounts:mypage')