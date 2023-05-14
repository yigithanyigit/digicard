from django.urls import path,re_path
from . import views

urlpatterns = [
	path('register/', views.UserRegister.as_view()),
	path('login/', views.UserLogin.as_view()),
	path('logout/', views.UserLogout.as_view()),
	path('user/', views.UserView.as_view()),
	path('user/change_pass', views.ChangePassword.as_view()),
	path('user/c/<int:userid>/profile', views.GetUserProfile.as_view()),
	path('user/c/<int:userid>/', views.GetUser.as_view()),
	path('user/c/<int:userid>/social', views.GetUserSocial.as_view()),
	path('user/add/social', views.AddSocial.as_view()),
	path('user/<int:userid>/photo', views.GetPhoto.as_view()),
	path('user/<int:userid>/edit/details', views.EditDetails.as_view()),




	# Normal Gets

	path('getchoices', views.GetChoices.as_view()),

]
