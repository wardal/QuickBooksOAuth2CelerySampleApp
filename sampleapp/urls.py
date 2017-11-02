from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^(?i)connect-to-quickbooks/?$', views.connect_to_quickbooks, name='connect_to_quickbooks'),
    url(r'^(?i)sign-in-with-intuit/?$', views.sign_in_with_intuit, name='sign_in_with_intuit'),
    url(r'^(?i)get-app-now/?$', views.get_app_now, name='get_app_now'),
    url(r'^(?i)auth-code-handler/?$', views.auth_code_handler, name='auth_code_handler'),
    url(r'^(?i)disconnect/?$', views.disconnect, name='disconnect'),
    url(r'^(?i)accounting-call/?$', views.accounting_call, name='accounting_call'),
    url(r'^(?i)user-call/?$', views.user_call, name='user_call'),
    url(r'^(?i)connected/?$', views.connected, name='connected'),
    url(r'^(?i)refresh-token-call/?$', views.refresh_token_call, name='refresh_token_call')
]
