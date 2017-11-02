import urllib

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.conf import settings

from .models import QuickBooksToken, QuickBooksDiscoveryDocument
from .services import (
    get_discovery_document,
    get_company_info,
    get_user_profile,
    get_bearer_token,
    get_bearer_token_from_refresh_token,
    get_secret_key,
    validate_jwt_token,
    revoke_token,
)


def index(request):
    return render(request, 'index.html')


def connect_to_quickbooks(request):
    get_discovery_document()
    discovery_document = QuickBooksDiscoveryDocument.objects.first()
    url = discovery_document.authorization_endpoint
    params = {'scope': settings.ACCOUNTING_SCOPE, 'redirect_uri': settings.REDIRECT_URI,
              'response_type': 'code', 'state': get_csrf_token(request), 'client_id': settings.CLIENT_ID}
    url += '?' + urllib.parse.urlencode(params)
    return redirect(url)


def sign_in_with_intuit(request):
    get_discovery_document()
    discovery_document = QuickBooksDiscoveryDocument.objects.first()
    url = discovery_document.authorization_endpoint
    scope = ' '.join(settings.OPENID_SCOPES)  # Scopes are required to be sent delimited by a space
    params = {'scope': scope, 'redirect_uri': settings.REDIRECT_URI,
              'response_type': 'code', 'state': get_csrf_token(request), 'client_id': settings.CLIENT_ID}
    url += '?' + urllib.parse.urlencode(params)
    return redirect(url)


def get_app_now(request):
    get_discovery_document()
    discovery_document = QuickBooksDiscoveryDocument.objects.first()
    url = discovery_document.authorization_endpoint
    scope = ' '.join(settings.GET_APP_SCOPES)  # Scopes are required to be sent delimited by a space
    params = {'scope': scope, 'redirect_uri': settings.REDIRECT_URI,
              'response_type': 'code', 'state': get_csrf_token(request), 'client_id': settings.CLIENT_ID}
    url += '?' + urllib.parse.urlencode(params)
    return redirect(url)


def auth_code_handler(request):
    state = request.GET.get('state', None)
    error = request.GET.get('error', None)
    if error == 'access_denied':
        return redirect('sampleapp:index')
    if state is None:
        return HttpResponseBadRequest()
    elif state != get_csrf_token(request):  # validate against CSRF attacks
        return HttpResponse('unauthorized', status=401)

    auth_code = request.GET.get('code', '')
    if auth_code is '':
        return HttpResponseBadRequest()

    bearer = get_bearer_token(auth_code)
    realm_id = request.GET.get('realmId', None)
    update_session(request, bearer.access_token, bearer.refresh_token, realm_id)
    query = QuickBooksToken.objects.first()
    if query:
        query.delete()
    QuickBooksToken.objects.create(
        quickbooks_realm_id=realm_id,
        quickbooks_access_token=bearer.access_token,
        quickbooks_access_token_expires_in=bearer.access_token_expire,
        quickbooks_refresh_token=bearer.refresh_token,
        quickbooks_refresh_token_expires_in=bearer.refresh_token_expire
    )

    # Validate JWT tokens only for OpenID scope
    if bearer.id_token is not None:
        if not validate_jwt_token(bearer.id_token):
            return HttpResponse('JWT Validation failed. Please try signing in again.')
        else:
            return redirect('sampleapp:connected')
    else:
        return redirect('sampleapp:connected')


def connected(request):
    query = QuickBooksToken.objects.first()
    access_token = query.quickbooks_access_token
    if access_token is '':
        return HttpResponse('Your Bearer token has expired, please initiate Sign In With Intuit flow again')

    refresh_token = query.quickbooks_refresh_token
    realm_id = query.quickbooks_realm_id
    if realm_id is None:
        user_profile_response, status_code = get_user_profile(access_token)

        if status_code >= 400:
            # if call to User Profile Service doesn't succeed then get a new bearer token from refresh token
            # and try again
            bearer = get_bearer_token_from_refresh_token(refresh_token)
            QuickBooksToken.objects.update(
                quickbooks_access_token=bearer.access_token,
                quickbooks_access_token_expires_in=bearer.access_token_expire,
                quickbooks_refresh_token=bearer.refresh_token,
                quickbooks_refresh_token_expires_in=bearer.refresh_token_expire,
            )
            user_profile_response, status_code = get_user_profile(bearer.access_token)

            if status_code >= 400:
                return HttpResponseServerError()

            update_session(request, bearer.access_token, bearer.refresh_token, request.session.get('realmId', None),
                           name=user_profile_response.get('givenName', ''))

        c = {
            'first_name': user_profile_response.get('givenName', ''),
        }
    else:
        if request.session.get('name') is None:
            name = ''
        else:
            name = request.session.get('name')
        c = {
            'first_name': name,
        }

    return render(request, 'connected.html', context=c)


def disconnect(request):
    query = QuickBooksToken.objects.first()
    access_token = query.quickbooks_access_token
    refresh_token = query.quickbooks_refresh_token

    if access_token is not '':
        revoke_response = revoke_token(access_token)
    elif refresh_token is not '':
        revoke_response = revoke_token(refresh_token)
    else:
        return HttpResponse('No access_token or refresh_token found, please connect again!')

    query.quickbooks_access_token = ''
    query.quickbooks_refresh_token = ''
    query.save()
    request.session.flush()

    return HttpResponse(revoke_response)


def refresh_token_call(request):
    query = QuickBooksToken.objects.first()
    refresh_token = query.quickbooks_refresh_token
    if refresh_token is '':
        return HttpResponse('Not authorized')
    bearer = get_bearer_token_from_refresh_token(refresh_token)
    QuickBooksToken.objects.update(
        quickbooks_access_token=bearer.access_token,
        quickbooks_access_token_expires_in=bearer.access_token_expire,
        quickbooks_refresh_token=bearer.refresh_token,
        quickbooks_refresh_token_expires_in=bearer.refresh_token_expire,
    )
    if isinstance(bearer, str):
        return HttpResponse(bearer)
    else:
        return HttpResponse('Access Token: ' + bearer.access_token + ', Refresh Token: ' + bearer.refresh_token)


def accounting_call(request):
    query = QuickBooksToken.objects.first()
    access_token = query.quickbooks_access_token
    if access_token is '':
        return HttpResponse('Your Bearer token has expired, please initiate C2QB flow again')

    realm_id = query.quickbooks_realm_id
    if realm_id is None:
        return HttpResponse('No realm ID. QBO calls only work if the accounting scope was passed!')

    refresh_token = query.quickbooks_refresh_token
    company_info_response, status_code = get_company_info(access_token, realm_id)

    if status_code >= 400:
        # if call to QBO doesn't succeed then get a new bearer token from refresh token and try again
        bearer = get_bearer_token_from_refresh_token(refresh_token)
        QuickBooksToken.objects.update(
            quickbooks_access_token=bearer.access_token,
            quickbooks_access_token_expires_in=bearer.access_token_expire,
            quickbooks_refresh_token=bearer.refresh_token,
            quickbooks_refresh_token_expires_in=bearer.refresh_token_expire,
        )
        company_info_response, status_code = get_company_info(bearer.access_token, realm_id)

        if status_code >= 400:
            return HttpResponseServerError()

        update_session(request, bearer.access_token, bearer.refresh_token, realm_id)

    company_name = company_info_response['CompanyInfo']['CompanyName']
    address = company_info_response['CompanyInfo']['CompanyAddr']

    return HttpResponse('Company Name: ' + company_name + ', Company Address: ' + address['Line1'] + ', ' + address[
        'City'] + ', ' + ' ' + address['PostalCode'])


def user_call(request):
    query = QuickBooksToken.objects.first()
    access_token = query.quickbooks_access_token
    if access_token is '':
        return HttpResponse('Your Bearer token has expired, please initiate C2QB flow again')

    refresh_token = query.quickbooks_refresh_token
    user_profile_response, status_code = get_user_profile(access_token)

    if status_code >= 400 and not status_code == 403:
        # if call to QBO doesn't succeed then get a new bearer token from refresh token and try again
        bearer = get_bearer_token_from_refresh_token(refresh_token)
        QuickBooksToken.objects.update(
            quickbooks_access_token=bearer.access_token,
            quickbooks_access_token_expires_in=bearer.access_token_expire,
            quickbooks_refresh_token=bearer.refresh_token,
            quickbooks_refresh_token_expires_in=bearer.refresh_token_expire,
        )
        user_profile_response, status_code = get_user_profile(bearer.access_token)

        if status_code == 403:
            return HttpResponse('Forbidden!. OpenID calls only work if the OpenID scope was passed!')

        if status_code >= 400:
            return HttpResponseServerError()

        update_session(request, bearer.access_token, bearer.refresh_token, request.session.get('realmId', None),
                       name=user_profile_response.get('givenName', ''))

    if status_code == 403:
        return HttpResponse('Forbidden! OpenID calls only work if the OpenID scope was passed!')

    first_name = user_profile_response['givenName']
    family_name = user_profile_response['familyName']
    email = user_profile_response['email']

    return HttpResponse('First Name: ' + first_name + ', Family Name: ' + family_name + ', Email: ' + email)


def get_csrf_token(request):
    token = request.session.get('csrfToken', None)
    if token is None:
        token = get_secret_key()
        request.session['csrfToken'] = token
    return token


def update_session(request, access_token, refresh_token, realm_id, name=None):
    request.session['accessToken'] = access_token
    request.session['refreshToken'] = refresh_token
    request.session['realmId'] = realm_id
    request.session['name'] = name
