import requests

from celery import shared_task

from django.conf import settings

from .models import QuickBooksDiscoveryDocument


@shared_task()
def get_discovery_document():
    r = requests.get(settings.DISCOVERY_DOCUMENT)
    if r.status_code >= 400:
        return 'Error! Connection to discovery document failed!'
    discovery_doc_json = r.json()

    data_dict = {
        'issuer': discovery_doc_json['issuer'],
        'authorization_endpoint': discovery_doc_json['authorization_endpoint'],
        'userinfo_endpoint': discovery_doc_json['userinfo_endpoint'],
        'revocation_endpoint': discovery_doc_json['revocation_endpoint'],
        'token_endpoint': discovery_doc_json['token_endpoint'],
        'jwks_uri': discovery_doc_json['jwks_uri']
    }

    query, created = QuickBooksDiscoveryDocument.objects.update_or_create(data_dict)

    if created is True:
        return 'Your Discovery Document was created!'
    else:
        return 'Your Discovery Document was updated!'
