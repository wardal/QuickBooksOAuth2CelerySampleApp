from django.db import models


class Bearer:
    def __init__(self, refresh_token_expire, access_token, token_type, refresh_token, access_token_expire,
                 id_token=None):
        self.token_type = token_type
        self.access_token = access_token
        self.access_token_expire = access_token_expire
        self.refresh_token = refresh_token
        self.refresh_token_expire = refresh_token_expire
        self.id_token = id_token


class QuickBooksToken(models.Model):
    quickbooks_realm_id = models.IntegerField(null=True)
    quickbooks_access_token = models.CharField(max_length=1000, default='', blank=True)
    quickbooks_access_token_expires_in = models.PositiveIntegerField(null=True)
    quickbooks_refresh_token = models.CharField(max_length=100, default='', blank=True)
    quickbooks_refresh_token_expires_in = models.PositiveIntegerField(null=True)

    def __str__(self):
        return 'QuickBooks Token'

    class Meta:
        verbose_name = 'QuickBooks Token'


class QuickBooksDiscoveryDocument(models.Model):
    issuer = models.CharField(max_length=100, default='', blank=True)
    authorization_endpoint = models.CharField(max_length=100, default='', blank=True)
    token_endpoint = models.CharField(max_length=100, default='', blank=True)
    userinfo_endpoint = models.CharField(max_length=100, default='', blank=True)
    revocation_endpoint = models.CharField(max_length=100, default='', blank=True)
    jwks_uri = models.CharField(max_length=100, default='', blank=True)

    def __str__(self):
        return 'QuickBooks Discovery Document'

    class Meta:
        verbose_name = 'QuickBooks Discovery Document'
