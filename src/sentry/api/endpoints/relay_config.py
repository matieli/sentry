from __future__ import absolute_import

from rest_framework.response import Response

from sentry.auth.access import SDKAccess
from sentry.api.authentication import (
    AuthenticationFailed, QuietBasicAuthentication, get_authorization_header
)
from sentry.api.bases.project import ProjectEndpoint, ProjectPermission


class SDKAuthentication(QuietBasicAuthentication):
    def authenticate(self, request):
        auth = get_authorization_header(request).split(' ', 1)

        if not auth or auth[0].lower() != b'x-sentry-auth':
            return None

        from sentry.coreapi import ClientApiHelper
        helper = ClientApiHelper(
            agent=request.META.get('HTTP_USER_AGENT'),
            ip_address=request.META['REMOTE_ADDR'],
        )
        try:
            client_auth = helper.auth_from_request(request)
        except Exception:
            raise AuthenticationFailed('Invalid credentials')

        try:
            project_id = helper.project_id_from_auth(client_auth)
        except Exception:
            raise AuthenticationFailed('Invalid credentials')

        access = SDKAccess(
            project_id=project_id,
        )

        return self.authenticate_credentials(access)

    def authenticate_credentials(self, access):
        return (None, access)


class SDKPermission(ProjectPermission):
    def has_object_permission(self, request, view, project):
        request.access = request.auth
        allowed_scopes = set(self.scope_map.get(request.method, []))
        return any(
            request.auth.has_project_scope(project, s)
            for s in allowed_scopes,
        )


class RelayConfigEndpoint(ProjectEndpoint):
    authentication_classes = (
        SDKAuthentication,
    )
    permission_classes = (
        SDKPermission,
    )

    def get(self, request, project):
        return Response({
            'hi': 'there',
        })
