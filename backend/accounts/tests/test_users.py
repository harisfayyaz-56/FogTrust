"""User management (admin only). Threats ID-2, ID-4, ID-12."""

import pytest

from audit.models import AuditEvent
from accounts.models import User

URL = "/api/v1/users/"
GOOD_PASSWORD = "Tr1cky-Horse-Battery"


def events(action):
    return list(AuditEvent.objects.filter(action=action).order_by("sequence"))


@pytest.mark.django_db
class TestPermissions:
    @pytest.mark.parametrize("role", ["operator", "viewer"])
    def test_only_admins_may_use_every_users_endpoint(self, client_as, make_user, role):
        client = client_as(role)
        target = make_user("target1", role="viewer")

        assert client.get(URL).status_code == 403
        assert client.post(URL, {"username": "newuser", "password": GOOD_PASSWORD}, format="json").status_code == 403
        assert client.patch(f"{URL}{target.pk}/", {"role": "admin"}, format="json").status_code == 403
        assert not User.objects.filter(username="newuser").exists()
        target.refresh_from_db()
        assert target.role == "viewer"
        assert events("access.denied")

    def test_anonymous_gets_401(self, api_client):
        assert api_client.get(URL).status_code == 401
        assert api_client.post(URL, {}, format="json").status_code == 401

    def test_csrf_is_enforced(self, client_as):
        response = client_as("admin", enforce_csrf=True).post(URL, {"username": "newuser", "password": GOOD_PASSWORD}, format="json")
        assert response.status_code == 403 and response.json()["error"]["code"] == "CSRF_FAILED"


@pytest.mark.django_db
class TestCreate:
    def test_creates_a_user_with_least_privilege_by_default(self, client_as):
        response = client_as("admin").post(URL, {"username": "newuser", "password": GOOD_PASSWORD}, format="json")

        assert response.status_code == 201
        body = response.json()
        assert body["username"] == "newuser" and body["role"] == "viewer" and body["is_active"] is True
        assert "password" not in body and GOOD_PASSWORD not in response.content.decode()

    def test_the_password_is_hashed_with_argon2_and_can_log_in(self, client_as, api_client):
        client_as("admin").post(URL, {"username": "newuser", "password": GOOD_PASSWORD, "role": "operator"}, format="json")
        user = User.objects.get(username="newuser")

        assert user.password.startswith("argon2$") and GOOD_PASSWORD not in user.password
        assert user.role == "operator"
        assert api_client.post("/api/v1/auth/login/", {"username": "newuser", "password": GOOD_PASSWORD}, format="json").status_code == 200

    def test_creation_is_audited_without_the_password(self, client_as):
        client_as("admin").post(URL, {"username": "newuser", "password": GOOD_PASSWORD, "role": "operator"}, format="json")

        event = events("user.create")[-1]
        assert event.target_id == "newuser" and event.details == {"role": "operator"} and event.actor_id == "admin1"
        assert GOOD_PASSWORD not in str(event.details)

    @pytest.mark.parametrize(
        "body",
        [
            {"username": "newuser", "password": "short"},
            {"username": "newuser", "password": "1234567890123"},
            {"username": "newuser", "password": "password123"},
            {"username": "newuser", "password": "newuser123"},
            {"username": "newuser", "password": "x" * 129},
            {"username": "ab", "password": GOOD_PASSWORD},
            {"username": "bad name", "password": GOOD_PASSWORD},
            {"username": "x" * 151, "password": GOOD_PASSWORD},
            {"username": "newuser", "password": GOOD_PASSWORD, "role": "root"},
            {"username": "newuser", "password": GOOD_PASSWORD, "is_superuser": True},
            {"username": "newuser"},
            {"password": GOOD_PASSWORD},
            {},
        ],
    )
    def test_invalid_users_are_rejected(self, client_as, body):
        response = client_as("admin").post(URL, body, format="json")

        assert response.status_code == 400 and response.json()["error"]["code"] == "VALIDATION_ERROR"
        assert User.objects.count() == 1  # only the admin

    def test_validation_errors_do_not_echo_the_password(self, client_as):
        response = client_as("admin").post(URL, {"username": "newuser", "password": "password123"}, format="json")
        assert "password123" not in response.content.decode()

    def test_duplicate_usernames_are_rejected_case_insensitively(self, client_as, make_user):
        make_user("Existing", role="viewer")
        response = client_as("admin").post(URL, {"username": "existing", "password": GOOD_PASSWORD}, format="json")
        assert response.status_code == 400


@pytest.mark.django_db
class TestList:
    def test_lists_users_without_secrets_and_filters_by_role(self, client_as, make_user):
        make_user("operator9", role="operator")
        make_user("viewer9", role="viewer")
        client = client_as("admin")

        everyone = client.get(URL).json()
        assert everyone["count"] == 3
        text = client.get(URL).content.decode()
        assert "password" not in text and "argon2" not in text
        assert [u["username"] for u in client.get(URL, {"role": "operator"}).json()["results"]] == ["operator9"]
        assert client.get(URL, {"role": "root"}).status_code == 400


@pytest.mark.django_db
class TestChangeRoleAndEnable:
    def test_changing_a_role_takes_effect_immediately_and_is_audited(self, client_as, make_user):
        target = make_user("target1", role="viewer")
        admin = client_as("admin")
        response = admin.patch(f"{URL}{target.pk}/", {"role": "operator"}, format="json")

        assert response.status_code == 200 and response.json()["role"] == "operator"
        target.refresh_from_db()
        assert target.role == "operator"
        event = events("user.role_change")[-1]
        assert event.details == {"from": "viewer", "to": "operator"} and event.target_id == "target1"

    def test_a_session_of_a_demoted_user_loses_its_power(self, client_as, make_user):
        promoted = client_as("operator", username="op1")
        assert promoted.get("/api/v1/users/").status_code == 403
        admin = client_as("admin")
        admin.patch(f"{URL}{promoted.user.pk}/", {"role": "admin"}, format="json")
        assert promoted.get("/api/v1/users/").status_code == 200  # same session, new role
        admin.patch(f"{URL}{promoted.user.pk}/", {"role": "viewer"}, format="json")
        assert promoted.get("/api/v1/users/").status_code == 403

    def test_disabling_blocks_an_existing_session_and_new_logins(self, client_as, api_client):
        victim = client_as("operator", username="op1")
        assert victim.get("/api/v1/nodes/").status_code == 200
        client_as("admin").patch(f"{URL}{victim.user.pk}/", {"is_active": False}, format="json")

        assert victim.get("/api/v1/nodes/").status_code == 401
        login = api_client.post("/api/v1/auth/login/", {"username": "op1", "password": "Str0ng-Passw0rd!"}, format="json")
        assert login.status_code == 401
        assert events("user.disable")[-1].target_id == "op1"

    def test_re_enabling_is_audited(self, client_as, make_user):
        target = make_user("target1", role="viewer", is_active=False)
        response = client_as("admin").patch(f"{URL}{target.pk}/", {"is_active": True}, format="json")

        assert response.status_code == 200 and response.json()["is_active"] is True
        assert events("user.enable")[-1].target_id == "target1"

    def test_no_event_when_nothing_changes(self, client_as, make_user):
        target = make_user("target1", role="viewer")
        client_as("admin").patch(f"{URL}{target.pk}/", {"role": "viewer"}, format="json")
        assert not events("user.role_change")

    @pytest.mark.parametrize("body", [{}, {"role": "root"}, {"is_active": "maybe"}, {"username": "renamed"}, {"password": "x"}, {"is_superuser": True}])
    def test_invalid_patches_are_rejected(self, client_as, make_user, body):
        target = make_user("target1", role="viewer")
        response = client_as("admin").patch(f"{URL}{target.pk}/", body, format="json")

        assert response.status_code == 400
        target.refresh_from_db()
        assert (target.role, target.username, target.is_active) == ("viewer", "target1", True)

    def test_unknown_and_malformed_ids_are_404(self, client_as):
        admin = client_as("admin")
        assert admin.patch(f"{URL}99999/", {"role": "viewer"}, format="json").status_code == 404
        assert admin.patch(f"{URL}abc/", {"role": "viewer"}, format="json").status_code == 404
        assert admin.patch(f"{URL}1%27%20OR%201=1/", {"role": "viewer"}, format="json").status_code == 404


@pytest.mark.django_db
class TestAdministratorCannotLockThemselvesOut:
    def test_cannot_demote_self(self, client_as):
        admin = client_as("admin")
        response = admin.patch(f"{URL}{admin.user.pk}/", {"role": "viewer"}, format="json")

        assert response.status_code == 409 and response.json()["error"]["code"] == "CONFLICT"
        admin.user.refresh_from_db()
        assert admin.user.role == "admin"
        assert events("user.role_change")[-1].outcome == "failure"

    def test_cannot_disable_self(self, client_as):
        admin = client_as("admin")
        response = admin.patch(f"{URL}{admin.user.pk}/", {"is_active": False}, format="json")

        assert response.status_code == 409
        admin.user.refresh_from_db()
        assert admin.user.is_active
        assert events("user.disable")[-1].outcome == "failure"

    def test_self_patch_that_keeps_admin_is_allowed(self, client_as):
        admin = client_as("admin")
        assert admin.patch(f"{URL}{admin.user.pk}/", {"role": "admin", "is_active": True}, format="json").status_code == 200

    def test_an_admin_can_change_another_admin(self, client_as, make_user):
        other = make_user("admin2", role="admin")
        assert client_as("admin").patch(f"{URL}{other.pk}/", {"role": "viewer"}, format="json").status_code == 200


@pytest.mark.django_db
class TestSeedDemoUsersCommand:
    def test_creates_one_account_per_role_with_random_passwords_and_leaves_existing_alone(self):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command("seed_demo_users", stdout=out)
        assert {u.username: u.role for u in User.objects.all()} == {"admin1": "admin", "operator1": "operator", "viewer1": "viewer"}
        passwords = [line.split("password=")[1] for line in out.getvalue().splitlines() if "password=" in line]
        assert len(set(passwords)) == 3 and all(len(p) >= 12 for p in passwords)
        assert User.objects.get(username="admin1").password.startswith("argon2$")

        again = StringIO()
        call_command("seed_demo_users", stdout=again)
        assert again.getvalue().count("already exists") == 3 and "password=" not in again.getvalue()
