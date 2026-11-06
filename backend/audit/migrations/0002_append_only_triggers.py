"""
Database-level append-only enforcement.

Even raw SQL, the Django admin or a script that bypasses the model cannot
UPDATE or DELETE an audit row: SQLite aborts the statement.

Side effect: `manage.py flush` and tests marked `transactional_db` cannot empty
this table. Use normal `django_db` tests (they roll back instead of deleting),
and delete db.sqlite3 to reset a local database.
"""

from django.db import migrations

TRIGGERS = {
    "audit_event_no_update": "UPDATE",
    "audit_event_no_delete": "DELETE",
}


def create_triggers(apps, schema_editor):
    if schema_editor.connection.vendor != "sqlite":
        return
    for name, operation in TRIGGERS.items():
        schema_editor.execute(
            f"CREATE TRIGGER {name} BEFORE {operation} ON audit_event "
            f"BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;"
        )


def drop_triggers(apps, schema_editor):
    if schema_editor.connection.vendor != "sqlite":
        return
    for name in TRIGGERS:
        schema_editor.execute(f"DROP TRIGGER IF EXISTS {name};")


class Migration(migrations.Migration):
    dependencies = [
        ("audit", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_triggers, drop_triggers),
    ]
