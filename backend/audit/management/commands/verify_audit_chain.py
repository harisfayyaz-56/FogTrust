"""
python manage.py verify_audit_chain

Recomputes every hash in the audit log. Exit code 0 when the chain is intact,
1 when it is broken (so scripts and the test runner can rely on it).
The check itself is recorded as an `audit.verify` event.
"""

from django.core.management.base import BaseCommand, CommandError

from core.errors import ErrorCode

from audit.services import log_event, verify_chain


class Command(BaseCommand):
    help = "Verify the audit log hash chain and report the first broken event."

    def add_arguments(self, parser):
        parser.add_argument("--no-record", action="store_true", help="do not write an audit.verify event")

    def handle(self, *args, **options):
        report = verify_chain()
        if not options["no_record"]:
            log_event(
                "audit.verify",
                "success" if report.valid else "failure",
                actor_type="system",
                actor_id="verify_audit_chain",
                reason_code="" if report.valid else ErrorCode.AUDIT_CHAIN_BROKEN,
                details=report.as_dict(),
            )
        if report.valid:
            self.stdout.write(self.style.SUCCESS(f"Audit chain valid: {report.events_checked} events checked."))
            return
        raise CommandError(
            f"Audit chain BROKEN at sequence {report.first_broken_sequence} "
            f"({report.problem}); {report.events_checked} events checked."
        )
