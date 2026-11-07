from django.core.management.base import BaseCommand
from tasks.services import detect_stalled_tasks


class Command(BaseCommand):
    help = "T3: Detects silent or crashed worker nodes and reassigns stalled tasks."

    def add_arguments(self, parser):
        parser.add_argument(
            "--stall-seconds",
            type=int,
            default=60,
            help="Threshold in seconds of node inactivity before declaring a task stalled.",
        )

    def handle(self, *args, **options):
        stall_seconds = options["stall_seconds"]
        self.stdout.write(f"Checking for stalled tasks with threshold={stall_seconds}s...")
        stalled = detect_stalled_tasks(stall_seconds=stall_seconds)
        self.stdout.write(self.style.SUCCESS(f"Processed {len(stalled)} stalled task(s)."))

