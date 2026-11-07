"""
Signals other slices can listen to.

node_revoked is sent AFTER the revocation has been committed, once per revoked node
(manual by an administrator, or automatic from the trust engine). Member 3 connects the
scheduler here to return the node's in-flight tasks to the queue:

    from django.dispatch import receiver
    from nodes.signals import node_revoked

    @receiver(node_revoked)
    def requeue_tasks(sender, node, source, reason, **kwargs):
        ...  # node.id, node.name; source is "manual" or "automatic"

Receivers run in the request that revoked the node, so keep them fast and make them
raise nothing the API should not show: errors in a receiver are logged and swallowed
(send_robust) so a scheduler bug can never leave a revoked node looking active.
"""

from django.dispatch import Signal

node_revoked = Signal()
