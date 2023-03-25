import os
from functools import cached_property

from waldur_client import WaldurClient

WALDUR_API_URL = os.environ.get('WALDUR_API_URL')
WALDUR_API_TOKEN = os.environ.get('WALDUR_API_TOKEN')

class Backend:
    @cached_property
    def waldur_client(self):
        return WaldurClient(WALDUR_API_URL, WALDUR_API_TOKEN)

    def terminate_vm(self, instance):
        self.waldur_client.stop_instance(instance, wait=True)
        self.waldur_client.delete_instance_via_marketplace(instance)

if __name__ == "__main__":
    backend = Backend()
    if os.environ.get("RESOURCE_BACKEND_ID") is not "":
        backend.terminate_vm(os.environ.get('RESOURCE_BACKEND_ID'))
