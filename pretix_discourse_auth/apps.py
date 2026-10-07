from django.apps import AppConfig


class PluginApp(AppConfig):
    name = 'pretix_discourse_auth'
    verbose_name = 'Discourse Auth'

    class PretixPluginMeta:
        name = 'Discourse Auth'
        author = 'gundalow'
        description = 'Discourse authentication backend for pretix'
        visible = True
        version = '1.0.0'
        category = 'INTEGRATION'

    def ready(self):
        from . import urls  # noqa
