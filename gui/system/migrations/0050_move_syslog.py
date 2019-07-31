from django.db import migrations, models
import django.db.migrations.operations.special


def move_syslog(apps, schema_editor):
    """Move syslog options from Settings model to Advanced model"""
    try:
        Advanced = apps.get_model('system', 'Advanced')
        Settings = apps.get_model('system', 'Settings')
    except LookupError:
        Advanced = None
        Settings = None

    if Advanced and Settings:
        try:
            settings = Settings.objects.latest('id')
            advanced = Advanced.objects.latest('id')
        except Settings.DoesNotExist:
            settings = None  # there is no 'settings' record in DB
        except Advanced.DoesNotExist:
            advanced = Advanced.objects.create()
        finally:
            if settings:
                advanced.adv_sysloglevel = settings.stg_sysloglevel
                advanced.adv_syslogserver = settings.stg_syslogserver
                advanced.save()


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0049_guihttpsprotocols'),
    ]

    operations = [
        migrations.AddField(
            model_name='advanced',
            name='adv_sysloglevel',
            field=models.CharField(choices=[('f_emerg', 'Emergency'), ('f_alert', 'Alert'), ('f_crit', 'Critical'), ('f_err', 'Error'), ('f_warning', 'Warning'), ('f_notice', 'Notice'), ('f_info', 'Info'), ('f_debug', 'Debug'), ('f_is_debug', 'Is_Debug')], default='f_info', help_text='Specifies which messages will be logged by server. INFO and VERBOSE log transactions that server performs on behalf of the client. f_is_debug specify higher levels of debugging output. The default is f_info.', max_length=120, verbose_name='Syslog level'),
        ),
        migrations.AddField(
            model_name='advanced',
            name='adv_syslogserver',
            field=models.CharField(blank=True, default='', help_text='Specifies the server and port syslog messages will be sent to.  The accepted format is hostname:port or ip:port, if :port is not specified it will default to port 514 (this field currently only takes IPv4 addresses)', max_length=120, verbose_name='Syslog server'),
        ),
        migrations.RunPython(
            code=move_syslog,
            reverse_code=django.db.migrations.operations.special.RunPython.noop
        ),
        migrations.RemoveField(
            model_name='settings',
            name='stg_sysloglevel',
        ),
        migrations.RemoveField(
            model_name='settings',
            name='stg_syslogserver',
        ),
    ]
